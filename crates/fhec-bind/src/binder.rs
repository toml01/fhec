//! Construction of a [`BoundUnit`]: declaration collection, import resolution,
//! inheritance linearization, and the scope-aware body walk.

use crate::ids::{ContractId, ErrorId, EventId, FileId, FunctionId, TypeDeclId, VarId};
use crate::inherit::c3_linearize;
use crate::model::*;
use crate::unit::{BoundUnit, SourceFile};
use solar_ast as ast;
use solar_data_structures::map::{FxHashMap, FxHashSet};
use solar_interface::{Ident, Span, Symbol};

/// A flat name table: one scope level, or a contract/file member table.
pub(crate) type NameTable = FxHashMap<Symbol, Resolution>;

/// A source file plus everything the binder derives for it.
pub(crate) struct FileInfo<'ast> {
    pub(crate) name: String,
    pub(crate) dir: String,
    #[allow(dead_code)] // kept for downstream passes that re-walk the AST per file
    pub(crate) ast: &'ast ast::SourceUnit<'ast>,
    /// Names declared at this file's top level.
    pub(crate) own_exports: NameTable,
    /// Names brought in by imports (all kinds).
    pub(crate) import_bindings: NameTable,
    /// External plain-import specifiers reachable through this file's plain-import
    /// closure. Non-empty ⇒ unknown names may come from outside the unit.
    pub(crate) external_exposure: Vec<String>,
    imports: Vec<ImportEntry>,
}

struct ImportEntry {
    specifier: String,
    span: Span,
    resolved: Option<FileId>,
    kind: ImportKind,
}

enum ImportKind {
    /// `import "x";` or `import "x" as NS;`
    Plain(Option<Ident>),
    /// `import {A as B, C} from "x";`
    Aliases(Vec<(Ident, Option<Ident>)>),
    /// `import * as NS from "x";`
    Glob(Ident),
}

/// Joins `spec` onto `dir` and normalizes `.`/`..` segments. Forward slashes only.
pub(crate) fn normalize_join(dir: &str, spec: &str) -> String {
    let mut parts: Vec<&str> = if spec.starts_with("./") || spec.starts_with("../") {
        dir.split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect()
    } else {
        Vec::new()
    };
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

fn dir_of(name: &str) -> String {
    match name.rfind('/') {
        Some(i) => name[..i].to_string(),
        None => String::new(),
    }
}

/// Binds a compilation unit. Must run inside the solar `Session::enter` scope that
/// parsed the files (symbol text access requires the session's interner).
pub fn bind<'ast>(sources: Vec<SourceFile<'ast>>) -> BoundUnit<'ast> {
    let mut b = Binder {
        unit: BoundUnit::empty(),
        raw_usings: Vec::new(),
    };
    b.collect(sources);
    b.resolve_imports();
    b.resolve_inheritance();
    b.resolve_usings();
    b.walk_bodies();
    b.unit
}

struct Binder<'ast> {
    unit: BoundUnit<'ast>,
    raw_usings: Vec<(&'ast ast::UsingDirective<'ast>, FileId, Option<ContractId>)>,
}

impl<'ast> Binder<'ast> {
    // ------------------------------------------------------------------
    // Pass 1: collect declarations.
    // ------------------------------------------------------------------

    fn collect(&mut self, sources: Vec<SourceFile<'ast>>) {
        for source in sources {
            let name = normalize_join("", &source.name);
            let file = FileId::new(self.unit.files.len());
            self.unit.files.push(FileInfo {
                dir: dir_of(&name),
                name,
                ast: source.ast,
                own_exports: NameTable::default(),
                import_bindings: NameTable::default(),
                external_exposure: Vec::new(),
                imports: Vec::new(),
            });
            for item in source.ast.items.iter() {
                self.collect_item(file, item);
            }
        }
    }

    fn collect_item(&mut self, file: FileId, item: &'ast ast::Item<'ast>) {
        match &item.kind {
            ast::ItemKind::Pragma(_) => {}
            ast::ItemKind::Import(import) => self.collect_import(file, import),
            ast::ItemKind::Using(using) => self.raw_usings.push((using, file, None)),
            ast::ItemKind::Contract(contract) => self.collect_contract(file, item.span, contract),
            ast::ItemKind::Function(func) => {
                let id = self.collect_function(file, None, item.span, func);
                if let Some(name) = func.header.name {
                    self.insert_file_export(file, name, Resolution::Function(vec![id]));
                }
            }
            ast::ItemKind::Variable(var) => {
                let id = self.push_var(
                    file,
                    VarOwner::FileConst(file),
                    var,
                    extract_policy_docs(&item.docs),
                );
                if let Some(name) = var.name {
                    self.insert_file_export(file, name, Resolution::FileConst(id));
                }
            }
            ast::ItemKind::Struct(s) => {
                let id = self.push_type_decl(
                    file,
                    None,
                    TypeDeclKind::Struct(s),
                    s.name,
                    extract_policy_docs(&item.docs),
                );
                self.collect_struct_fields(file, id, s);
                self.insert_file_export(file, s.name, Resolution::TypeName(id));
            }
            ast::ItemKind::Enum(e) => {
                let id = self.push_type_decl(file, None, TypeDeclKind::Enum(e), e.name, Vec::new());
                self.insert_file_export(file, e.name, Resolution::TypeName(id));
            }
            ast::ItemKind::Udvt(u) => {
                let id = self.push_type_decl(file, None, TypeDeclKind::Udvt(u), u.name, Vec::new());
                self.insert_file_export(file, u.name, Resolution::TypeName(id));
            }
            ast::ItemKind::Error(e) => {
                let id = ErrorId::new(self.unit.errors.len());
                self.unit.errors.push(ErrorInfo {
                    ast: e,
                    file,
                    contract: None,
                });
                self.insert_file_export(file, e.name, Resolution::Error(id));
            }
            ast::ItemKind::Event(e) => {
                let id = EventId::new(self.unit.events.len());
                self.unit.events.push(EventInfo {
                    ast: e,
                    file,
                    contract: None,
                    policy_docs: extract_policy_docs(&item.docs),
                });
                self.insert_file_export(file, e.name, Resolution::Event(id));
            }
        }
    }

    fn collect_import(&mut self, file: FileId, import: &'ast ast::ImportDirective<'ast>) {
        let kind = match &import.items {
            ast::ImportItems::Plain(alias) => ImportKind::Plain(*alias),
            ast::ImportItems::Aliases(list) => {
                ImportKind::Aliases(list.iter().map(|(a, b)| (*a, *b)).collect())
            }
            ast::ImportItems::Glob(ns) => ImportKind::Glob(*ns),
        };
        self.unit.files[file.index()].imports.push(ImportEntry {
            specifier: import.path.value.as_str().to_string(),
            span: import.path.span,
            resolved: None,
            kind,
        });
    }

    fn collect_contract(
        &mut self,
        file: FileId,
        span: Span,
        contract: &'ast ast::ItemContract<'ast>,
    ) {
        let id = ContractId::new(self.unit.contracts.len());
        self.unit.contracts.push(ContractInfo {
            ast: contract,
            span,
            name: contract.name,
            name_str: contract.name.as_str().to_string(),
            kind: contract.kind,
            file,
            bases: Vec::new(),
            linearization: Linearization {
                order: vec![id],
                complete: true,
                reason: None,
            },
            state_vars: Vec::new(),
            functions: Vec::new(),
            members: NameTable::default(),
        });
        self.insert_file_export(file, contract.name, Resolution::Contract(id));

        for item in contract.body.iter() {
            match &item.kind {
                ast::ItemKind::Using(using) => self.raw_usings.push((using, file, Some(id))),
                ast::ItemKind::Function(func) => {
                    let fid = self.collect_function(file, Some(id), item.span, func);
                    self.unit.contracts[id.index()].functions.push(fid);
                    if func.kind == ast::FunctionKind::Function
                        || func.kind == ast::FunctionKind::Modifier
                    {
                        if let Some(name) = func.header.name {
                            self.insert_member(id, name, Resolution::Function(vec![fid]));
                        }
                    }
                }
                ast::ItemKind::Variable(var) => {
                    let vid = self.push_var(
                        file,
                        VarOwner::State(id),
                        var,
                        extract_policy_docs(&item.docs),
                    );
                    self.unit.contracts[id.index()].state_vars.push(vid);
                    if let Some(name) = var.name {
                        self.insert_member(id, name, Resolution::StateVar(vid));
                    }
                }
                ast::ItemKind::Struct(s) => {
                    let tid = self.push_type_decl(
                        file,
                        Some(id),
                        TypeDeclKind::Struct(s),
                        s.name,
                        extract_policy_docs(&item.docs),
                    );
                    self.collect_struct_fields(file, tid, s);
                    self.insert_member(id, s.name, Resolution::TypeName(tid));
                }
                ast::ItemKind::Enum(e) => {
                    let tid = self.push_type_decl(
                        file,
                        Some(id),
                        TypeDeclKind::Enum(e),
                        e.name,
                        Vec::new(),
                    );
                    self.insert_member(id, e.name, Resolution::TypeName(tid));
                }
                ast::ItemKind::Udvt(u) => {
                    let tid = self.push_type_decl(
                        file,
                        Some(id),
                        TypeDeclKind::Udvt(u),
                        u.name,
                        Vec::new(),
                    );
                    self.insert_member(id, u.name, Resolution::TypeName(tid));
                }
                ast::ItemKind::Error(e) => {
                    let eid = ErrorId::new(self.unit.errors.len());
                    self.unit.errors.push(ErrorInfo {
                        ast: e,
                        file,
                        contract: Some(id),
                    });
                    self.insert_member(id, e.name, Resolution::Error(eid));
                }
                ast::ItemKind::Event(e) => {
                    let eid = EventId::new(self.unit.events.len());
                    self.unit.events.push(EventInfo {
                        ast: e,
                        file,
                        contract: Some(id),
                        policy_docs: extract_policy_docs(&item.docs),
                    });
                    self.insert_member(id, e.name, Resolution::Event(eid));
                }
                // Pragma/Import/Contract are not allowed inside contracts; the parser
                // rejects them, so nothing to do here.
                _ => {}
            }
        }
    }

    fn collect_function(
        &mut self,
        file: FileId,
        contract: Option<ContractId>,
        span: Span,
        func: &'ast ast::ItemFunction<'ast>,
    ) -> FunctionId {
        let id = FunctionId::new(self.unit.functions.len());
        // Reserve the slot before pushing vars so VarOwner can reference `id`.
        self.unit.functions.push(FunctionInfo {
            ast: func,
            span,
            name: func.header.name,
            name_str: func.header.name.map(|n| n.as_str().to_string()),
            file,
            contract,
            params: Vec::new(),
            returns: Vec::new(),
        });
        let params: Vec<VarId> = func
            .header
            .parameters
            .vars
            .iter()
            .map(|v| self.push_var(file, VarOwner::Param(id), v, Vec::new()))
            .collect();
        let returns: Vec<VarId> = func
            .header
            .returns()
            .iter()
            .map(|v| self.push_var(file, VarOwner::Return(id), v, Vec::new()))
            .collect();
        let info = &mut self.unit.functions[id.index()];
        info.params = params;
        info.returns = returns;
        id
    }

    fn collect_struct_fields(
        &mut self,
        file: FileId,
        id: TypeDeclId,
        s: &'ast ast::ItemStruct<'ast>,
    ) {
        for field in s.fields.iter() {
            self.push_var(file, VarOwner::StructField(id), field, Vec::new());
        }
    }

    fn push_var(
        &mut self,
        file: FileId,
        owner: VarOwner,
        var: &'ast ast::VariableDefinition<'ast>,
        policy_docs: Vec<PolicyDoc>,
    ) -> VarId {
        let id = VarId::new(self.unit.vars.len());
        self.unit.vars.push(VarInfo {
            decl: var,
            name: var.name,
            file,
            owner,
            policy_docs,
        });
        id
    }

    fn push_type_decl(
        &mut self,
        file: FileId,
        contract: Option<ContractId>,
        kind: TypeDeclKind<'ast>,
        name: Ident,
        policy_docs: Vec<PolicyDoc>,
    ) -> TypeDeclId {
        let id = TypeDeclId::new(self.unit.type_decls.len());
        self.unit.type_decls.push(TypeDeclInfo {
            kind,
            file,
            contract,
            name,
            policy_docs,
        });
        id
    }

    fn insert_file_export(&mut self, file: FileId, name: Ident, resolution: Resolution) {
        let table = &mut self.unit.files[file.index()].own_exports;
        Self::insert_into(table, name, resolution, file, &mut self.unit.diagnostics);
    }

    fn insert_member(&mut self, contract: ContractId, name: Ident, resolution: Resolution) {
        let file = self.unit.contracts[contract.index()].file;
        let table = &mut self.unit.contracts[contract.index()].members;
        Self::insert_into(table, name, resolution, file, &mut self.unit.diagnostics);
    }

    /// Inserts a declaration into a table; merges function overloads; reports
    /// FHE1020 on a non-mergeable duplicate (first declaration wins).
    fn insert_into(
        table: &mut NameTable,
        name: Ident,
        resolution: Resolution,
        file: FileId,
        diagnostics: &mut Vec<BindDiagnostic>,
    ) {
        match (table.get_mut(&name.name), resolution) {
            (None, r) => {
                table.insert(name.name, r);
            }
            (Some(Resolution::Function(existing)), Resolution::Function(new)) => {
                existing.extend(new);
            }
            (Some(_), _) => {
                diagnostics.push(BindDiagnostic {
                    code: CODE_DUPLICATE_DEFINITION,
                    message: format!("duplicate definition of `{}` in the same scope", name),
                    span: name.span,
                    file,
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // Pass 2: imports.
    // ------------------------------------------------------------------

    fn resolve_imports(&mut self) {
        let name_to_file: FxHashMap<String, FileId> = self
            .unit
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), FileId::new(i)))
            .collect();

        // Resolve specifiers.
        for fi in 0..self.unit.files.len() {
            let dir = self.unit.files[fi].dir.clone();
            for ei in 0..self.unit.files[fi].imports.len() {
                let spec = self.unit.files[fi].imports[ei].specifier.clone();
                let normalized = normalize_join(&dir, &spec);
                let is_relative = spec.starts_with("./") || spec.starts_with("../");
                let target = name_to_file.get(&normalized).copied();
                self.unit.files[fi].imports[ei].resolved = target;
                if is_relative && target.is_none() {
                    let span = self.unit.files[fi].imports[ei].span;
                    self.unit.diagnostics.push(BindDiagnostic {
                        code: CODE_UNRESOLVED_IMPORT,
                        message: format!(
                            "cannot resolve relative import `{spec}` within the compilation unit"
                        ),
                        span,
                        file: FileId::new(fi),
                    });
                }
            }
        }

        // Plain-import closure per file: reachable in-unit files and external exposure.
        let mut closures: Vec<(Vec<FileId>, Vec<String>)> = Vec::new();
        for fi in 0..self.unit.files.len() {
            closures.push(self.plain_closure(FileId::new(fi)));
        }

        // Merge closure exports and bind aliased/glob imports.
        for (fi, (reachable, exposure)) in closures.into_iter().enumerate() {
            let file = FileId::new(fi);
            self.unit.files[fi].external_exposure = exposure;

            let mut bindings = NameTable::default();
            for &target in &reachable {
                let exports: Vec<(Symbol, Resolution)> = self.unit.files[target.index()]
                    .own_exports
                    .iter()
                    .map(|(s, r)| (*s, r.clone()))
                    .collect();
                for (sym, res) in exports {
                    match bindings.get(&sym) {
                        None => {
                            bindings.insert(sym, res);
                        }
                        Some(existing) if *existing == res => {}
                        Some(_) => {
                            bindings
                                .insert(sym, Resolution::Unresolved(UnresolvedReason::Ambiguous));
                        }
                    }
                }
            }

            let entries = std::mem::take(&mut self.unit.files[fi].imports);
            for entry in &entries {
                self.bind_import_entry(file, entry, &mut bindings);
            }
            self.unit.files[fi].imports = entries;
            self.unit.files[fi].import_bindings = bindings;
        }
    }

    /// BFS over plain (merging) imports: returns in-unit reachable files (excluding
    /// self) and the external plain specifiers encountered anywhere in the closure.
    fn plain_closure(&self, start: FileId) -> (Vec<FileId>, Vec<String>) {
        let mut seen: FxHashSet<FileId> = FxHashSet::default();
        let mut queue = vec![start];
        seen.insert(start);
        let mut reachable = Vec::new();
        let mut exposure = Vec::new();
        while let Some(f) = queue.pop() {
            for entry in &self.unit.files[f.index()].imports {
                if !matches!(entry.kind, ImportKind::Plain(None)) {
                    continue;
                }
                match entry.resolved {
                    Some(target) => {
                        if seen.insert(target) {
                            reachable.push(target);
                            queue.push(target);
                        }
                    }
                    None => {
                        if !exposure.contains(&entry.specifier) {
                            exposure.push(entry.specifier.clone());
                        }
                    }
                }
            }
        }
        (reachable, exposure)
    }

    fn bind_import_entry(&mut self, file: FileId, entry: &ImportEntry, bindings: &mut NameTable) {
        match &entry.kind {
            ImportKind::Plain(None) => {} // handled by closure merge
            ImportKind::Plain(Some(ns)) | ImportKind::Glob(ns) => {
                let res = match entry.resolved {
                    Some(target) => Resolution::Namespace(target),
                    None => Resolution::External {
                        specifier: entry.specifier.clone(),
                        member: None,
                    },
                };
                Self::insert_into(bindings, *ns, res, file, &mut self.unit.diagnostics);
            }
            ImportKind::Aliases(aliases) => {
                for (orig, alias) in aliases {
                    let bound_name = alias.unwrap_or(*orig);
                    let res = match entry.resolved {
                        None => Resolution::External {
                            specifier: entry.specifier.clone(),
                            member: Some(orig.name),
                        },
                        Some(target) => {
                            let t = &self.unit.files[target.index()];
                            if let Some(r) = t.own_exports.get(&orig.name) {
                                r.clone()
                            } else if !t.imports.is_empty() {
                                // The target may re-export the symbol through its own
                                // imports; we do not chase alias chains (fixpoint), so
                                // degrade instead of erroring.
                                Resolution::Unresolved(UnresolvedReason::MaybeReExport {
                                    specifier: entry.specifier.clone(),
                                })
                            } else {
                                self.unit.diagnostics.push(BindDiagnostic {
                                    code: CODE_UNRESOLVED_IMPORT,
                                    message: format!(
                                        "`{}` is not exported by `{}`",
                                        orig, entry.specifier
                                    ),
                                    span: orig.span,
                                    file,
                                });
                                Resolution::Unresolved(UnresolvedReason::ImportFailed {
                                    specifier: entry.specifier.clone(),
                                })
                            }
                        }
                    };
                    Self::insert_into(bindings, bound_name, res, file, &mut self.unit.diagnostics);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Pass 3: inheritance.
    // ------------------------------------------------------------------

    fn resolve_inheritance(&mut self) {
        // Resolve base references.
        for ci in 0..self.unit.contracts.len() {
            let file = self.unit.contracts[ci].file;
            let contract_ast = self.unit.contracts[ci].ast;
            let mut bases = Vec::new();
            for base in contract_ast.bases.iter() {
                let res = self.resolve_path_at_file(file, &base.name);
                if let Some(first) = base.name.segments().first() {
                    self.unit.resolutions.insert(first.span, res.clone());
                }
                let name = base.name.to_string();
                bases.push(match res {
                    Resolution::Contract(id) => BaseRef::InUnit(id),
                    Resolution::External { specifier, .. } => BaseRef::External {
                        name,
                        specifier: Some(specifier),
                    },
                    _ => BaseRef::Unknown { name },
                });
            }
            self.unit.contracts[ci].bases = bases;
        }

        // Completeness: every base in-unit, transitively.
        let n = self.unit.contracts.len();
        let mut complete: Vec<Option<bool>> = vec![None; n];
        for ci in 0..n {
            self.completeness(ci, &mut complete, &mut Vec::new());
        }

        // Linearize.
        let mut in_unit_bases: FxHashMap<ContractId, Vec<ContractId>> = FxHashMap::default();
        for ci in 0..n {
            let ids: Vec<ContractId> = self.unit.contracts[ci]
                .bases
                .iter()
                .filter_map(|b| match b {
                    BaseRef::InUnit(id) => Some(*id),
                    _ => None,
                })
                .collect();
            in_unit_bases.insert(ContractId::new(ci), ids);
        }
        for (ci, is_complete) in complete.iter().enumerate() {
            let id = ContractId::new(ci);
            let lin = if *is_complete == Some(true) {
                match c3_linearize(id, &in_unit_bases) {
                    Some(order) => Linearization {
                        order,
                        complete: true,
                        reason: None,
                    },
                    None => Linearization {
                        order: vec![id],
                        complete: false,
                        reason: Some(IncompleteReason::LinearizationFailed),
                    },
                }
            } else {
                let reason = if self.unit.contracts[ci]
                    .bases
                    .iter()
                    .any(|b| matches!(b, BaseRef::Unknown { .. }))
                {
                    IncompleteReason::UnresolvedBase
                } else if self.unit.contracts[ci]
                    .bases
                    .iter()
                    .any(|b| matches!(b, BaseRef::External { .. }))
                {
                    IncompleteReason::ExternalBase
                } else {
                    IncompleteReason::BaseIncomplete
                };
                Linearization {
                    order: vec![id],
                    complete: false,
                    reason: Some(reason),
                }
            };
            self.unit.contracts[ci].linearization = lin;
        }
    }

    fn completeness(
        &self,
        ci: usize,
        memo: &mut Vec<Option<bool>>,
        stack: &mut Vec<usize>,
    ) -> bool {
        if let Some(v) = memo[ci] {
            return v;
        }
        if stack.contains(&ci) {
            return false; // cycle: linearization will fail anyway
        }
        stack.push(ci);
        let mut result = true;
        for base in &self.unit.contracts[ci].bases {
            match base {
                BaseRef::InUnit(id) => {
                    if !self.completeness(id.index(), memo, stack) {
                        result = false;
                    }
                }
                _ => result = false,
            }
        }
        stack.pop();
        memo[ci] = Some(result);
        result
    }

    // ------------------------------------------------------------------
    // Pass 3.5: using directives.
    // ------------------------------------------------------------------

    fn resolve_usings(&mut self) {
        let raw = std::mem::take(&mut self.raw_usings);
        for (using, file, contract) in raw {
            let target = match &using.ty {
                None => UsingTarget::Wildcard,
                Some(ty) => match &ty.kind {
                    ast::TypeKind::Elementary(e) => UsingTarget::Name(e.to_abi_str().into_owned()),
                    ast::TypeKind::Custom(path) => {
                        let segs = path.segments();
                        if segs.len() == 1 {
                            UsingTarget::Name(segs[0].as_str().to_string())
                        } else {
                            UsingTarget::Complex
                        }
                    }
                    _ => UsingTarget::Complex,
                },
            };
            let list = match &using.list {
                ast::UsingList::Single(path) => {
                    UsingListResolution::Library(self.resolve_path_at_file(file, path))
                }
                ast::UsingList::Multiple(entries) => {
                    let mut fns = Vec::new();
                    for (path, op) in entries.iter() {
                        let segs = path.segments();
                        let method = segs.last().expect("paths are never empty").name;
                        let resolution = self.resolve_path_at_file(file, path);
                        fns.push(UsingFunction {
                            method,
                            resolution,
                            is_operator: op.is_some(),
                        });
                    }
                    UsingListResolution::Functions(fns)
                }
            };
            self.unit.insert_using(UsingEntry {
                file,
                contract,
                global: using.global,
                target,
                list,
            });
        }
    }

    /// Resolves a (possibly qualified) path at file scope: the first segment through
    /// the file's tables, further segments through namespaces and contract members.
    fn resolve_path_at_file(&self, file: FileId, path: &ast::AstPath<'ast>) -> Resolution {
        let segs = path.segments();
        let first = segs[0];
        let mut current = self.unit.resolve_at_file(file, first.name, first.as_str());
        for seg in &segs[1..] {
            current = match current {
                Resolution::Namespace(f) => match self.unit.namespace_member(f, seg.name) {
                    Some(r) => r.clone(),
                    None => Resolution::Unresolved(UnresolvedReason::NotFound),
                },
                Resolution::Contract(c) => match self.unit.own_member(c, seg.name) {
                    Some(r) => r.clone(),
                    None => Resolution::Unresolved(UnresolvedReason::NotFound),
                },
                Resolution::External { specifier, .. } => Resolution::External {
                    specifier,
                    member: Some(seg.name),
                },
                other @ Resolution::Unresolved(_) => other,
                _ => Resolution::Unresolved(UnresolvedReason::NotFound),
            };
        }
        current
    }

    // ------------------------------------------------------------------
    // Pass 4: body walk.
    // ------------------------------------------------------------------

    fn walk_bodies(&mut self) {
        // Signature-level types and initializers first (no local scopes involved).
        for vi in 0..self.unit.vars.len() {
            let (file, contract, decl) = {
                let v = &self.unit.vars[vi];
                // A param/return/struct-field type is written in the scope
                // of its owning function or struct, not just the file: a
                // library- or contract-nested type name (e.g. `D storage d`
                // where `struct D` is declared inside the same library)
                // only resolves via that owner's contract scope (issue
                // #92). File-level owners (`FileConst`) have no such scope.
                let contract = match v.owner {
                    VarOwner::State(c) => Some(c),
                    VarOwner::Param(f) | VarOwner::Return(f) => self.unit.function(f).contract,
                    VarOwner::StructField(t) => self.unit.type_decl(t).contract,
                    VarOwner::FileConst(_) | VarOwner::Local(_) => None,
                };
                (v.file, contract, v.decl)
            };
            let is_sig_level = matches!(
                self.unit.vars[vi].owner,
                VarOwner::State(_)
                    | VarOwner::FileConst(_)
                    | VarOwner::StructField(_)
                    | VarOwner::Param(_)
                    | VarOwner::Return(_)
            );
            if !is_sig_level {
                continue;
            }
            let mut w = Walker::new(self, file, contract, None);
            w.walk_type(&decl.ty);
            if let Some(init) = &decl.initializer {
                w.walk_expr(init);
            }
        }

        // Event/error parameter types.
        for ei in 0..self.unit.events.len() {
            let (file, contract, ast) = (
                self.unit.events[ei].file,
                self.unit.events[ei].contract,
                self.unit.events[ei].ast,
            );
            let mut w = Walker::new(self, file, contract, None);
            for p in ast.parameters.vars.iter() {
                w.walk_type(&p.ty);
            }
        }
        for ei in 0..self.unit.errors.len() {
            let (file, contract, ast) = (
                self.unit.errors[ei].file,
                self.unit.errors[ei].contract,
                self.unit.errors[ei].ast,
            );
            let mut w = Walker::new(self, file, contract, None);
            for p in ast.parameters.vars.iter() {
                w.walk_type(&p.ty);
            }
        }

        // Contract base constructor arguments (`is Base(42)`).
        for ci in 0..self.unit.contracts.len() {
            let (file, ast) = (self.unit.contracts[ci].file, self.unit.contracts[ci].ast);
            let mut w = Walker::new(self, file, Some(ContractId::new(ci)), None);
            for base in ast.bases.iter() {
                for arg in base.arguments.exprs() {
                    w.walk_expr(arg);
                }
            }
        }

        // Function bodies.
        for fi in 0..self.unit.functions.len() {
            let (file, contract, func) = {
                let f = &self.unit.functions[fi];
                (f.file, f.contract, f.ast)
            };
            let id = FunctionId::new(fi);
            let mut w = Walker::new(self, file, contract, Some(id));
            w.push_scope();
            // Parameters and named returns are visible throughout the body.
            let params = w.binder.unit.functions[fi].params.clone();
            for vid in params {
                w.declare_existing(vid, Resolution::Param(vid));
            }
            let returns = w.binder.unit.functions[fi].returns.clone();
            for vid in returns {
                // Named returns behave as locals.
                w.declare_existing(vid, Resolution::Local(vid));
            }
            // The §2.8 shared-return recipient (`shared(msg.sender)`), if
            // any: syntactically part of the return-type list, but a name
            // inside it resolves in the function's own scope — params
            // included — same as any other body expression. Walking it here,
            // with params already declared, is what lets the checker tell a
            // shadowing parameter named `msg` from the real builtin (spec
            // §2.8 restriction 2; issue #61).
            for r in func.header.returns() {
                if let Some(shared) = &r.shared {
                    if let Some(recipient) = &shared.recipient {
                        w.walk_expr(recipient);
                    }
                }
            }
            // Modifier invocations (includes base-constructor calls on constructors).
            for m in func.header.modifiers.iter() {
                let res = w.resolve_name(m.name.segments()[0].name, m.name.segments()[0].as_str());
                w.binder
                    .unit
                    .resolutions
                    .insert(m.name.segments()[0].span, res);
                for arg in m.arguments.exprs() {
                    w.walk_expr(arg);
                }
            }
            if let Some(body) = &func.body {
                for stmt in body.stmts.iter() {
                    w.walk_stmt(stmt);
                }
            }
            w.pop_scope();
        }
    }
}

// ----------------------------------------------------------------------
// The scope-aware statement/expression walker.
// ----------------------------------------------------------------------

struct Walker<'a, 'ast> {
    binder: &'a mut Binder<'ast>,
    file: FileId,
    contract: Option<ContractId>,
    function: Option<FunctionId>,
    scopes: Vec<NameTable>,
}

impl<'a, 'ast> Walker<'a, 'ast> {
    fn new(
        binder: &'a mut Binder<'ast>,
        file: FileId,
        contract: Option<ContractId>,
        function: Option<FunctionId>,
    ) -> Self {
        Self {
            binder,
            file,
            contract,
            function,
            scopes: Vec::new(),
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(NameTable::default());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    /// Declares an already-collected variable (param/named return) in the current scope.
    fn declare_existing(&mut self, vid: VarId, resolution: Resolution) {
        if let Some(name) = self.binder.unit.vars[vid.index()].name {
            self.declare(name, resolution);
        }
    }

    /// Declares a new local from its AST node and brings it into scope.
    fn declare_local(&mut self, var: &'ast ast::VariableDefinition<'ast>) {
        let function = self
            .function
            .expect("locals can only be declared inside a function body");
        let vid = self
            .binder
            .push_var(self.file, VarOwner::Local(function), var, Vec::new());
        if let Some(name) = var.name {
            self.declare(name, Resolution::Local(vid));
        }
    }

    fn declare(&mut self, name: Ident, resolution: Resolution) {
        let scope = self
            .scopes
            .last_mut()
            .expect("declaration outside any scope");
        if scope.contains_key(&name.name) {
            self.binder.unit.diagnostics.push(BindDiagnostic {
                code: CODE_DUPLICATE_DEFINITION,
                message: format!("duplicate declaration of `{name}` in the same scope"),
                span: name.span,
                file: self.file,
            });
            return;
        }
        scope.insert(name.name, resolution);
    }

    /// Full lookup: scopes → contract members → inherited surface → file scope →
    /// builtins → conservative fallbacks. See the crate docs for the exact order.
    fn resolve_name(&self, name: Symbol, text: &str) -> Resolution {
        for scope in self.scopes.iter().rev() {
            if let Some(r) = scope.get(&name) {
                return r.clone();
            }
        }
        if let Some(contract) = self.contract {
            if let Some(r) = self.binder.unit.own_member(contract, name) {
                return r.clone();
            }
            let lin = &self.binder.unit.contracts[contract.index()].linearization;
            if lin.complete {
                if let Some(r) = self.binder.unit.inherited_member(contract, name) {
                    return r;
                }
            } else {
                if let Some(r) = self
                    .binder
                    .unit
                    .inherited_member_in_known_prefix(contract, name)
                {
                    return r;
                }
                // Past the known prefix the name may still be a member of a
                // base this unit cannot see, and an inherited member shadows
                // a file-scope name of the same identifier. Returning the
                // file-scope binding here would hand a *permission* — the
                // call would classify as a builtin and skip the §7 branch
                // legality check — on a guess. Degrade instead, and carry
                // what file scope would have said for the policies that ask
                // for it explicitly (`trust.rs`, `precondition.rs`).
                let fallback = self.binder.unit.resolve_at_file(self.file, name, text);
                return Resolution::Unresolved(UnresolvedReason::IncompleteInheritance {
                    contract,
                    fallback: Box::new(fallback),
                });
            }
        }
        self.binder.unit.resolve_at_file(self.file, name, text)
    }

    fn resolve_ident(&mut self, ident: Ident) {
        let res = self.resolve_name(ident.name, ident.as_str());
        self.binder.unit.resolutions.insert(ident.span, res);
    }

    fn walk_stmt(&mut self, stmt: &'ast ast::Stmt<'ast>) {
        use ast::StmtKind::*;
        match &stmt.kind {
            DeclSingle(var) => {
                self.walk_type(&var.ty);
                if let Some(init) = &var.initializer {
                    self.walk_expr(init);
                }
                self.declare_local(var);
            }
            DeclMulti(vars, rhs) => {
                self.walk_expr(rhs);
                for var in vars.iter() {
                    if let Some(var) = var.as_ref().unspan() {
                        self.walk_type(&var.ty);
                        self.declare_local(var);
                    }
                }
            }
            // A `precondition { ... }` block (spec §2.7) binds exactly like an
            // ordinary nested block: its declarations are scoped to it and do
            // not escape. Positional legality is the checker's job.
            Block(block) | UncheckedBlock(block) | Precondition(block) => {
                self.push_scope();
                for s in block.stmts.iter() {
                    self.walk_stmt(s);
                }
                self.pop_scope();
            }
            Break | Continue | Placeholder => {}
            DoWhile(body, cond) => {
                self.walk_stmt(body);
                self.walk_expr(cond);
            }
            Emit(path, args) | Revert(path, args) => {
                let first = path.segments()[0];
                let res = self.resolve_name(first.name, first.as_str());
                self.binder.unit.resolutions.insert(first.span, res);
                for arg in args.exprs() {
                    self.walk_expr(arg);
                }
            }
            Expr(e) => self.walk_expr(e),
            For {
                init,
                cond,
                next,
                body,
            } => {
                self.push_scope();
                if let Some(init) = init {
                    self.walk_stmt(init);
                }
                if let Some(cond) = cond {
                    self.walk_expr(cond);
                }
                if let Some(next) = next {
                    self.walk_expr(next);
                }
                self.walk_stmt(body);
                self.pop_scope();
            }
            If(cond, then, els) => {
                self.walk_expr(cond);
                self.walk_stmt(then);
                if let Some(els) = els {
                    self.walk_stmt(els);
                }
            }
            Return(e) => {
                if let Some(e) = e {
                    self.walk_expr(e);
                }
            }
            Try(t) => {
                self.walk_expr(t.expr);
                for clause in t.clauses.iter() {
                    self.push_scope();
                    for var in clause.args.vars.iter() {
                        self.walk_type(&var.ty);
                        self.declare_local(var);
                    }
                    for s in clause.block.stmts.iter() {
                        self.walk_stmt(s);
                    }
                    self.pop_scope();
                }
            }
            While(cond, body) => {
                self.walk_expr(cond);
                self.walk_stmt(body);
            }
            // Yul is outside the positive fragment; the legality pass rejects encrypted
            // interactions with assembly separately.
            Assembly(_) => {}
        }
    }

    fn walk_expr(&mut self, expr: &'ast ast::Expr<'ast>) {
        use ast::ExprKind::*;
        match &expr.kind {
            Array(els) => {
                for e in els.iter() {
                    self.walk_expr(e);
                }
            }
            Assign(lhs, _, rhs) => {
                self.walk_expr(lhs);
                self.walk_expr(rhs);
            }
            Binary(l, _, r) => {
                self.walk_expr(l);
                self.walk_expr(r);
            }
            Call(callee, args) => {
                self.walk_expr(callee);
                for arg in args.exprs() {
                    self.walk_expr(arg);
                }
            }
            CallOptions(base, opts) => {
                self.walk_expr(base);
                for opt in opts.iter() {
                    self.walk_expr(opt.value);
                }
            }
            Delete(e) => self.walk_expr(e),
            Ident(ident) => self.resolve_ident(*ident),
            Index(base, kind) => {
                self.walk_expr(base);
                match kind {
                    ast::IndexKind::Index(e) => {
                        if let Some(e) = e {
                            self.walk_expr(e);
                        }
                    }
                    ast::IndexKind::Range(a, b) => {
                        if let Some(a) = a {
                            self.walk_expr(a);
                        }
                        if let Some(b) = b {
                            self.walk_expr(b);
                        }
                    }
                }
            }
            Lit(..) => {}
            // Member names after `.` need type information; the checker resolves them.
            Member(base, _name) => self.walk_expr(base),
            New(ty) => self.walk_type(ty),
            Payable(args) => {
                for arg in args.exprs() {
                    self.walk_expr(arg);
                }
            }
            Ternary(c, a, b) => {
                self.walk_expr(c);
                self.walk_expr(a);
                self.walk_expr(b);
            }
            Tuple(els) => {
                for e in els.iter() {
                    if let Some(e) = e.as_ref().unspan() {
                        self.walk_expr(e);
                    }
                }
            }
            TypeCall(ty) | Type(ty) => self.walk_type(ty),
            Unary(_, e) => self.walk_expr(e),
            Err(_) => {}
        }
    }

    fn walk_type(&mut self, ty: &'ast ast::Type<'ast>) {
        use ast::TypeKind::*;
        match &ty.kind {
            Elementary(_) => {}
            Array(a) => {
                self.walk_type(&a.element);
                if let Some(size) = &a.size {
                    self.walk_expr(size);
                }
            }
            Function(f) => {
                for p in f.parameters.vars.iter() {
                    self.walk_type(&p.ty);
                }
                for r in f.returns() {
                    self.walk_type(&r.ty);
                }
            }
            Mapping(m) => {
                self.walk_type(&m.key);
                self.walk_type(&m.value);
            }
            Custom(path) => {
                let first = path.segments()[0];
                let res = self.resolve_name(first.name, first.as_str());
                self.binder.unit.resolutions.insert(first.span, res);
            }
        }
    }
}
