//! [`BoundUnit`]: the queryable result of binding a compilation unit.

use crate::binder::FileInfo;
use crate::ids::{ContractId, ErrorId, EventId, FileId, FunctionId, TypeDeclId, VarId};
use crate::model::*;
use solar_ast as ast;
use solar_data_structures::map::FxHashMap;
use solar_interface::{Ident, Span, Symbol};

/// One parsed source file of a compilation unit.
///
/// `ast` must stay alive for the whole pipeline run: the binder borrows AST nodes.
pub struct SourceFile<'ast> {
    /// The (virtual) path of the file, used to resolve relative imports between unit
    /// files. Forward slashes only.
    pub name: String,
    /// The parsed source unit.
    pub ast: &'ast ast::SourceUnit<'ast>,
}

/// The bound compilation unit: declarations, scopes, resolutions, inheritance.
///
/// # Lifetime design
///
/// The solar AST is arena-allocated; `BoundUnit<'ast>` *borrows* it. The intended use is
/// a same-scope pipeline: enter a solar `Session`, parse every file into one `Arena`,
/// call [`bind`](crate::bind), and run the checker/lowering passes inside that scope.
/// All name text is additionally stored as owned `String`s where the checker needs
/// session-free access; resolved identifier uses are keyed by their [`Span`], which is
/// unique across a session's source map.
pub struct BoundUnit<'ast> {
    pub(crate) files: Vec<FileInfo<'ast>>,
    pub(crate) contracts: Vec<ContractInfo<'ast>>,
    pub(crate) functions: Vec<FunctionInfo<'ast>>,
    pub(crate) vars: Vec<VarInfo<'ast>>,
    pub(crate) type_decls: Vec<TypeDeclInfo<'ast>>,
    pub(crate) events: Vec<EventInfo<'ast>>,
    pub(crate) errors: Vec<ErrorInfo<'ast>>,
    pub(crate) usings: Vec<UsingEntry>,
    pub(crate) resolutions: FxHashMap<Span, Resolution>,
    pub(crate) diagnostics: Vec<BindDiagnostic>,
}

impl<'ast> BoundUnit<'ast> {
    /// The files of the unit as `(id, normalized name)` pairs.
    pub fn files(&self) -> impl Iterator<Item = (FileId, &str)> + use<'_, 'ast> {
        self.files
            .iter()
            .enumerate()
            .map(|(i, f)| (FileId::new(i), f.name.as_str()))
    }

    /// Looks up a file by its normalized name.
    pub fn file_id(&self, name: &str) -> Option<FileId> {
        let name = crate::binder::normalize_join("", name);
        self.files
            .iter()
            .position(|f| f.name == name)
            .map(FileId::new)
    }

    /// All contracts in the unit.
    pub fn contracts(
        &self,
    ) -> impl Iterator<Item = (ContractId, &ContractInfo<'ast>)> + use<'_, 'ast> {
        self.contracts
            .iter()
            .enumerate()
            .map(|(i, c)| (ContractId::new(i), c))
    }

    /// The contract with the given id.
    pub fn contract(&self, id: ContractId) -> &ContractInfo<'ast> {
        &self.contracts[id.index()]
    }

    /// Finds a contract by name (first match across the unit).
    pub fn contract_by_name(&self, name: &str) -> Option<ContractId> {
        self.contracts
            .iter()
            .position(|c| c.name_str == name)
            .map(ContractId::new)
    }

    /// All functions in the unit.
    pub fn functions(
        &self,
    ) -> impl Iterator<Item = (FunctionId, &FunctionInfo<'ast>)> + use<'_, 'ast> {
        self.functions
            .iter()
            .enumerate()
            .map(|(i, f)| (FunctionId::new(i), f))
    }

    /// The function with the given id.
    pub fn function(&self, id: FunctionId) -> &FunctionInfo<'ast> {
        &self.functions[id.index()]
    }

    /// Finds a function of a contract by name (first overload).
    pub fn function_by_name(&self, contract: ContractId, name: &str) -> Option<FunctionId> {
        self.contract(contract)
            .functions
            .iter()
            .copied()
            .find(|&f| self.functions[f.index()].name_str.as_deref() == Some(name))
    }

    /// The variable with the given id.
    pub fn var(&self, id: VarId) -> &VarInfo<'ast> {
        &self.vars[id.index()]
    }

    /// The type declaration with the given id.
    pub fn type_decl(&self, id: TypeDeclId) -> &TypeDeclInfo<'ast> {
        &self.type_decls[id.index()]
    }

    /// All type declarations in the unit, in declaration order.
    pub fn type_decls(
        &self,
    ) -> impl Iterator<Item = (TypeDeclId, &TypeDeclInfo<'ast>)> + use<'_, 'ast> {
        self.type_decls
            .iter()
            .enumerate()
            .map(|(i, t)| (TypeDeclId::new(i), t))
    }

    /// The event declaration with the given id.
    pub fn event(&self, id: EventId) -> &EventInfo<'ast> {
        &self.events[id.index()]
    }

    /// The error declaration with the given id.
    pub fn error(&self, id: ErrorId) -> &ErrorInfo<'ast> {
        &self.errors[id.index()]
    }

    /// The resolution recorded for an identifier *use*, keyed by its span.
    ///
    /// Returns `None` for spans the binder does not resolve (e.g. member names after
    /// `.`, which require type information and belong to the checker).
    pub fn resolve(&self, ident: Ident) -> Option<&Resolution> {
        self.resolve_span(ident.span)
    }

    /// Like [`resolve`](Self::resolve), from a raw span.
    pub fn resolve_span(&self, span: Span) -> Option<&Resolution> {
        self.resolutions.get(&span)
    }

    /// The linearized inheritance of a contract (most-derived-first, starting with the
    /// contract itself). Check [`Linearization::complete`] before trusting the tail.
    pub fn linearization(&self, id: ContractId) -> &Linearization {
        &self.contracts[id.index()].linearization
    }

    /// Structural diagnostics found while binding (FHE1xxx).
    pub fn diagnostics(&self) -> &[BindDiagnostic] {
        &self.diagnostics
    }

    /// All collected `using` directives, resolved.
    pub fn usings(&self) -> &[UsingEntry] {
        &self.usings
    }

    /// Looks up a file-level name visible in `file` (own declarations plus everything
    /// merged in by plain imports). Used for `NS.member` resolution by the checker.
    pub fn namespace_member(&self, file: FileId, name: Symbol) -> Option<&Resolution> {
        let f = &self.files[file.index()];
        f.own_exports
            .get(&name)
            .or_else(|| f.import_bindings.get(&name))
    }

    /// Resolves method-call syntax `receiver.method(...)` where `receiver` has the
    /// *single-identifier* type named `receiver_type` (e.g. `euint32`), through the
    /// `using` directives visible at (`file`, `ctx`).
    ///
    /// Bindings declared in external files (the CoFHE pattern: `using BindingsEuint32
    /// for euint32 global;` lives inside FHE.sol) are invisible here; the checker must
    /// consult the target profile for those.
    pub fn method_candidates(
        &self,
        ctx: Option<ContractId>,
        file: FileId,
        receiver_type: &str,
        method: Symbol,
    ) -> MethodResolution {
        let mut ids: Vec<FunctionId> = Vec::new();
        let mut external: Option<Option<String>> = None;

        // The contracts whose contract-scoped `using` directives apply here: the
        // context contract and (when the hierarchy is known) its bases.
        let ctx_chain: Vec<ContractId> = match ctx {
            Some(c) => {
                let lin = &self.contracts[c.index()].linearization;
                lin.order.clone()
            }
            None => Vec::new(),
        };

        for entry in &self.usings {
            let in_scope = entry.global
                || (entry.contract.is_none() && entry.file == file)
                || entry.contract.is_some_and(|c| ctx_chain.contains(&c));
            if !in_scope {
                continue;
            }
            let target_matches = match &entry.target {
                UsingTarget::Wildcard => true,
                UsingTarget::Name(n) => n == receiver_type,
                UsingTarget::Complex => false,
            };
            if !target_matches {
                continue;
            }
            match &entry.list {
                UsingListResolution::Library(res) => match res {
                    Resolution::Contract(lib) => {
                        if let Some(Resolution::Function(fs)) =
                            self.contracts[lib.index()].members.get(&method)
                        {
                            ids.extend(fs.iter().copied());
                        }
                    }
                    Resolution::External { specifier, .. } => {
                        external.get_or_insert(Some(specifier.clone()));
                    }
                    // A library we cannot see may bind this method; report External
                    // rather than claiming there is no binding.
                    Resolution::Unresolved(_) => {
                        external.get_or_insert(None);
                    }
                    _ => {}
                },
                UsingListResolution::Functions(entries) => {
                    for e in entries {
                        if e.is_operator || e.method != method {
                            continue;
                        }
                        match &e.resolution {
                            Resolution::Function(fs) => ids.extend(fs.iter().copied()),
                            Resolution::External { specifier, .. } => {
                                external.get_or_insert(Some(specifier.clone()));
                            }
                            Resolution::Unresolved(_) => {
                                external.get_or_insert(None);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if !ids.is_empty() {
            ids.sort_unstable();
            ids.dedup();
            MethodResolution::Functions(ids)
        } else if let Some(spec) = external {
            MethodResolution::External { specifier: spec }
        } else {
            MethodResolution::NoBinding
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            files: Vec::new(),
            contracts: Vec::new(),
            functions: Vec::new(),
            vars: Vec::new(),
            type_decls: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            usings: Vec::new(),
            resolutions: FxHashMap::default(),
            diagnostics: Vec::new(),
        }
    }

    /// Own-member lookup on a contract, without inheritance.
    pub(crate) fn own_member(&self, contract: ContractId, name: Symbol) -> Option<&Resolution> {
        self.contracts[contract.index()].members.get(&name)
    }

    /// Member lookup through the linearized inheritance chain. Private members of base
    /// contracts are not visible. Must only be called when the linearization is
    /// complete (callers handle the incomplete case).
    pub(crate) fn inherited_member(
        &self,
        contract: ContractId,
        name: Symbol,
    ) -> Option<Resolution> {
        let lin = &self.contracts[contract.index()].linearization;
        for &c in lin.order.iter().skip(1) {
            if let Some(member) = self.inheritable_own_member(c, name) {
                return Some(member);
            }
        }
        None
    }

    /// Looks up only the inherited members that precede every opaque base in
    /// all possible completions of an incomplete linearization.
    ///
    /// For a function name the returned list is a **lower bound** on the
    /// overload set: Solidity unions overloads across the whole
    /// linearization, and an unseen base may add a signature solc prefers.
    /// A caller that grants a *permission* on the strength of this answer —
    /// effect-freedom, branch safety — must therefore refuse instead when
    /// the linearization is incomplete. Typing is safe: a wrong return type
    /// dies at solc.
    pub(crate) fn inherited_member_in_known_prefix(
        &self,
        contract: ContractId,
        name: Symbol,
    ) -> Option<Resolution> {
        self.member_in_known_prefix(contract, name, false, &mut Vec::new())
    }

    fn member_in_known_prefix(
        &self,
        contract: ContractId,
        name: Symbol,
        include_own: bool,
        seen: &mut Vec<ContractId>,
    ) -> Option<Resolution> {
        if seen.contains(&contract) {
            return None;
        }
        seen.push(contract);

        if include_own {
            if let Some(member) = self.inheritable_own_member(contract, name) {
                return Some(member);
            }
        }

        let info = &self.contracts[contract.index()];
        if info.linearization.complete {
            return self.inherited_member(contract, name);
        }

        match info.bases.as_slice() {
            // With one known base, its own surface and its guaranteed prefix
            // necessarily precede the first opaque ancestor.
            [BaseRef::InUnit(base)] => self.member_in_known_prefix(*base, name, true, seen),
            // Solidity gives the rightmost direct base precedence. Its own
            // member is therefore certain even when a lower part of the C3
            // merge is opaque; no deeper member is certain because another
            // direct base can interleave before that ancestor.
            [.., BaseRef::InUnit(base)] => self.inheritable_own_member(*base, name),
            _ => None,
        }
    }

    fn inheritable_own_member(&self, contract: ContractId, name: Symbol) -> Option<Resolution> {
        match self.contracts[contract.index()].members.get(&name) {
            Some(Resolution::Function(fs)) => {
                let visible: Vec<FunctionId> = fs
                    .iter()
                    .copied()
                    .filter(|f| {
                        self.functions[f.index()].ast.header.visibility()
                            != Some(ast::Visibility::Private)
                    })
                    .collect();
                (!visible.is_empty()).then_some(Resolution::Function(visible))
            }
            Some(Resolution::StateVar(v)) => (self.vars[v.index()].decl.visibility
                != Some(ast::Visibility::Private))
            .then_some(Resolution::StateVar(*v)),
            Some(other) => Some(other.clone()),
            None => None,
        }
    }

    /// File-scope-only name lookup (own exports, then import bindings, then the
    /// conservative fallbacks). Used for base names, `using` paths, and as the tail of
    /// body-scope resolution.
    pub(crate) fn resolve_at_file(&self, file: FileId, name: Symbol, text: &str) -> Resolution {
        let f = &self.files[file.index()];
        if let Some(r) = f.own_exports.get(&name) {
            return r.clone();
        }
        if let Some(r) = f.import_bindings.get(&name) {
            return r.clone();
        }
        if let Some(b) = BUILTINS.iter().find(|b| **b == text) {
            return Resolution::Builtin(Builtin(b));
        }
        if !f.external_exposure.is_empty() {
            return Resolution::Unresolved(UnresolvedReason::MaybeExternal {
                specifiers: f.external_exposure.clone(),
            });
        }
        Resolution::Unresolved(UnresolvedReason::NotFound)
    }

    pub(crate) fn insert_using(&mut self, entry: UsingEntry) {
        self.usings.push(entry);
    }
}
