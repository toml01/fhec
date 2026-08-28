//! Selective imports versus the symbols the sugar needs (spec §2.3, §2.8).
//!
//! A plain `import "…/FHE.sol";` brings the whole profile surface into scope
//! and nothing here applies. A *selective* import brings in exactly what it
//! names, which the dialect can outgrow in two directions:
//!
//! - the author writes `in shared euint64 x` in a file that imported only
//!   `sharedEuint64`, so the type the marker names is not in scope;
//! - the expansion emits `externalEuint64` / `sharedEuint64` in a file that
//!   imported only the plain types, so the *generated* name is not in scope.
//!
//! Both are the same missing line, and both are fixable mechanically: extend
//! the import list. This module finds the import and builds that fix-it.

use solar_ast as ast;
use solar_interface::Span;

use crate::diag::FixIt;
use crate::trust::Trust;

/// A selective import of the profile module, and what it names.
pub(crate) struct SelectiveProfileImport {
    /// Names the list already brings into scope (aliases count as the alias).
    names: Vec<String>,
    /// Byte position just after the last name in the list.
    insert_at: Span,
}

impl SelectiveProfileImport {
    /// Whether the list already brings `name` into scope.
    pub(crate) fn has(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// A `safe: true` fix-it that adds `name` to the list.
    pub(crate) fn extend_fixit(&self, name: &str) -> FixIt {
        FixIt {
            span: self.insert_at,
            replacement: format!(", {name}"),
            safe: true,
        }
    }
}

/// The file's selective import of the profile module, if it has exactly one.
///
/// Returns `None` for a plain or glob import (everything is in scope), for a
/// file that does not import the profile at all, and for the ambiguous case
/// of several selective imports of the same module.
pub(crate) fn selective_profile_import<'ast>(
    file: &ast::SourceUnit<'ast>,
    trust: &Trust,
) -> Option<SelectiveProfileImport> {
    let mut found: Option<SelectiveProfileImport> = None;
    for item in file.items.iter() {
        let ast::ItemKind::Import(import) = &item.kind else {
            continue;
        };
        if !trust.specifier_trusted(import.path.value.as_str()) {
            continue;
        }
        let ast::ImportItems::Aliases(list) = &import.items else {
            return None; // a plain or glob import covers everything
        };
        let last = list.last()?;
        let names = list
            .iter()
            .map(|(name, alias)| alias.unwrap_or(*name).as_str().to_string())
            .collect();
        let end = last.1.unwrap_or(last.0).span;
        if found.is_some() {
            return None; // more than one: do not guess which to extend
        }
        found = Some(SelectiveProfileImport {
            names,
            insert_at: end.with_lo(end.hi()),
        });
    }
    found
}
