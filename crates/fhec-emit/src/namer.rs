//! Deterministic generated-temporary naming (spec §2.4).
//!
//! Names follow `__fhe_<hint>_<n>` with a single per-function counter shared
//! by all hints, starting at 0 and incremented per generated temp. A
//! candidate that collides with a visible identifier is skipped (the counter
//! advances), so identical input always produces identical names.

use std::collections::HashSet;
use std::fmt;

/// The role of a generated temporary (the `<hint>` part, spec §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TempHint {
    /// Hoisted encrypted condition (§5.2 step 2).
    Cond,
    /// Pre-value of a written location (§5.2 step 4).
    Pre,
    /// Then-branch assignment version (§5.2 step 5).
    Then,
    /// Else-branch assignment version (§5.2 step 5).
    Else,
    /// Hoisted plaintext index key (§5.2 step 3).
    Key,
    /// General hoisted value.
    Val,
    /// Hoisted return value (§8.3 R3).
    Ret,
    /// Hoisted callee address (§8.2 R2).
    Callee,
    /// Batch input array of a multi-`in`-parameter expansion (§2.3).
    Inputs,
    /// Verified handle array of a multi-`in`-parameter expansion (§2.3).
    Hashes,
}

impl TempHint {
    /// The hint's spelling inside the generated name.
    pub fn as_str(self) -> &'static str {
        match self {
            TempHint::Cond => "cond",
            TempHint::Pre => "pre",
            TempHint::Then => "then",
            TempHint::Else => "else",
            TempHint::Key => "key",
            TempHint::Val => "val",
            TempHint::Ret => "ret",
            TempHint::Callee => "callee",
            TempHint::Inputs => "inputs",
            TempHint::Hashes => "hashes",
        }
    }
}

impl fmt::Display for TempHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A per-function temporary-name generator.
///
/// Construct one per function with every identifier visible in that function
/// (parameters, locals, referenced contract members — the binder supplies
/// these); names it hands out are added to the taken set, so repeated calls
/// never collide with each other either.
#[derive(Debug, Clone)]
pub struct TempNamer {
    taken: HashSet<String>,
    next: usize,
}

impl TempNamer {
    /// A namer that avoids every identifier in `taken`.
    pub fn new<I, S>(taken: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        TempNamer {
            taken: taken.into_iter().map(Into::into).collect(),
            next: 0,
        }
    }

    /// The next free name for `hint`, deterministically.
    ///
    /// The counter is shared across hints and advances on every attempt, so a
    /// collision "skips to the next unused n" exactly as spec §2.4 requires.
    /// Terminates because the taken set is finite (pigeonhole).
    pub fn fresh(&mut self, hint: TempHint) -> String {
        loop {
            let candidate = format!("__fhe_{}_{}", hint.as_str(), self.next);
            self.next += 1;
            if self.taken.insert(candidate.clone()) {
                return candidate;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_counter_across_hints() {
        let mut n = TempNamer::new(Vec::<String>::new());
        assert_eq!(n.fresh(TempHint::Cond), "__fhe_cond_0");
        assert_eq!(n.fresh(TempHint::Pre), "__fhe_pre_1");
        assert_eq!(n.fresh(TempHint::Pre), "__fhe_pre_2");
        assert_eq!(n.fresh(TempHint::Ret), "__fhe_ret_3");
    }

    #[test]
    fn collision_skips_to_next_unused() {
        let mut n = TempNamer::new(["__fhe_cond_0", "__fhe_pre_1"]);
        assert_eq!(n.fresh(TempHint::Cond), "__fhe_cond_1");
        // Counter is now 2; "__fhe_pre_1" being taken is irrelevant at n=2.
        assert_eq!(n.fresh(TempHint::Pre), "__fhe_pre_2");
    }

    #[test]
    fn deterministic_across_instances() {
        let taken = ["count", "__fhe_val_0", "__fhe_val_1"];
        let seq = |mut n: TempNamer| {
            vec![
                n.fresh(TempHint::Val),
                n.fresh(TempHint::Cond),
                n.fresh(TempHint::Val),
            ]
        };
        assert_eq!(seq(TempNamer::new(taken)), seq(TempNamer::new(taken)));
        assert_eq!(
            seq(TempNamer::new(taken)),
            vec!["__fhe_val_2", "__fhe_cond_3", "__fhe_val_4"]
        );
    }
}
