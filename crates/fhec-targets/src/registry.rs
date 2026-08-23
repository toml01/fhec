//! Resolution of a `fhec.toml` target string to a profile instance.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use crate::cofhe::CofheProfile;
use crate::profile::TargetProfile;

/// A shareable, thread-safe profile handle.
pub type ProfileHandle = Arc<dyn TargetProfile + Send + Sync>;

/// The requested target profile is not registered (→ FHE5002,
/// unknown-target-profile).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProfileError {
    /// The specifier as requested (e.g. `"zama@1"`).
    pub requested: String,
    /// The registered specifiers, sorted.
    pub available: Vec<String>,
}

impl fmt::Display for UnknownProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown target profile `{}` (available: {})",
            self.requested,
            self.available.join(", ")
        )
    }
}

impl std::error::Error for UnknownProfileError {}

/// Registry mapping profile specifiers (`"<family>@<version>"`, plus a bare
/// `"<family>"` alias for the family default) to profile instances.
pub struct ProfileRegistry {
    entries: BTreeMap<String, ProfileHandle>,
}

impl ProfileRegistry {
    /// The registry of built-in profiles.
    ///
    /// Currently: `cofhe@0.2.x` (also reachable as plain `cofhe`). Future
    /// versions (e.g. a `cofhe@HEAD` data delta) register here.
    pub fn builtin() -> Self {
        let mut registry = ProfileRegistry {
            entries: BTreeMap::new(),
        };
        let cofhe_0_2: ProfileHandle = Arc::new(CofheProfile::v0_2());
        registry.register("cofhe@0.2.x", Arc::clone(&cofhe_0_2));
        registry.register("cofhe", cofhe_0_2);
        registry
    }

    fn register(&mut self, spec: &str, profile: ProfileHandle) {
        self.entries.insert(spec.to_string(), profile);
    }

    /// Resolves a profile specifier.
    pub fn resolve(&self, spec: &str) -> Result<ProfileHandle, UnknownProfileError> {
        self.entries
            .get(spec)
            .cloned()
            .ok_or_else(|| UnknownProfileError {
                requested: spec.to_string(),
                available: self.available(),
            })
    }

    /// All registered specifiers, sorted.
    pub fn available(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_builtin_specs() {
        let registry = ProfileRegistry::builtin();
        let by_alias = registry.resolve("cofhe").unwrap();
        let by_full = registry.resolve("cofhe@0.2.x").unwrap();
        assert_eq!(by_alias.id(), "cofhe");
        assert_eq!(by_alias.version(), "0.2.x");
        assert_eq!(by_full.version(), "0.2.x");
    }

    #[test]
    fn unknown_profile_lists_available() {
        let registry = ProfileRegistry::builtin();
        let Err(err) = registry.resolve("zama@1") else {
            panic!("zama@1 must not resolve");
        };
        assert_eq!(err.requested, "zama@1");
        assert_eq!(err.available, vec!["cofhe", "cofhe@0.2.x"]);
        assert!(err.to_string().contains("unknown target profile `zama@1`"));
    }
}
