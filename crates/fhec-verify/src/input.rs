//! The standard-JSON input handed to `solc --standard-json`.
//!
//! The caller supplies **every** source, keyed by the virtual path solc should
//! see. solc therefore never touches the filesystem to resolve an import: a
//! relative import resolves against the importing source's virtual path, and a
//! bare import such as `@openzeppelin/contracts/utils/Strings.sol` must be
//! present in the map under exactly that key (or be reachable through a
//! [`CompileSettings::remappings`] entry).

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// The default EVM version for emitted contracts, per PLAN.md stage 8.
pub const DEFAULT_EVM_VERSION: &str = "cancun";

/// Which compiler outputs to request.
///
/// The verify gate only needs `errors[]`, so [`OutputSelection::ErrorsOnly`] is
/// the default and keeps solc from running code generation at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OutputSelection {
    /// Request nothing. solc still parses, resolves and type-checks, so every
    /// analysis diagnostic is reported, but code generation is skipped — which
    /// means codegen-only diagnostics such as "stack too deep" do not appear.
    #[default]
    ErrorsOnly,
    /// Request ABI, metadata and creation/runtime bytecode for every contract.
    /// Slower, but populates [`crate::CompileOutput::contracts`] and surfaces
    /// codegen diagnostics.
    Artifacts,
    /// A caller-built `outputSelection` object, used verbatim.
    Custom(Value),
}

impl OutputSelection {
    /// The `outputSelection` value to put in the standard-JSON settings.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::ErrorsOnly => json!({ "*": { "": [], "*": [] } }),
            Self::Artifacts => json!({
                "*": {
                    "*": [
                        "abi",
                        "metadata",
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object",
                    ],
                }
            }),
            Self::Custom(value) => value.clone(),
        }
    }
}

/// The optimizer settings block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Optimizer {
    /// Whether the optimizer runs at all. Off by default: the gate checks that
    /// the output compiles, and optimizing costs time without changing
    /// diagnostics.
    pub enabled: bool,
    /// The `runs` tuning parameter, only meaningful when `enabled`.
    pub runs: u32,
}

impl Default for Optimizer {
    fn default() -> Self {
        Self {
            enabled: false,
            runs: 200,
        }
    }
}

impl Optimizer {
    /// An enabled optimizer with the given `runs`.
    #[must_use]
    pub fn enabled(runs: u32) -> Self {
        Self {
            enabled: true,
            runs,
        }
    }
}

/// The `settings` block of the standard-JSON input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileSettings {
    /// The EVM version to target. Defaults to [`DEFAULT_EVM_VERSION`]; `None`
    /// omits the key and lets solc pick its own default.
    pub evm_version: Option<String>,
    /// Optimizer configuration. Off by default.
    pub optimizer: Optimizer,
    /// Which outputs to request. [`OutputSelection::ErrorsOnly`] by default.
    pub output: OutputSelection,
    /// Import remappings, in solc's `prefix=target` form. Usually empty,
    /// because the caller supplies fully-keyed sources.
    pub remappings: Vec<String>,
    /// Whether to compile through the Yul IR pipeline.
    pub via_ir: bool,
    /// Stop after parsing, skipping analysis. Useful for a cheap syntax gate.
    pub stop_after_parsing: bool,
    /// Extra settings keys merged over the generated ones, as an escape hatch
    /// for options this struct does not model.
    pub extra: Map<String, Value>,
}

impl Default for CompileSettings {
    fn default() -> Self {
        Self {
            evm_version: Some(DEFAULT_EVM_VERSION.to_owned()),
            optimizer: Optimizer::default(),
            output: OutputSelection::default(),
            remappings: Vec::new(),
            via_ir: false,
            stop_after_parsing: false,
            extra: Map::new(),
        }
    }
}

impl CompileSettings {
    /// The `settings` object of the standard-JSON input.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut settings = Map::new();
        if let Some(evm_version) = &self.evm_version {
            settings.insert("evmVersion".to_owned(), json!(evm_version));
        }
        settings.insert(
            "optimizer".to_owned(),
            json!({ "enabled": self.optimizer.enabled, "runs": self.optimizer.runs }),
        );
        settings.insert("outputSelection".to_owned(), self.output.to_json());
        if !self.remappings.is_empty() {
            settings.insert("remappings".to_owned(), json!(self.remappings));
        }
        if self.via_ir {
            settings.insert("viaIR".to_owned(), json!(true));
        }
        if self.stop_after_parsing {
            settings.insert("stopAfter".to_owned(), json!("parsing"));
        }
        for (key, value) in &self.extra {
            settings.insert(key.clone(), value.clone());
        }
        Value::Object(settings)
    }
}

/// A complete standard-JSON compilation request.
///
/// # Example
///
/// ```
/// use fhec_verify::CompileInput;
///
/// let input = CompileInput::new()
///     .with_source("generated/Counter.sol", "// SPDX-License-Identifier: MIT\n")
///     .with_source("@openzeppelin/contracts/utils/Strings.sol", "// …library source…\n");
/// assert_eq!(input.sources.len(), 2);
/// assert_eq!(input.to_standard_json()["language"], "Solidity");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompileInput {
    /// Virtual source path to file content. Must be closed under imports: no
    /// filesystem resolution happens inside solc.
    pub sources: BTreeMap<String, String>,
    /// Compiler settings.
    pub settings: CompileSettings,
}

impl CompileInput {
    /// An empty request with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a source, builder-style.
    #[must_use]
    pub fn with_source(mut self, path: impl Into<String>, content: impl Into<String>) -> Self {
        self.sources.insert(path.into(), content.into());
        self
    }

    /// Replaces the settings, builder-style.
    #[must_use]
    pub fn with_settings(mut self, settings: CompileSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Adds a source, returning any content it displaced.
    pub fn insert_source(
        &mut self,
        path: impl Into<String>,
        content: impl Into<String>,
    ) -> Option<String> {
        self.sources.insert(path.into(), content.into())
    }

    /// Renders the full standard-JSON request.
    #[must_use]
    pub fn to_standard_json(&self) -> Value {
        let sources = self
            .sources
            .iter()
            .map(|(path, content)| (path.clone(), json!({ "content": content })))
            .collect::<Map<_, _>>();
        json!({
            "language": "Solidity",
            "sources": Value::Object(sources),
            "settings": self.settings.to_json(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_cancun_no_optimizer_errors_only() {
        let json = CompileInput::new()
            .with_source("A.sol", "contract A {}")
            .to_standard_json();
        assert_eq!(json["language"], "Solidity");
        assert_eq!(json["sources"]["A.sol"]["content"], "contract A {}");
        assert_eq!(json["settings"]["evmVersion"], "cancun");
        assert_eq!(json["settings"]["optimizer"]["enabled"], false);
        assert_eq!(json["settings"]["outputSelection"]["*"]["*"], json!([]));
        assert!(json["settings"].get("viaIR").is_none());
        assert!(json["settings"].get("remappings").is_none());
    }

    #[test]
    fn artifacts_selection_asks_for_bytecode() {
        let settings = CompileSettings {
            output: OutputSelection::Artifacts,
            optimizer: Optimizer::enabled(999),
            via_ir: true,
            ..CompileSettings::default()
        };
        let json = CompileInput::new()
            .with_settings(settings)
            .to_standard_json();
        let selection = &json["settings"]["outputSelection"]["*"]["*"];
        assert!(selection
            .as_array()
            .expect("array")
            .contains(&json!("evm.bytecode.object")));
        assert_eq!(json["settings"]["optimizer"]["runs"], 999);
        assert_eq!(json["settings"]["viaIR"], true);
    }

    #[test]
    fn custom_selection_and_extra_settings_pass_through() {
        let mut extra = Map::new();
        extra.insert("debug".to_owned(), json!({ "revertStrings": "strip" }));
        let settings = CompileSettings {
            evm_version: None,
            output: OutputSelection::Custom(json!({ "A.sol": { "A": ["ir"] } })),
            remappings: vec!["oz/=node_modules/@openzeppelin/".to_owned()],
            stop_after_parsing: true,
            extra,
            ..CompileSettings::default()
        };
        let json = settings.to_json();
        assert!(json.get("evmVersion").is_none());
        assert_eq!(json["outputSelection"]["A.sol"]["A"], json!(["ir"]));
        assert_eq!(json["remappings"][0], "oz/=node_modules/@openzeppelin/");
        assert_eq!(json["stopAfter"], "parsing");
        assert_eq!(json["debug"]["revertStrings"], "strip");
    }

    #[test]
    fn sources_are_ordered_deterministically() {
        let input = CompileInput::new()
            .with_source("b.sol", "b")
            .with_source("a.sol", "a");
        let rendered = serde_json::to_string(&input.to_standard_json()).expect("serialises");
        let a = rendered.find("a.sol").expect("a present");
        let b = rendered.find("b.sol").expect("b present");
        assert!(a < b, "BTreeMap ordering makes the payload byte-stable");
    }
}
