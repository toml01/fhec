//! `fhec explain FHEnnnn` — static registry of the diagnostic catalog.
//!
//! Hand-copied from spec/spec.md §9 (v0.1.0). Keep in sync when the spec
//! changes; codes are stable once assigned, so entries are append-only.

/// One catalog entry.
pub struct CatalogEntry {
    pub code: &'static str,
    pub severity: &'static str,
    pub name: &'static str,
    /// Spec section that defines the rule, when one exists.
    pub rule: &'static str,
    pub summary: &'static str,
}

/// The §9 catalog (plus draft CLI additions marked "draft").
pub static CATALOG: &[CatalogEntry] = &[
    CatalogEntry { code: "FHE1001", severity: "error", name: "unsupported-pragma-range", rule: "§2.1", summary: "The file's pragma solidity range is not within >=0.8.25 <0.9.0." },
    CatalogEntry { code: "FHE1002", severity: "error", name: "dialect-parse-error", rule: "§2.2", summary: "The source does not parse under the .fsol dialect grammar." },
    CatalogEntry { code: "FHE1003", severity: "error", name: "import-not-found", rule: "§2.2", summary: "An import specifier cannot be resolved. A relative .sol/.fsol swap that names a discovered unit file carries a safe fix-it." },
    CatalogEntry { code: "FHE1004", severity: "error", name: "config-not-found (draft)", rule: "—", summary: "No fhec.toml was found upward from the working directory (draft code, pending spec §9 inclusion)." },
    CatalogEntry { code: "FHE1005", severity: "error", name: "config-invalid (draft)", rule: "—", summary: "fhec.toml is unreadable or invalid (draft code, pending spec §9 inclusion)." },
    CatalogEntry { code: "FHE1006", severity: "error", name: "frozen-drift (draft)", rule: "§1.4", summary: "--frozen: regenerating the out dir would change it; run `fhec build` and commit (draft code, pending spec §9 inclusion)." },
    CatalogEntry { code: "FHE1007", severity: "warning", name: "no-files-matched", rule: "§2.1", summary: "project.include matched no .fsol/.sol files under project.src; this is almost always a misconfigured src or include glob." },
    CatalogEntry { code: "FHE1020", severity: "error", name: "duplicate-definition", rule: "§9", summary: "The same name is declared twice in one scope." },
    CatalogEntry { code: "FHE1010", severity: "error", name: "in-sugar-non-encrypted-type", rule: "§2.3", summary: "`in` parameter sugar used with a type that is not an encrypted value type." },
    CatalogEntry { code: "FHE1011", severity: "error", name: "in-sugar-name-collision", rule: "§2.3", summary: "The generated `<name>_input` identifier collides with an existing declaration." },
    CatalogEntry { code: "FHE1012", severity: "error", name: "in-sugar-bad-position", rule: "§2.3", summary: "`in` sugar outside a function/constructor parameter list." },
    CatalogEntry { code: "FHE1013", severity: "error", name: "in-sugar-proof-binding-invalid", rule: "§2.3", summary: "An `in(proof)` binder that does not name a `bytes memory` or `bytes calldata` parameter of the same parameter list." },
    CatalogEntry { code: "FHE1014", severity: "error", name: "in-sugar-proof-binding-inconsistent", rule: "§2.3", summary: "One parameter list mixes the implicit `in` form with the explicit `in(proof)` binder, or binds two different proof parameters." },
    CatalogEntry { code: "FHE1015", severity: "error", name: "shared-boundary-bad-position", rule: "§2.8", summary: "A shared-boundary marker in an illegal position or shape: `in shared` outside an external non-view function, in a `try`/`catch` declaration list, carrying a data location, mixed with external `in` inputs, a shared return that is named, part of a tuple, has a recipient other than `msg.sender`, or a `return` that is bare, braceless, assigns, or leaves a rewrite site in a statement an R2 grant already claims." },
    CatalogEntry { code: "FHE1016", severity: "error", name: "shared-boundary-name-collision", rule: "§2.8", summary: "The generated `<name>_shared` wire parameter collides with an existing declaration." },
    CatalogEntry { code: "FHE1017", severity: "error", name: "precondition-bad-position", rule: "§2.7", summary: "A `precondition` block that is not the first statement of the body, a second block in the same function, or a block on a function with no dialect-managed encrypted input." },
    CatalogEntry { code: "FHE1018", severity: "error", name: "cast-sugar-bad-arity", rule: "§2.9", summary: "Explicit cast sugar (`eT(...)`) called with a number of arguments other than one." },
    CatalogEntry { code: "FHE1019", severity: "error", name: "sugar-name-in-modifier", rule: "§2.3", summary: "A modifier invocation names a dialect-managed parameter; in the header that name is the wire parameter, so move the check into the function body." },
    CatalogEntry { code: "FHE1021", severity: "error", name: "sugar-symbol-not-imported", rule: "§2.3", summary: "A selective import from the profile module does not name a symbol the sugar needs, in the source or in its expansion; extend the import list." },
    CatalogEntry { code: "FHE1022", severity: "error", name: "fhe-library-identifier-shadowed", rule: "§1.3", summary: "A state variable, local, parameter, inherited member, or unseen-base member shadows (or an unconfirmed plain import could retarget) an identifier a generated call must use — `FHE`, or, for the batched `in`-sugar materializer, `Impl`/`Utils`/`UnsignedEncryptedInput`, and the `externalT`/`eT` wrap/unwrap type names its parameters name; rename the conflicting declaration or import the profile library directly." },
    CatalogEntry { code: "FHE2001", severity: "error", name: "encrypted-meets-unknown", rule: "§3.2", summary: "An encrypted operand meets an operand whose type the transpiler cannot determine; refusing rather than guessing." },
    CatalogEntry { code: "FHE2002", severity: "error", name: "incompatible-encrypted-operands", rule: "§3.2", summary: "Two encrypted operands of incompatible kinds (e.g. eaddress + euint32)." },
    CatalogEntry { code: "FHE2003", severity: "error", name: "literal-out-of-range", rule: "§3.3", summary: "A literal does not fit the target encrypted width (or is negative)." },
    CatalogEntry { code: "FHE2004", severity: "error", name: "implicit-narrowing-required", rule: "§3.3", summary: "The context would require an implicit narrowing conversion; narrowing is never inserted." },
    CatalogEntry { code: "FHE2005", severity: "error", name: "unary-minus-on-encrypted", rule: "§3.3", summary: "Unary minus on an encrypted value; use FHE.sub(FHE.asEuintN(0), x)." },
    CatalogEntry { code: "FHE2006", severity: "error", name: "operator-unsupported-for-encrypted-type", rule: "§4.1", summary: "The operator/type pair has no lowering in the operator table." },
    CatalogEntry { code: "FHE2007", severity: "error", name: "possibly-uninitialized-encrypted", rule: "§6", summary: "A possibly-uninitialized encrypted variable reaches an FHE operation, a return, or a function exit (an encrypted named return left unassigned on some path); CoFHE silently substitutes defaults, so this is always an error." },
    CatalogEntry { code: "FHE2008", severity: "error", name: "plaintext-operand-not-convertible", rule: "§3.3", summary: "A plaintext operand cannot be trivially encrypted to the required encrypted type." },
    CatalogEntry { code: "FHE2009", severity: "error", name: "condition-not-ebool", rule: "§3.3", summary: "An euintN used where an ebool condition is required; suggest FHE.ne(x, FHE.asEuintN(0))." },
    CatalogEntry { code: "FHE2010", severity: "error", name: "encrypted-op-in-view-or-pure", rule: "§3.4", summary: "An expression lowers to an FHE operation inside a view/pure function." },
    CatalogEntry { code: "FHE2011", severity: "error", name: "inc-dec-value-used", rule: "§4.2", summary: "++/-- on an encrypted value used inside a larger expression; only statement position is supported." },
    CatalogEntry { code: "FHE2012", severity: "error / warning", name: "shared-boundary-type-mismatch", rule: "§2.8", summary: "The expression a shared return returns is not the encrypted type the function declares it shares. A warning, and still rewritten, when the only obstacle is a callee behind an incomplete inheritance surface." },
    CatalogEntry { code: "FHE3001", severity: "error", name: "return-in-encrypted-branch", rule: "§7.1", summary: "`return` inside an encrypted-condition branch; assign to a local and return after the if." },
    CatalogEntry { code: "FHE3002", severity: "error", name: "break-continue-in-encrypted-branch", rule: "§7.1", summary: "`break`/`continue` inside an encrypted-condition branch." },
    CatalogEntry { code: "FHE3003", severity: "error", name: "revert-family-in-encrypted-branch", rule: "§7.1", summary: "revert/require/assert inside an encrypted-condition branch; encrypted conditions cannot revert." },
    CatalogEntry { code: "FHE3004", severity: "error", name: "external-call-in-encrypted-branch", rule: "§7.1", summary: "External call inside an encrypted-condition branch." },
    CatalogEntry { code: "FHE3005", severity: "error", name: "emit-in-encrypted-branch", rule: "§7.1", summary: "`emit` inside an encrypted-condition branch would leak the condition." },
    CatalogEntry { code: "FHE3006", severity: "error", name: "plaintext-write-in-encrypted-branch", rule: "§7.1", summary: "Write to a plaintext location inside an encrypted-condition branch would leak the condition." },
    CatalogEntry { code: "FHE3007", severity: "error", name: "plaintext-control-flow-in-encrypted-branch", rule: "§7.1", summary: "Plaintext if/loop/try inside an encrypted-condition branch (v1 restriction)." },
    CatalogEntry { code: "FHE3008", severity: "error", name: "unverified-call-in-encrypted-branch", rule: "§7.1", summary: "Call to a function not verified branch-safe inside an encrypted-condition branch." },
    CatalogEntry { code: "FHE3009", severity: "error", name: "inline-assembly-in-encrypted-branch", rule: "§7.1", summary: "Inline assembly inside an encrypted-condition branch." },
    CatalogEntry { code: "FHE3010", severity: "error", name: "delete-on-encrypted", rule: "§7.2", summary: "`delete` on an encrypted lvalue; assign FHE.asEuintN(0) explicitly if intended." },
    CatalogEntry { code: "FHE3011", severity: "error", name: "undecidable-write-aliasing", rule: "§5.2", summary: "Two indexed writes in encrypted branches whose keys may alias; hoist keys or restructure." },
    CatalogEntry { code: "FHE3012", severity: "error", name: "side-effecting-encrypted-operand", rule: "§5.5", summary: "Side effect in an operand of encrypted &&, || or ?:; both sides always evaluate." },
    CatalogEntry { code: "FHE3013", severity: "error", name: "unsupported-statement-in-encrypted-branch", rule: "§5.2", summary: "Statement form inside an encrypted if branch that the lowering rules do not enumerate (e.g. a tuple declaration)." },
    CatalogEntry { code: "FHE3014", severity: "error", name: "encrypted-input-used-in-precondition", rule: "§2.7", summary: "A dialect-managed encrypted input is named inside a `precondition` block; the block runs before the generated conversion, so the value does not exist yet." },
    CatalogEntry { code: "FHE3015", severity: "error", name: "precondition-forbidden-effect", rule: "§2.7", summary: "A `precondition` block contains a state write, an encrypted-typed expression, an emit, a return, a loop, assembly, or a call the checker cannot prove is a same-unit view/pure call." },
    CatalogEntry { code: "FHE3020", severity: "error", name: "encrypted-index", rule: "§7.2", summary: "Encrypted value used as an array or mapping index." },
    CatalogEntry { code: "FHE3021", severity: "error", name: "encrypted-loop-condition", rule: "§5.6", summary: "Loop with an encrypted condition or loop-control expression." },
    CatalogEntry { code: "FHE3022", severity: "error", name: "ebool-in-plaintext-bool-context", rule: "§7.2", summary: "ebool used where a plaintext bool is required (e.g. require)." },
    CatalogEntry { code: "FHE4001", severity: "warning", name: "non-sender-keyed-encrypted-write", rule: "§8.1", summary: "A storage write's owner is not provably msg.sender (a simple state variable, an array element, a struct field, or a mapping keyed by anything else); the sender grant is withheld rather than guessed." },
    CatalogEntry { code: "FHE4002", severity: "warning", name: "view-or-pure-without-acl", rule: "§8.4", summary: "View or pure function returns an encrypted value (R3), or a view function passes one as an argument to an external call (R2); ACL cannot be granted in view or pure context." },
    CatalogEntry { code: "FHE4003", severity: "error", name: "acl-callee-type-underivable", rule: "§8.2", summary: "R2 callee hoisting: the callee expression's declared type cannot be derived; restructure the callee into a cast or a typed variable." },
    CatalogEntry { code: "FHE4004", severity: "error", name: "acl-position-illegal", rule: "§8", summary: "An ACL grant would have to be written where no statement may go (a `for` header); move the statement above the loop." },
    CatalogEntry { code: "FHE4005", severity: "error", name: "acl-policy-invalid", rule: "§8.8", summary: "A `@custom:fhe-allow` reader policy is malformed, misplaced, or fails one of the eight restrictions (an unrecognized `@custom:fhe-` key, a policy in a `.sol` file, a target that does not resolve, a reader path that cannot be resolved by the five reader-resolution rules, `msg`/`tx`/`block`, `public` combined with other readers, or a reader naming the target itself)." },
    CatalogEntry { code: "FHE4006", severity: "error", name: "acl-policy-target-unbindable", rule: "§8.9", summary: "A reader policy targets a struct field, but the write's storage pointer cannot be proven to resolve to it: it must be assigned exactly once, from a call to a parameterless function or from a state variable, and never reassigned or conditionally bound." },
    CatalogEntry { code: "FHE4007", severity: "error / warning", name: "acl-policy-not-reapplicable", rule: "§8.11", summary: "A mapping/array policy target names mutable state in its readers or its `public if` condition; re-application has no key to bind with, so the policy is forward-only (warning). A gated `public if` on such a target can never actually publish and is refused (error)." },
    CatalogEntry { code: "FHE4008", severity: "warning", name: "acl-cross-reader-copy", rule: "§8.12", summary: "A storage write's right-hand value is a handle read from another slot with no intervening profile operation, and the two slots' policies name different readers; the copied handle carries the union of both slots' readers." },
    CatalogEntry { code: "FHE4009", severity: "warning", name: "acl-empty-reader-set", rule: "§8.12", summary: "An encrypted value reaches an `emit` or a `return` with a reader set the transpiler knows is empty (transient grants do not count); not implemented in this revision — see the reader-policies implementation notes." },
    CatalogEntry { code: "FHE4010", severity: "note", name: "suggest-allow-after-write", rule: "§8.1", summary: "--acl=suggest: a storage write would receive allowThis, and allowSender too when the slot is provably owned by msg.sender." },
    CatalogEntry { code: "FHE4011", severity: "note", name: "suggest-transient-for-argument", rule: "§8.2", summary: "--acl=suggest: an encrypted call argument would receive allowTransient here." },
    CatalogEntry { code: "FHE4012", severity: "note", name: "suggest-transient-for-return", rule: "§8.3", summary: "--acl=suggest: an encrypted return would receive allowTransient here." },
    CatalogEntry { code: "FHE4013", severity: "note", name: "suggest-policy-grant", rule: "§8.9", summary: "--acl=suggest: a policy-governed storage write or event argument would receive its R4/R5 grant sequence here." },
    CatalogEntry { code: "FHE5001", severity: "error", name: "op-not-in-profile-version", rule: "§1.5", summary: "The lowering needs an operation the pinned target profile version does not provide." },
    CatalogEntry { code: "FHE5002", severity: "error", name: "unknown-target-profile", rule: "§1.5", summary: "The configured target profile is not known to this fhec build." },
    CatalogEntry { code: "FHE5003", severity: "error", name: "installed-library-version-mismatch", rule: "§1.5", summary: "The installed FHE library version does not satisfy the pinned profile version." },
    CatalogEntry { code: "FHE6000", severity: "forwarded", name: "solc-diagnostic", rule: "§9", summary: "A diagnostic forwarded from solc, remapped to the original .fsol span." },
    CatalogEntry { code: "FHE9001", severity: "error", name: "internal-invariant-violation", rule: "§9", summary: "An internal invariant of the transpiler failed; please report this as a bug." },
    CatalogEntry { code: "FHE9002", severity: "error", name: "output-reparse-failed", rule: "§2.5", summary: "The complete output failed to re-parse as valid Solidity; refusing to write it." },
    CatalogEntry { code: "FHE9003", severity: "error", name: "fragment-reparse-failed", rule: "§2.5", summary: "A rendered fragment failed to re-parse; refusing to splice it." },
];

/// Looks up a code (case-sensitive, e.g. "FHE2007").
pub fn lookup(code: &str) -> Option<&'static CatalogEntry> {
    CATALOG.iter().find(|e| e.code == code)
}

/// Renders the `explain` output for one entry.
pub fn render(entry: &CatalogEntry) -> String {
    format!(
        "{} — {} ({})\n\n{}\n\nSpec: {}\nDocs: https://fhec.dev/errors/{}\n",
        entry.code, entry.name, entry.severity, entry.summary, entry.rule, entry.code
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_resolve() {
        assert!(lookup("FHE2007").is_some());
        assert!(lookup("FHE9003").is_some());
        assert!(lookup("FHE0000").is_none());
    }

    #[test]
    fn catalog_codes_unique_and_wellformed() {
        let mut seen = std::collections::HashSet::new();
        for e in CATALOG {
            assert!(e.code.starts_with("FHE") && e.code.len() == 7, "{}", e.code);
            assert!(seen.insert(e.code), "duplicate {}", e.code);
        }
    }
}
