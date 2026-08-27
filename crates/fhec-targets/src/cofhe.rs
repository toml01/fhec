//! The CoFHE target profile, verified against
//! `@fhenixprotocol/cofhe-contracts` (`FHE.sol` / `ICofhe.sol`) at the
//! pinned revision.

use fhec_ir::{EType, FheOp};

use crate::profile::{Capabilities, ProfileError, TargetProfile};

/// Which encrypted type kinds an operation accepts (all operands the same
/// type after the checker's widening, spec §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applicability {
    /// `euintN` only (arithmetic, shifts, ordering comparisons, min/max).
    Euint,
    /// `euintN` or `ebool` (bitwise/logical ops, `not`).
    EuintOrEbool,
    /// `euintN`, `ebool`, or `eaddress` (`eq`/`ne`).
    AnyEncrypted,
}

/// The encrypted result of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultKind {
    /// Same type as the value operands.
    Same,
    /// Always `ebool` (comparisons).
    Ebool,
    /// No encrypted result (ACL operations).
    Void,
}

/// One row of the signature table: operation, library spelling, accepted
/// operand kinds, result.
struct OpEntry {
    op: FheOp,
    name: &'static str,
    applicability: Applicability,
    result: ResultKind,
}

const fn entry(
    op: FheOp,
    name: &'static str,
    applicability: Applicability,
    result: ResultKind,
) -> OpEntry {
    OpEntry {
        op,
        name,
        applicability,
        result,
    }
}

/// Signature table for cofhe-contracts 0.2.x, transcribed from `FHE.sol`:
/// every payload-free [`FheOp`] with its spelling and shape. Cast and
/// input-conversion operations are name-formula-driven (`asEuintN`…) and are
/// handled structurally in [`CofheProfile`].
const COFHE_0_2_OPS: &[OpEntry] = &[
    entry(FheOp::Add, "add", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Sub, "sub", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Mul, "mul", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Div, "div", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Rem, "rem", Applicability::Euint, ResultKind::Same),
    entry(
        FheOp::And,
        "and",
        Applicability::EuintOrEbool,
        ResultKind::Same,
    ),
    entry(
        FheOp::Or,
        "or",
        Applicability::EuintOrEbool,
        ResultKind::Same,
    ),
    entry(
        FheOp::Xor,
        "xor",
        Applicability::EuintOrEbool,
        ResultKind::Same,
    ),
    entry(FheOp::Shl, "shl", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Shr, "shr", Applicability::Euint, ResultKind::Same),
    entry(
        FheOp::Not,
        "not",
        Applicability::EuintOrEbool,
        ResultKind::Same,
    ),
    entry(
        FheOp::Eq,
        "eq",
        Applicability::AnyEncrypted,
        ResultKind::Ebool,
    ),
    entry(
        FheOp::Ne,
        "ne",
        Applicability::AnyEncrypted,
        ResultKind::Ebool,
    ),
    entry(FheOp::Lt, "lt", Applicability::Euint, ResultKind::Ebool),
    entry(FheOp::Lte, "lte", Applicability::Euint, ResultKind::Ebool),
    entry(FheOp::Gt, "gt", Applicability::Euint, ResultKind::Ebool),
    entry(FheOp::Gte, "gte", Applicability::Euint, ResultKind::Ebool),
    entry(FheOp::Min, "min", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Max, "max", Applicability::Euint, ResultKind::Same),
    entry(
        FheOp::Square,
        "square",
        Applicability::Euint,
        ResultKind::Same,
    ),
    entry(FheOp::Rol, "rol", Applicability::Euint, ResultKind::Same),
    entry(FheOp::Ror, "ror", Applicability::Euint, ResultKind::Same),
    entry(
        FheOp::Select,
        "select",
        Applicability::AnyEncrypted,
        ResultKind::Same,
    ),
    entry(
        FheOp::AllowThis,
        "allowThis",
        Applicability::AnyEncrypted,
        ResultKind::Void,
    ),
    entry(
        FheOp::AllowSender,
        "allowSender",
        Applicability::AnyEncrypted,
        ResultKind::Void,
    ),
    entry(
        FheOp::AllowTransient,
        "allowTransient",
        Applicability::AnyEncrypted,
        ResultKind::Void,
    ),
    entry(
        FheOp::AllowGlobal,
        "allowGlobal",
        Applicability::AnyEncrypted,
        ResultKind::Void,
    ),
];

/// The CoFHE target profile.
///
/// Holds its signature table as data so a future `cofhe@HEAD` variant is a
/// data delta (different table / different version string), not a new
/// implementation.
pub struct CofheProfile {
    version: &'static str,
    lib: &'static str,
    pragma_range: &'static str,
    import_lines: &'static [&'static str],
    ops: &'static [OpEntry],
    /// Encrypted types this version gives a shared boundary (spec §2.8):
    /// a `sharedT` wire type, `shareT`, and `receiveTParam`. Data, not a
    /// hard-coded "always", so a future profile version is a table delta.
    shared_boundary: &'static [EType],
}

impl CofheProfile {
    /// The profile for cofhe-contracts 0.2.x (the pinned published release).
    pub fn v0_2() -> Self {
        CofheProfile {
            version: "0.2.x",
            lib: "FHE",
            pragma_range: ">=0.8.25 <0.9.0",
            import_lines: &["import \"@fhenixprotocol/cofhe-contracts/FHE.sol\";"],
            ops: COFHE_0_2_OPS,
            // FHE.sol 0.2.x declares `type sharedT is bytes32` plus
            // `shareT(T, address)` and `receiveTParam(sharedT)` for every one
            // of the seven profile types.
            shared_boundary: &EType::ALL,
        }
    }

    fn lookup(&self, op: FheOp) -> Option<&OpEntry> {
        self.ops.iter().find(|e| e.op == op)
    }

    /// The one capability predicate behind all three shared-boundary methods.
    fn shared_ok(&self, ty: EType) -> Result<(), ProfileError> {
        if self.shared_boundary.contains(&ty) {
            Ok(())
        } else {
            Err(ProfileError::NoSharedBoundary { ty })
        }
    }

    /// `euint32` → `asEuint32`, `ebool` → `asEbool`, etc.
    fn cast_fn_name(ty: EType) -> String {
        format!("as{}", ty.suffix())
    }

    /// `euint32` → `Utils.EUINT32_TFHE`, the utype constant of ICofhe.sol.
    fn utype_const(ty: EType) -> String {
        format!("Utils.{}_TFHE", ty.suffix().to_uppercase())
    }

    fn unsupported(op: FheOp, operands: &[EType]) -> ProfileError {
        ProfileError::Unsupported {
            op,
            operands: operands.to_vec(),
        }
    }

    /// The number of *encrypted* operands the op is typed over (differs from
    /// [`FheOp::arity`] for ops with plaintext arguments).
    fn encrypted_operand_count(op: FheOp) -> usize {
        match op {
            FheOp::TrivialEncrypt { .. } | FheOp::FromExternal { .. } => 0,
            FheOp::AllowTransient => 1,
            _ => op.arity(),
        }
    }

    fn accepts(applicability: Applicability, ty: EType) -> bool {
        match applicability {
            Applicability::Euint => ty.is_euint(),
            Applicability::EuintOrEbool => ty.is_euint() || ty == EType::Ebool,
            Applicability::AnyEncrypted => true,
        }
    }
}

impl TargetProfile for CofheProfile {
    fn id(&self) -> &str {
        "cofhe"
    }

    fn version(&self) -> &str {
        self.version
    }

    fn pragma_range(&self) -> &str {
        self.pragma_range
    }

    fn import_lines(&self) -> Vec<String> {
        self.import_lines.iter().map(|s| s.to_string()).collect()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities { has_decrypt: false }
    }

    fn result_type(&self, op: FheOp, operands: &[EType]) -> Result<Option<EType>, ProfileError> {
        let expected = Self::encrypted_operand_count(op);
        if operands.len() != expected {
            return Err(ProfileError::WrongArity {
                op,
                expected,
                got: operands.len(),
            });
        }

        match op {
            FheOp::TrivialEncrypt { to } => Ok(Some(to)),
            FheOp::FromExternal { ty } => Ok(Some(ty)),
            FheOp::Widen { from, to } => {
                // Widening exists only strictly narrow-to-wide (spec §3.3);
                // the operand must match the declared source width.
                if from >= to || operands[0] != EType::Euint(from) {
                    return Err(Self::unsupported(op, operands));
                }
                Ok(Some(EType::Euint(to)))
            }
            _ => {
                let Some(entry) = self.lookup(op) else {
                    return Err(Self::unsupported(op, operands));
                };
                // Value operands: everything except select's leading ebool
                // condition. All value operands must be the same type.
                let value_operands = match op {
                    FheOp::Select => {
                        if operands[0] != EType::Ebool {
                            return Err(Self::unsupported(op, operands));
                        }
                        &operands[1..]
                    }
                    _ => operands,
                };
                let first = value_operands[0];
                if !Self::accepts(entry.applicability, first)
                    || value_operands.iter().any(|t| *t != first)
                {
                    return Err(Self::unsupported(op, operands));
                }
                Ok(match entry.result {
                    ResultKind::Same => Some(first),
                    ResultKind::Ebool => Some(EType::Ebool),
                    ResultKind::Void => None,
                })
            }
        }
    }

    fn render_call(
        &self,
        op: FheOp,
        operands: &[EType],
        args: &[&str],
    ) -> Result<String, ProfileError> {
        if args.len() != op.arity() {
            return Err(ProfileError::WrongArity {
                op,
                expected: op.arity(),
                got: args.len(),
            });
        }
        self.result_type(op, operands)?;

        let callee = match op {
            FheOp::TrivialEncrypt { to } => self.conversion_fn(to),
            FheOp::FromExternal { ty } => self.conversion_fn(ty),
            FheOp::Widen { to, .. } => self.conversion_fn(EType::Euint(to)),
            _ => {
                // result_type above guarantees the entry exists.
                let entry = self.lookup(op).expect("validated by result_type");
                format!("{}.{}", self.lib, entry.name)
            }
        };
        Ok(format!("{}({})", callee, args.join(", ")))
    }

    fn can_cast(&self, from: EType, to: EType) -> bool {
        // Transcribed from FHE.sol's cast matrix: every pair has an
        // `asX(fromType)` overload except casts *to* eaddress and
        // self-casts (which do not exist — none are needed).
        if from == to {
            return false;
        }
        !matches!(to, EType::Eaddress)
    }

    fn acl_fn_name(&self, op: FheOp) -> Option<String> {
        if !op.is_acl() {
            return None;
        }
        self.lookup(op).map(|e| e.name.to_string())
    }

    fn external_input_type(&self, ty: EType) -> String {
        ty.external_name().to_string()
    }

    fn input_proof_param(&self) -> String {
        "bytes memory inputProof".to_string()
    }

    fn shared_wire_type(&self, ty: EType) -> Result<String, ProfileError> {
        self.shared_ok(ty)?;
        Ok(ty.shared_name().to_string())
    }

    fn render_share(
        &self,
        ty: EType,
        handle: &str,
        recipient: &str,
    ) -> Result<String, ProfileError> {
        self.shared_ok(ty)?;
        // FHE.sol: `share{Suffix}(eT ctHash, address receiver)`.
        Ok(format!(
            "{}.share{}({handle}, {recipient})",
            self.lib,
            ty.suffix()
        ))
    }

    fn render_receive_param(&self, ty: EType, wire: &str) -> Result<String, ProfileError> {
        self.shared_ok(ty)?;
        // FHE.sol: `receive{Suffix}Param(shared{Suffix} shared)`.
        Ok(format!(
            "{}.receive{}Param({wire})",
            self.lib,
            ty.suffix()
        ))
    }

    fn conversion_fn(&self, ty: EType) -> String {
        format!("{}.{}", self.lib, Self::cast_fn_name(ty))
    }

    fn batch_input_statements(
        &self,
        params: &[(EType, &str, &str)],
        proof: &str,
        inputs_tmp: &str,
        hashes_tmp: &str,
    ) -> Vec<String> {
        // One signature covers the whole batch (cofhe-contracts#78): build
        // the UnsignedEncryptedInput array in parameter order, verify once,
        // wrap each returned handle. Security zone 0 matches FHE.sol's own
        // batch helpers (asEuint32s…). The mixed-type verification entry
        // point lives in FHE.sol's `library Impl` (the FHE library only has
        // per-type array helpers, which cannot express a mixed batch).
        let mut stmts = Vec::with_capacity(params.len() * 2 + 2);
        stmts.push(format!(
            "UnsignedEncryptedInput[] memory {inputs_tmp} = new UnsignedEncryptedInput[]({});",
            params.len()
        ));
        for (i, (ty, input_name, _)) in params.iter().enumerate() {
            stmts.push(format!(
                "{inputs_tmp}[{i}] = UnsignedEncryptedInput(uint256({}.unwrap({input_name})), 0, {});",
                ty.external_name(),
                Self::utype_const(*ty)
            ));
        }
        stmts.push(format!(
            "bytes32[] memory {hashes_tmp} = Impl.verifyBatchInputs({inputs_tmp}, {proof});"
        ));
        for (i, (ty, _, value_name)) in params.iter().enumerate() {
            stmts.push(format!(
                "{} {value_name} = {}.wrap({hashes_tmp}[{i}]);",
                ty.solidity_name(),
                ty.solidity_name()
            ));
        }
        stmts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhec_ir::EWidth;

    #[test]
    fn cast_fn_names() {
        assert_eq!(CofheProfile::cast_fn_name(EType::Ebool), "asEbool");
        assert_eq!(
            CofheProfile::cast_fn_name(EType::Euint(EWidth::W128)),
            "asEuint128"
        );
        assert_eq!(CofheProfile::cast_fn_name(EType::Eaddress), "asEaddress");
    }

    /// Transcribed from FHE.sol 0.2.x lines 25–31 and 3457–3690: every profile
    /// type has a wire type, a `share`, and a `receive…Param`, all spelled
    /// from the same suffix.
    #[test]
    fn shared_boundary_spellings() {
        let p = CofheProfile::v0_2();
        assert_eq!(
            p.shared_wire_type(EType::Euint(EWidth::W64)).unwrap(),
            "sharedEuint64"
        );
        assert_eq!(
            p.render_share(EType::Euint(EWidth::W64), "x", "msg.sender")
                .unwrap(),
            "FHE.shareEuint64(x, msg.sender)"
        );
        assert_eq!(
            p.render_receive_param(EType::Euint(EWidth::W64), "x_shared")
                .unwrap(),
            "FHE.receiveEuint64Param(x_shared)"
        );
        assert_eq!(p.shared_wire_type(EType::Ebool).unwrap(), "sharedEbool");
        assert_eq!(
            p.shared_wire_type(EType::Eaddress).unwrap(),
            "sharedEaddress"
        );
        for t in EType::ALL {
            assert!(p.shared_wire_type(t).is_ok(), "{t} has no shared boundary");
            assert!(p.render_share(t, "h", "r").is_ok());
            assert!(p.render_receive_param(t, "w").is_ok());
        }
    }

    /// A profile version without a boundary for a type reports the gap that
    /// the checker turns into FHE5001, rather than rendering a call that does
    /// not exist.
    #[test]
    fn missing_shared_boundary_is_a_profile_gap() {
        let mut p = CofheProfile::v0_2();
        p.shared_boundary = &[EType::Ebool];
        let gone = EType::Euint(EWidth::W64);
        assert_eq!(
            p.shared_wire_type(gone),
            Err(ProfileError::NoSharedBoundary { ty: gone })
        );
        assert!(p.render_share(gone, "h", "r").is_err());
        assert!(p.render_receive_param(gone, "w").is_err());
        assert!(p.shared_wire_type(EType::Ebool).is_ok());
    }

    #[test]
    fn signature_table_covers_every_payload_free_op_once() {
        for e in COFHE_0_2_OPS {
            assert_eq!(
                COFHE_0_2_OPS.iter().filter(|o| o.op == e.op).count(),
                1,
                "duplicate table row for {}",
                e.op
            );
        }
    }
}
