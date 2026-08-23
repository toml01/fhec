# The `.fsol` Dialect Specification

| | |
|---|---|
| **Version** | 0.2.0 |
| **Status** | Draft |
| **Date** | 2026-08-22 |
| **Applies to** | `fhec` transpiler, target profile family `cofhe` |

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals, as shown here.

Items marked **⚠ Draft decision** are choices this draft pins down that PLAN-level design left open. Reviewers should treat each one as an explicit question.

---

## §1 Scope and conformance

### §1.1 What this document specifies

This document specifies the `.fsol` source dialect — a superset of Solidity — and the observable behavior of a conforming transpiler `T` that maps `.fsol` sources to plain Solidity that calls a Fully Homomorphic Encryption (FHE) contract library. The normative reference target is the CoFHE library (`@fhenixprotocol/cofhe-contracts`); lowered operation names are given in CoFHE spelling. A conforming implementation MAY support other targets through *target profiles* (§1.5); all rules in this document except concrete API spellings are target-independent.

### §1.2 Conforming transpiler

A *conforming transpiler* is a program that, for every input compilation unit:

1. Accepts the input if and only if it conforms to this specification, and
2. Produces output whose behavior matches the semantics defined here, and
3. Rejects — with a diagnostic from the catalog in §9 — every input for which it cannot establish both of the above.

### §1.3 The prime directive: never miscompile

When the transpiler cannot determine with certainty that a rewrite is semantics-preserving, it MUST emit an error and refuse to produce output for the affected contract. It MUST NOT guess, and it MUST NOT fall back to "best effort" output.

*Rationale (informative):* the CoFHE `FHE.select` operation substitutes default values (`asEbool(false)`, `asEuintN(0)`) for uninitialized ciphertext handles instead of reverting. A miscompilation therefore tends to produce *wrong ciphertexts*, not reverts; the error is silent and may be irreversible. Refusal is always safer than guessing.

### §1.4 The no-op guarantee

Let `T` be the transpile function on file contents.

1. **No-op:** For any input file that is valid plain Solidity making direct FHE library calls (i.e. contains no dialect constructs requiring lowering and triggers no ACL insertion), the output MUST be byte-identical to the input, except for import-specifier rewriting per §2.6.
2. **Idempotence:** For every accepted input `x`, `T(T(x))` MUST equal `T(x)` byte-exactly.

These are conformance-testable properties (§10.4). When a tool verifies idempotence by re-running the pipeline on its own output (a self-check), diagnostics from the re-run below `error` severity MUST be suppressed: warnings and notes were already reported for the first run, and the re-run exists only to prove byte identity.

### §1.5 Target profiles

A *target profile* supplies: the encrypted type list, the operation name table, the call style, the cast matrix, ACL primitive mapping, required imports, and a capability set. Profiles are versioned per library release. The transpiler MUST NOT emit an operation absent from the pinned profile version; violations are FHE5001 errors. This document's tables describe profile `cofhe` at the pinned revision current at the time of writing.

The CoFHE encrypted value types are:

```
ebool  euint8  euint16  euint32  euint64  euint128  eaddress
```

There is no `euint256`. The *external input* handle types are `externalEbool`, `externalEuint8`, `externalEuint16`, `externalEuint32`, `externalEuint64`, `externalEuint128`, `externalEaddress` — `bytes32` user-defined value types carrying an unverified input ciphertext hash. Since cofhe-contracts 0.2.0 an encrypted input arrives as such a handle plus a `bytes` proof; one signature authenticates a whole batch of inputs (`UnsignedEncryptedInput { uint256 ctHash; uint8 securityZone; uint8 utype; }` is the per-entry verification record). The former `InEuintX` input structs no longer exist.

### §1.6 Running example (informative)

Dialect input (fragment):

```solidity
// EncryptedCounter.fsol
contract EncryptedCounter {
    euint32 public count;

    function setCount(in euint32 newCount) external onlyOwner {
        count = newCount;
    }

    function incrementCount() external onlyOwner {
        count = count + 1;
    }
}
```

Conforming output (fragment):

```solidity
// generated/EncryptedCounter.sol
contract EncryptedCounter {
    euint32 public count;

    function setCount(externalEuint32 newCount_input, bytes memory inputProof) external onlyOwner {
        euint32 newCount = FHE.asEuint32(newCount_input, inputProof);
        count = newCount;
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    function incrementCount() external onlyOwner {
        count = FHE.add(count, FHE.asEuint32(1));
        FHE.allowThis(count);
        FHE.allowSender(count);
    }
}
```

---

## §2 Source language and grammar delta

### §2.1 Files and pragma

1. Dialect source files use the extension `.fsol`. Plain `.sol` files in the same project MUST pass through unmodified except §2.6.
2. A `.fsol` file MUST carry a `pragma solidity` constraint whose satisfiable range lies within `>=0.8.25 <0.9.0`. Constraints outside this range are FHE1001 errors, enforced by the load stage; a pragma the load stage cannot parse defers to solc rather than erroring. (The CoFHE interface file itself requires `>=0.8.25`; CoFHE deployments require the `cancun` EVM target.)
3. Except for the extension in §2.3, the grammar of `.fsol` is exactly the grammar of Solidity in the supported pragma range. Every valid Solidity file in that range is a valid `.fsol` file.

### §2.2 Parse errors

Input that does not parse under the dialect grammar is rejected with FHE1002. Unresolvable imports are FHE1003.

### §2.3 The `in` parameter sugar (the single v1 grammar extension)

Grammar: in a function or constructor parameter list, the production

```
parameter := 'in' encrypted-type identifier
```

is added, where `encrypted-type` is one of the profile's encrypted value types (§1.5). `in` is a reserved Solidity keyword, so this production conflicts with no valid Solidity program.

**Expansion.** For a function or constructor with k ≥ 1 sugared parameters (`eT` maps to external handle type `externalT` and conversion function `asT` per the profile — e.g. `euint32` → `externalEuint32` / `FHE.asEuint32`):

1. Each parameter `in eT name` becomes the declaration `externalT name_input` in the same position (external handle types are value types; no data location).
2. One shared parameter `bytes memory inputProof` is appended at the end of the parameter list — once per function, regardless of k. This matches the SDK convention (cofhe SDK 0.7.0): a function with encrypted inputs ends with one plain `bytes` parameter receiving the shared batch signature.
3. Conversion statements are inserted at the start of the function body, before any existing statement, in parameter-list order:
   - k = 1: `eT name = FHE.asT(name_input, inputProof);`
   - k > 1: a single batch verification. One signature covers the whole batch (cofhe-contracts#78), so per-parameter `FHE.asT(hash, proof)` calls — which each rebuild a one-element batch digest — would fail verification. The expansion builds one `UnsignedEncryptedInput[]` in parameter order (security zone 0, matching FHE.sol's own batch helpers), verifies it once through `Impl.verifyBatchInputs(inputs, inputProof)`, and wraps each returned `bytes32` handle into its value type:

     ```solidity
     UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](k);
     __fhe_inputs_0[i] = UnsignedEncryptedInput(uint256(externalT.unwrap(name_input)), 0, Utils.T_TFHE); // per parameter
     bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, inputProof);
     eT name = eT.wrap(__fhe_hashes_1[i]); // per parameter
     ```

     The array temporaries are named per §2.4 (hints `inputs`, `hashes`).

**⚠ Draft decision (data location):** the appended proof parameter uses `memory`. `calldata` is not used in v1.

**⚠ Draft decision (generated names):** the raw-input parameter is named `<name>_input`, and the shared proof parameter is named `inputProof`. If `<name>_input` or `inputProof` is already declared anywhere in the function's scope (parameters, locals, contract members referenced unqualified), the transpiler MUST reject with FHE1011 rather than rename silently.

**Restrictions.**

1. The sugar is permitted only in `function` and `constructor` parameter lists. Occurrence in return-parameter lists, modifier parameter lists, variable declarations, or event/error parameter lists is FHE1012.
2. `in` followed by a non-encrypted type is FHE1010.
3. On a declaration without a body (interface member, abstract function signature, or an overridden virtual signature), only the signature rewrites (1) and (2) apply; no conversion statement is generated. An implementing body in a `.fsol` file MUST spell its own parameters (the sugar does not propagate through inheritance).

### §2.4 Generated temporaries

**⚠ Draft decision (naming scheme):** generated temporaries are named

```
__fhe_<hint>_<n>
```

where `<hint>` ∈ {`cond`, `pre`, `then`, `else`, `key`, `val`, `ret`, `callee`} describes the temp's role and `<n>` is a per-function counter starting at 0, incremented per generated temp, assigned in generation order. Naming MUST be deterministic: identical input produces identical names. If a candidate name collides with any identifier visible in the enclosing function, the transpiler MUST skip to the next unused `<n>`. If no non-colliding name exists (pathological input), FHE9001.

### §2.5 Comments, formatting, and patch discipline

The output is the input byte sequence, altered only inside patch spans produced by lowering (§4, §5) and insertion points produced by ACL rules (§8). Comments and formatting outside patch spans MUST be preserved byte-exactly. Every rendered fragment MUST be re-parsed before splicing (failure: FHE9003); the complete output MUST re-parse as valid Solidity (failure: FHE9002).

### §2.6 Import rewriting

An import specifier that ends in `.fsol` MUST be rewritten to end in `.sol` in the output. No other import rewriting is performed. This is the only permitted byte difference in otherwise-untouched files.

---

## §3 Encryptedness typing

### §3.1 The positive fragment

The transpiler does not re-implement Solidity's type system. It assigns precise types only to the *positive fragment*:

- declared variables, parameters, and return values with explicit type annotations;
- state variables, including mappings, arrays, and struct fields, by declaration;
- calls to the FHE library whose signatures come from the pinned target profile;
- method-syntax bindings on encrypted types (`a.add(b)` via the profile's `using ... for` binding libraries);
- literals (address, boolean, number);
- operator applications over already-typed operands.

Every other expression types as **Unknown**. `Unknown` is a first-class, safe result — it means "the transpiler does not know", never "assume plaintext".

### §3.2 Interaction table

For a binary operator with operand encryptedness classes:

| left \ right | encrypted | plaintext | literal | Unknown |
|---|---|---|---|---|
| **encrypted** | lower (§4) | coerce right (§3.3), lower | coerce right (§3.3), lower | **error FHE2001** |
| **plaintext** | coerce left, lower | no patch (solc checks) | no patch | no patch |
| **literal** | coerce left, lower | no patch | no patch | no patch |
| **Unknown** | **error FHE2001** | no patch | no patch | no patch |

"No patch" means the expression is left byte-identical; solc remains the authority for plain Solidity. An implementation MUST enforce, structurally, that lowering functions accept only precise types — `Unknown` MUST NOT be able to reach the emitter.

### §3.3 Coercions

1. **Trivial encrypt.** A plaintext operand combined with an encrypted operand MUST be wrapped in the profile's trivial-encrypt conversion (`FHE.asEuintN(x)`, `FHE.asEbool(b)`, `FHE.asEaddress(a)`) when Solidity would implicitly convert the plaintext type to the encrypted type's plaintext analogue. Otherwise FHE2008.
2. **Literals.** A number literal MUST be range-checked against the target encrypted width; out-of-range literals are FHE2003. Negative number literals never coerce to `euintN` (FHE2003).
3. **Widening.** When encrypted operands have different widths in the chain `euint8 → euint16 → euint32 → euint64 → euint128`, the narrower operand MUST be widened with the profile cast (`FHE.asEuintN`). Narrowing MUST never be inserted implicitly; a context that would require it is FHE2004.
4. **No cross-kind conversion.** There is no implicit conversion between `ebool` and `euintN`, between `eaddress` and any other encrypted type, or between encrypted and plaintext results. **⚠ Draft decision:** `if (x)` with `x : euintN` is FHE2009 with a fix-it suggesting `FHE.ne(x, FHE.asEuintN(0))` — not auto-inserted.
5. **Unary minus.** `-x` on encrypted `x` is FHE2005; the fix-it suggests `FHE.sub(FHE.asEuintN(0), x)`.

### §3.4 Encrypted operations in `view`/`pure` contexts

All profile FHE operations perform external calls and are not `pure`/`view`. **⚠ Draft decision:** a transpiler SHOULD reject an expression that lowers to an FHE operation inside a `view` or `pure` function with FHE2010, rather than deferring to a less legible solc error. Reading/returning an existing handle in a `view` function is legal (see §8.4 for the ACL caveat).

---

## §4 Operator lowering

### §4.1 Operator table

For operands of encrypted type after coercion (§3.3), operators lower as follows. `euintN` means both operands the same width post-widening. Result column gives the encrypted result type.

| Operator | Operand types | Result | Lowered form | Notes |
|---|---|---|---|---|
| `+` | euintN × euintN | euintN | `FHE.add(a, b)` | wrapping semantics per backend |
| `-` | euintN × euintN | euintN | `FHE.sub(a, b)` | wrapping; no revert on underflow |
| `*` | euintN × euintN | euintN | `FHE.mul(a, b)` | |
| `/` | euintN × euintN | euintN | `FHE.div(a, b)` | encrypted divisor IS supported by CoFHE; div-by-zero semantics defined by the backend, not by this spec |
| `%` | euintN × euintN | euintN | `FHE.rem(a, b)` | same caveat as `/` |
| `&` | euintN × euintN | euintN | `FHE.and(a, b)` | |
| `\|` | euintN × euintN | euintN | `FHE.or(a, b)` | |
| `^` | euintN × euintN | euintN | `FHE.xor(a, b)` | |
| `~` | euintN | euintN | `FHE.not(a)` | |
| `<<` | euintN × euintN | euintN | `FHE.shl(a, b)` | shift amount typing: §4.3 |
| `>>` | euintN × euintN | euintN | `FHE.shr(a, b)` | shift amount typing: §4.3 |
| `<` | euintN × euintN | ebool | `FHE.lt(a, b)` | |
| `<=` | euintN × euintN | ebool | `FHE.lte(a, b)` | |
| `>` | euintN × euintN | ebool | `FHE.gt(a, b)` | |
| `>=` | euintN × euintN | ebool | `FHE.gte(a, b)` | |
| `==` | euintN × euintN, ebool × ebool, eaddress × eaddress | ebool | `FHE.eq(a, b)` | |
| `!=` | same as `==` | ebool | `FHE.ne(a, b)` | |
| `&&` | ebool × ebool | ebool | `FHE.and(a, b)` | NO short-circuit; §5.5 |
| `\|\|` | ebool × ebool | ebool | `FHE.or(a, b)` | NO short-circuit; §5.5 |
| `!` | ebool | ebool | `FHE.not(a)` | |
| `?:` | cond ebool; arms euintN/ebool/eaddress | arm type | `FHE.select(c, a, b)` | arms widened to common type; §5.4 |
| `**` | any encrypted | — | **FHE2006** | no profile op; `x.square()` exists as a method for `x**2` but is not auto-applied |
| `-` (unary) | any encrypted | — | **FHE2005** | fix-it per §3.5 |

`eaddress` supports only `==`, `!=`, and `?:` arms. `ebool` supports `&&`, `||`, `!`, `==`, `!=`, `&`, `|`, `^` (the last three lower to `FHE.and/or/xor` on ebool) and `?:` in all three positions. Any operator/type pair not in this table applied to an encrypted operand is FHE2006.

Profile methods with no operator (`min`, `max`, `square`, `rol`, `ror`, `isInitialized`, casts, ACL methods) pass through as ordinary calls and are typed by the checker via the profile signature table.

### §4.2 Compound assignment and increment

**⚠ Draft decision:** compound assignments (`+=`, `-=`, `*=`, `/=`, `%=`, `&=`, `|=`, `^=`, `<<=`, `>>=`) on an encrypted left-hand side lower as `L = L <op> R` and then follow §4.1. `++x`/`x++`/`--x`/`x--` on encrypted `x` lower to `x = FHE.add/sub(x, FHE.asEuintN(1))` when used as an expression *statement*; use of their value inside a larger expression is FHE2011 (the plaintext pre/post distinction has no cheap encrypted analogue and silent divergence would violate §1.3).

### §4.3 Shift amounts

**⚠ Draft decision:** Solidity permits any unsigned shift amount type; CoFHE `shl`/`shr` require both operands the same encrypted width. A plaintext shift amount MUST be trivially encrypted to the width of the shifted operand. An encrypted shift amount narrower than the shifted operand MUST be widened; wider is FHE2004.

### §4.4 Evaluation order

Lowered operands MUST be evaluated in the same order as Solidity would evaluate the original expression. Where lowering requires hoisting (e.g. §5), hoisted temporaries MUST preserve original left-to-right evaluation order.

---

## §5 Control-flow semantics

### §5.1 `if`/`else` on an encrypted condition

An `if` statement whose condition has type `ebool` MUST be lowered to straight-line code using `FHE.select`. An `if` whose condition types as plaintext `bool` or `Unknown` is left untouched (plaintext control flow; solc checks it).

**Both branches always execute.** In the lowered program, the statements of the then-branch AND the else-branch are all executed on every path. This is normative and observable: gas is consumed for both branches; any lowered FHE operation in either branch runs. *Security note (informative):* this is what removes the secret-dependent control flow — branch choice cannot be observed. *Gas note (informative):* cost is the SUM of both branches plus the merge selects.*

### §5.2 The branch-versioning algorithm (SSA-lite)

Naive per-assignment select-rewriting is unsound: because both branches execute, the else-branch must read values as they were BEFORE the if. A conforming transpiler MUST implement semantics equivalent to:

1. **Legality.** Check both branches against §7. Any violation rejects the whole statement.
2. **Condition hoisting.** Evaluate the condition exactly once into a fresh temp: `ebool __fhe_cond_n = <cond>;`.
3. **Write set.** Compute the set of locations written in either branch: local variables, state variables, mapping/array slots, struct fields. For indexed locations, hoist each plaintext index key into a temp before the branches (`__fhe_key_n`). Two indexed writes denote the same location if and only if their keys are the same hoisted temp, or are distinct literals (then they are different locations). If the transpiler cannot decide aliasing (two syntactically different non-literal keys), it MUST reject with FHE3011.
4. **Pre-values.** For every location `L` in the write set, read a pre-value temp before the branches: `__fhe_pre_n = L;`.
5. **Branch environments.** Walk the then-branch and the else-branch with *separate* environments, each seeded from the pre-value temps. Each assignment in a branch produces a fresh temp holding the assigned value; subsequent reads in the SAME branch see that temp; reads in the OTHER branch see the pre-value.
6. **Merge.** After both branch bodies, for every location `L`:
   `L = FHE.select(__fhe_cond_n, <thenVal or pre>, <elseVal or pre>);`
   where `thenVal`/`elseVal` are the final temps of `L` in each branch environment, defaulting to the pre-value temp when a branch did not write `L`.

Merge writes MUST be emitted in a deterministic order (**⚠ Draft decision:** order of first write occurrence in source).

Variables **declared inside a branch** are branch-local: they are not part of the write set, need no pre-value, and are not merged; the transpiler MUST keep them scoped to the rendered branch body (e.g. by emitting each branch body in its own sub-block). Statement forms inside encrypted branches that this specification does not enumerate (e.g. tuple declarations) MUST be rejected with FHE3013 rather than lowered by guesswork.

### §5.3 Nesting

Encrypted `if` statements nested inside encrypted branches MUST be lowered innermost-first. Conjunction of conditions composes automatically through the merges (the inner select's result feeds the outer merge); the transpiler MUST NOT synthesize explicit condition conjunctions.

### §5.4 Ternary `?:`

A conditional expression whose condition is `ebool` lowers to `FHE.select(cond, a, b)` with arms coerced to a common encrypted type per §3.3. Operand side effects follow §5.5. A conditional expression with a *plaintext* condition is NOT lowered, even when its arms are encrypted (plain Solidity handles it).

### §5.5 No short-circuit

`&&`, `||`, and `?:` over encrypted operands evaluate BOTH sides on every execution. There is no short-circuit. Consequently:

1. An operand containing a side effect (assignment, function call not known side-effect-free, `++`/`--`, `delete`, external call) MUST be rejected with FHE3012.
2. Programs MUST NOT rely on `&&`/`||` to guard evaluation (e.g. bounds checks); the spec calls this out because it silently differs from plaintext Solidity intuition.

### §5.6 Loops and encrypted conditions

`while`, `do`/`while`, and `for` statements whose condition (or any loop-control expression) is encrypted are FHE3021. Encrypted values MAY be used freely inside the body of a plaintext loop.

---

## §6 Definite assignment

For every encrypted local variable, the transpiler MUST perform definite-assignment analysis. Use of a possibly-uninitialized encrypted variable as an operand of any lowered FHE operation, as a `select` arm, as a merge pre-value, in an ACL insertion, or as a return value is an error FHE2007.

*Rationale (normative for severity):* CoFHE operations, including `FHE.select`, silently substitute default ciphertexts (`asEbool(false)`, `asEuintN(0)`) for uninitialized handles. An uninitialized-handle bug therefore produces a wrong ciphertext, not a revert. Because the failure is silent, this diagnostic is an ERROR, never a warning, and MUST NOT be downgradeable by configuration.

A variable is *definitely assigned* at a use if every control-flow path from its declaration to the use assigns it. The analysis is the classical conservative one; when in doubt, reject (§1.3).

---

## §7 Legality rules (reject list)

### §7.1 Inside encrypted branches

Within the then- or else-branch of an `if` with encrypted condition (transitively, including nested plaintext blocks), each of the following constructs MUST be rejected with the listed code:

| Code | Construct | Fix-suggestion sketch |
|---|---|---|
| FHE3001 | `return` | restructure: assign to a local, return after the `if` |
| FHE3002 | `break` / `continue` | restructure loop body |
| FHE3003 | `revert` / `require` / `assert` | encrypted conditions cannot revert; use plaintext guard before the `if`, or encode failure in state |
| FHE3004 | external call (including `transfer`/`send`/low-level calls) | hoist call out of the branch |
| FHE3005 | `emit` | events are public; emitting per-branch leaks the condition |
| FHE3006 | write to a plaintext location | a plaintext write in one branch leaks the condition; write encrypted or hoist |
| FHE3007 | plaintext control flow (`if`/loop/`try` on plaintext condition) | v1 restriction; hoist or flatten |
| FHE3008 | call to a user function not verified branch-safe | v1: only profile FHE calls and same-contract functions the checker has verified against this table are permitted |
| FHE3009 | inline assembly | none |
| FHE3010 | `delete` on an encrypted value (also global, see §7.2) | assign `FHE.asEuintN(0)` explicitly if intended |

### §7.2 Global rejects (anywhere in a `.fsol` file)

| Code | Construct |
|---|---|
| FHE3010 | `delete` on an encrypted lvalue |
| FHE3011 | branch write set with undecidable aliasing (§5.2 step 3) |
| FHE3012 | side-effecting operand of encrypted `&&` / `\|\|` / `?:` (§5.5) |
| FHE3020 | encrypted value used as array or mapping index |
| FHE3021 | loop with encrypted condition or loop-control expression (§5.6) |
| FHE3022 | `ebool` used where plaintext `bool` is required (e.g. `require(eb)`, plaintext `if` reached after inference, boolean state flag) |

Every FHE3xxx diagnostic MUST carry the source span of the offending construct and SHOULD carry a fix-suggestion.

---

## §8 ACL insertion

ACL insertion is always on. With `--acl=suggest`, insertions are downgraded to fix-it diagnostics (FHE4010–FHE4012, severity `note`) and NOT applied; the rest of the transpile proceeds unchanged. These notes appear on `check` as well as `build`. The R1 suggest fix-it is the canonical `safe: true` fix-it that `--fix` auto-applies; fix-its that change semantics non-mechanically (e.g. the §3.3 unary-minus rewrite) MUST be marked `safe: false`.

### §8.1 R1 — storage writes

After each storage write whose right-hand value is encrypted (state variable, mapping slot, array element, struct field), the transpiler MUST insert:

```solidity
FHE.allowThis(<lvalue>);
FHE.allowSender(<lvalue>);
```

immediately after the write statement. When the written slot is keyed by an address-typed expression that is not `msg.sender`, the transpiler MUST additionally emit warning FHE4001 (the sender gains read access to a ciphertext filed under another address — likely confidentiality bug or intended escrow; the author must decide).

### §8.2 R2 — encrypted arguments to external calls

Before an external call taking one or more encrypted arguments, the transpiler MUST insert, per encrypted argument `a`:

```solidity
FHE.allowTransient(a, address(<callee>));
```

The second argument of `allowTransient` is an `address`; contract-typed callee expressions do not convert implicitly, so the transpiler MUST wrap the callee in an explicit `address(...)` cast.

**⚠ Draft decision (callee hoisting):** when the callee expression is not a plain identifier, `this`-derived constant, or literal, it MUST be hoisted to a temp `__fhe_callee_n` **of the callee's declared type** and that temp used in both the `allowTransient` call (wrapped in `address(...)`) and the call itself, preserving single evaluation. When the declared type cannot be derived, the transpiler MUST refuse the file with FHE4003 rather than guess.

When the callee expression's type is `Unknown` to the checker, no R2 fact exists and no grant is inserted (conservative under-grant: the call reverts on the ACL check instead of leaking access). The transpiler SHOULD surface this as a note in a future revision.

### §8.3 R3 — encrypted returns

In a non-`view` `public`/`external` function returning an encrypted value, the return expression MUST be hoisted to a temp `__fhe_ret_n` and

```solidity
FHE.allowTransient(__fhe_ret_n, msg.sender);
```

inserted before `return __fhe_ret_n;`.

### §8.4 View functions

ACL operations cannot execute in `view` context. A `view` function returning an encrypted value gets NO insertion and warning FHE4002 (the caller must have been granted access elsewhere; the getter itself cannot grant it).

### §8.5 The never-auto-allow rule

The transpiler MUST NOT auto-insert `FHE.allow(x, <address>)` for any address other than the patterns in R1–R3 (`allowThis`, `allowSender`, `allowTransient` to callee / `msg.sender`), and MUST NOT auto-insert `allowGlobal` or `allowPublic` under any circumstances. Over-broad allowance is a recognized vulnerability class; broad grants require explicit code (or a future annotation syntax, out of scope for v1).

### §8.6 Dedupe and idempotence

An insertion is suppressed when an equivalent call is already present. **⚠ Draft decision (dedupe window):** "already present" means: a statement calling the same ACL function with an argument that is syntactically identical (after trivial parenthesis stripping) to the would-be inserted argument. For R1 the window looks **forward**: in the same block after the triggering statement and before the next write to the same location, the next external call, or the end of the block, whichever comes first. For R2 and R3 the window looks **backward**: in the same block before the triggering call or `return`, after the previous write to the granted value, since the grant must precede the statement it serves. Method-syntax calls (`x.allowThis()`) count as equivalent to library-syntax calls (`FHE.allowThis(x)`). An existing grant modulo the `address(...)` wrapper counts as equivalent for R2.

This rule is what makes §1.4 idempotence hold through the ACL pass: re-transpiling output inserts nothing.

### §8.7 Transient-only values

Encrypted values that never reach storage and never cross a call boundary (locals consumed within the transaction) get NO insertion.

---

## §9 Error catalog

Codes are stable: once assigned, a code's meaning MUST NOT change; retired codes MUST NOT be reused. Ranges:

| Range | Domain |
|---|---|
| FHE1xxx | load / parse / grammar |
| FHE2xxx | typing |
| FHE3xxx | legality |
| FHE4xxx | ACL |
| FHE5xxx | target / version |
| FHE6xxx | forwarded solc diagnostics |
| FHE9xxx | internal invariants |

Assigned in this version:

| Code | Severity | Name |
|---|---|---|
| FHE1001 | error | unsupported-pragma-range |
| FHE1002 | error | dialect-parse-error |
| FHE1003 | error | import-not-found |
| FHE1004 | error | config-not-found (no `fhec.toml` for a command that requires one) |
| FHE1005 | error | config-invalid (`fhec.toml` parse or validation failure) |
| FHE1006 | error | frozen-drift (`--frozen`: regeneration differs from the committed output tree) |
| FHE1010 | error | in-sugar-non-encrypted-type |
| FHE1011 | error | in-sugar-name-collision (§2.3) |
| FHE1012 | error | in-sugar-bad-position (§2.3) |
| FHE1020 | error | duplicate-definition (same name declared twice in one scope) |
| FHE2001 | error | encrypted-meets-unknown (§3.2) |
| FHE2002 | error | incompatible-encrypted-operands (e.g. eaddress + euint32) |
| FHE2003 | error | literal-out-of-range (§3.3) |
| FHE2004 | error | implicit-narrowing-required (§3.3, §4.3) |
| FHE2005 | error | unary-minus-on-encrypted (§3.3) |
| FHE2006 | error | operator-unsupported-for-encrypted-type (§4.1) |
| FHE2007 | error | possibly-uninitialized-encrypted (§6) |
| FHE2008 | error | plaintext-operand-not-convertible (§3.3) |
| FHE2009 | error | condition-not-ebool (§3.3) |
| FHE2010 | error | encrypted-op-in-view-or-pure (§3.4) |
| FHE2011 | error | inc-dec-value-used (§4.2) |
| FHE3001 | error | return-in-encrypted-branch |
| FHE3002 | error | break-continue-in-encrypted-branch |
| FHE3003 | error | revert-family-in-encrypted-branch |
| FHE3004 | error | external-call-in-encrypted-branch |
| FHE3005 | error | emit-in-encrypted-branch |
| FHE3006 | error | plaintext-write-in-encrypted-branch |
| FHE3007 | error | plaintext-control-flow-in-encrypted-branch |
| FHE3008 | error | unverified-call-in-encrypted-branch |
| FHE3009 | error | inline-assembly-in-encrypted-branch |
| FHE3010 | error | delete-on-encrypted |
| FHE3011 | error | undecidable-write-aliasing (§5.2) |
| FHE3012 | error | side-effecting-encrypted-operand (§5.5) |
| FHE3013 | error | unsupported-statement-in-encrypted-branch (§5.2) |
| FHE3020 | error | encrypted-index |
| FHE3021 | error | encrypted-loop-condition |
| FHE3022 | error | ebool-in-plaintext-bool-context |
| FHE4001 | warning | non-sender-keyed-encrypted-write (§8.1) |
| FHE4002 | warning | view-return-without-acl (§8.4) |
| FHE4003 | error | acl-callee-type-underivable (§8.2) |
| FHE4010 | note | suggest-allow-after-write (`--acl=suggest`) |
| FHE4011 | note | suggest-transient-for-argument (`--acl=suggest`) |
| FHE4012 | note | suggest-transient-for-return (`--acl=suggest`) |
| FHE5001 | error | op-not-in-profile-version (§1.5) |
| FHE5002 | error | unknown-target-profile |
| FHE5003 | error | installed-library-version-mismatch |
| FHE6000 | (forwarded) | solc-diagnostic (carries solc's own code, severity, and the remapped `.fsol` span) |
| FHE9001 | error | internal-invariant-violation |
| FHE9002 | error | output-reparse-failed (§2.5) |
| FHE9003 | error | fragment-reparse-failed (§2.5) |

Every diagnostic MUST carry: code, severity, original-source span, message. It SHOULD carry fix-its and a documentation link. Fix-its marked `safe: true` MAY be auto-applied by `--fix`.

---

## §10 Conformance test format

### §10.1 Fixture layout

```
fixtures/<area>/<case-name>/
    input.fsol                    # required
    expected.sol                  # required iff transpilation succeeds
    expected.diagnostics.json     # required (empty array when no diagnostics)
    fhec.toml                     # optional per-case config override
```

`<area>` is one of: `operators`, `select`, `acl`, `sugar`, `typing`, `reject`, `noop`, `idempotence` (extensible).

### §10.2 Diagnostic JSON schema

`expected.diagnostics.json` is a JSON array of objects:

```json
{
  "code": "FHE3011",
  "severity": "error | warning | note",
  "span": {
    "file": "input.fsol",
    "start_byte": 0, "end_byte": 0,
    "start_line": 1, "start_col": 1,
    "end_line": 1, "end_col": 1
  },
  "message": "…",
  "fixits": [
    { "span": { "…": "as above" }, "replacement": "…", "safe": true }
  ],
  "rule": "§5.2"
}
```

**⚠ Draft decision:** lines and columns are 1-based; byte offsets are 0-based half-open; columns count UTF-8 bytes, not grapheme clusters. `message` matching in the harness is exact by default; a fixture MAY specify a prefix match with `"message_prefix"`.

### §10.3 Pass criteria

A case passes when (a) produced diagnostics equal the expected set (order-insensitive, spans exact), and (b) if `expected.sol` exists, output is byte-identical to it, and (c) the output compiles under the pinned solc with the pinned profile library.

### §10.4 Property clauses

1. **Idempotence:** for every accepted `input.fsol`, `T(T(x)) == T(x)` byte-exact.
2. **No-op:** for every file `y` in the plain-Solidity must-not-touch corpus, `T(y) == y` byte-exact (modulo §2.6, which does not apply to files without `.fsol` imports).
3. **Differential equivalence** (informative here, normative for the reference implementation's CI): transpiled output and a hand-written reference contract, run under the CoFHE mock TaskManager with identical transaction sequences, produce identical plaintexts and identical `isAllowed` state.

---

## Changelog

- **0.1.0 (2026-08-17)** — first draft. Covers: conformance clauses, `in` sugar, encryptedness typing, operator table, select lowering with branch versioning, definite assignment, reject list, ACL rules R1–R3, error catalog, conformance test format.
- **0.1.1 (2026-08-17)** — error-catalog additions from implementation: FHE1004 config-not-found, FHE1005 config-invalid, FHE1020 duplicate-definition.
- **0.1.2 (2026-08-17)** — findings from the lowering implementation: §8.2 requires the explicit `address(...)` wrapper, typed callee hoisting, FHE4003 for underivable callee types, and documents the Unknown-callee under-grant; §8.6 splits the dedupe window (forward for R1, backward for R2/R3); §5.2 defines branch-local declarations and FHE3013 for unsupported statement forms in encrypted branches.
- **0.1.3 (2026-08-17)** — findings from the CLI wiring: FHE1006 frozen-drift; §2.1 names the load stage as the pragma-gate owner; §8.4 states that suggest-mode notes appear on `check` and defines the safe-fix-it boundary for `--fix`.
- **0.1.4 (2026-08-22)** — §1.4 defines the self-check diagnostic-suppression rule (re-run diagnostics below error severity are suppressed).
- **0.2.0 (2026-08-22)** — cofhe-contracts 0.2.0 input model: §1.5 replaces the removed `InEuintX` input structs with the `externalE*` handle types; §2.3 lowers the sugar to an in-place `externalT name_input` parameter plus one shared trailing `bytes memory inputProof` parameter per function, converts one input via the two-argument `FHE.asT(hash, proof)` and several inputs via a single `Impl.verifyBatchInputs` batch (one signature covers the whole batch); FHE1011 additionally guards the `inputProof` name.
