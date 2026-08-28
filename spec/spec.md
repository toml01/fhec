# The `.fsol` Dialect Specification

| | |
|---|---|
| **Version** | 0.6.0 |
| **Status** | Draft |
| **Date** | 2026-08-28 |
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
3. Except for the extensions in §2.3, §2.7, and §2.8, the grammar of `.fsol` is exactly the grammar of Solidity in the supported pragma range. Every valid Solidity file in that range is a valid `.fsol` file.
4. When `project.include` matches no `.fsol` / `.sol` files under `project.src`, the load stage MUST emit FHE1007 (warning). An empty match is almost always a misconfigured `src` or include glob, not an empty project.

### §2.2 Parse errors

Input that does not parse under the dialect grammar is rejected with FHE1002. Unresolvable imports are FHE1003. When a relative specifier fails to resolve and replacing `.sol` with `.fsol` (or the reverse) names a file the compilation unit actually discovered, the diagnostic SHOULD carry a `safe: true` fix-it that rewrites the specifier.

### §2.3 The `in` parameter sugar

Grammar: in a function or constructor parameter list, the production

```
parameter := 'in' [ '(' identifier ')' ] encrypted-type identifier
```

is added, where `encrypted-type` is one of the profile's encrypted value types (§1.5). `in` is a reserved Solidity keyword, so this production conflicts with no valid Solidity program.

The two forms differ only in where the input proof comes from:

- **implicit** — `in eT name`: the expansion appends one shared proof parameter at the end of the list;
- **explicit binder** — `in(proof) eT name`: `proof` names a parameter the author already declared in the *same* parameter list, and nothing is appended.

The binder exists because the appended parameter is always last, which some external ABIs do not allow: ERC-7984's `…AndCall` entry points fix the proof *before* the trailing `data` argument. The binder lets the author write that order and keep it.

**Expansion.** For a function or constructor with k ≥ 1 sugared parameters (`eT` maps to external handle type `externalT` and conversion function `asT` per the profile — e.g. `euint32` → `externalEuint32` / `FHE.asEuint32`):

1. Each parameter `in eT name` or `in(proof) eT name` becomes the declaration `externalT name_input` in the same position (external handle types are value types; no data location).
2. The *proof parameter* is determined once per function, regardless of k:
   - implicit form: one shared parameter `bytes memory inputProof` is appended at the end of the parameter list. This matches the SDK convention (cofhe SDK 0.7.0): a function with encrypted inputs ends with one plain `bytes` parameter receiving the shared batch signature.
   - explicit binder: the bound parameter is the proof parameter. It keeps its declared position, name, and data location byte-for-byte, and **no** parameter is appended, so the bound form adds nothing to the ABI.
3. Conversion statements are inserted at the *materialization point*, in parameter-list order, and read the proof parameter fixed by (2). The materialization point is the start of the function body, before any existing statement — unless the body opens with a `precondition` block, which moves it after that block (§2.7).
   - k = 1: `eT name = FHE.asT(name_input, inputProof);`
   - k > 1: a single batch verification. One signature covers the whole batch (cofhe-contracts#78), so per-parameter `FHE.asT(hash, proof)` calls — which each rebuild a one-element batch digest — would fail verification. The expansion builds one `UnsignedEncryptedInput[]` in parameter order (security zone 0, matching FHE.sol's own batch helpers), verifies it once through `Impl.verifyBatchInputs(inputs, inputProof)`, and wraps each returned `bytes32` handle into its value type:

     ```solidity
     UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](k);
     __fhe_inputs_0[i] = UnsignedEncryptedInput(uint256(externalT.unwrap(name_input)), 0, Utils.T_TFHE); // per parameter
     bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, inputProof);
     eT name = eT.wrap(__fhe_hashes_1[i]); // per parameter
     ```

     The array temporaries are named per §2.4 (hints `inputs`, `hashes`). In the bound form `inputProof` above is the bound parameter's own name.

**Binding.** The proof binder is resolved by name, never guessed. For a parameter list that uses the explicit form:

1. The bound identifier MUST name **exactly one** parameter of the **same** parameter list, declared `bytes memory` or `bytes calldata`. A binder that names nothing in that list, names a parameter of another type or data location, or names something that is not a parameter of that list at all (a state variable, a constant, a name from an enclosing scope) is FHE1013. The transpiler MUST NOT fall back to searching a wider scope, and MUST NOT infer the proof from a parameter's type or position.
2. Every `in` parameter of **one** parameter list MUST agree: either all use the implicit form, or all bind the **same** identifier. Mixing the two forms in one list, or binding two different identifiers, is FHE1014. Several inputs bound to one proof still verify as **one atomic batch**, in encrypted-parameter source order — the position of the bound parameter within the list does not affect that order.

The bound parameter is an ordinary author-declared parameter everywhere else: it is a plaintext `bytes` value the body may read, and the transpiler neither renames it nor moves it.

**⚠ Draft decision (data location):** the *appended* proof parameter uses `memory`. `calldata` is not used in v1. A *bound* proof keeps whichever of `memory` or `calldata` the author declared.

A modifier invocation is part of the function *header* and is evaluated before the body opens, but `<name>` only exists from the materialization point onwards. A modifier argument that names an `in` / `in(proof)` / `in shared` parameter would therefore reference an identifier the output does not declare there, so the transpiler MUST refuse with FHE1019 rather than emit it.

A selective import (`import {A, B} from "…";`) brings in exactly what it names. The sugar needs two symbols in scope: the encrypted type the author wrote, and the wire type the expansion declares the parameter with (`externalT` for §2.3, `sharedT` for §2.8). When the file imports the profile module selectively and does not name either, the transpiler MUST refuse with FHE1021, naming the missing symbol, and SHOULD attach a `safe: true` fix-it that adds it to the import list. A plain import brings the whole surface into scope and is unaffected.

On a **bodiless** declaration the §2.3 expansion likewise generates no local, so the parameter keeps the author's name and only its type changes; the appended proof parameter is unaffected.

**⚠ Draft decision (generated names):** the raw-input parameter is named `<name>_input`, and, in the implicit form, the appended proof parameter is named `inputProof`. If `<name>_input` is already declared anywhere in the function's scope (parameters, locals, contract members referenced unqualified), the transpiler MUST reject with FHE1011 rather than rename silently; the same applies to `inputProof` in the implicit form. The explicit binder introduces **no** new fixed generated name — it reuses the author's own parameter name verbatim — so `inputProof` is not reserved in a bound function and a parameter of that name is the ordinary case there.

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

### §2.7 The `precondition` block

Grammar: in any statement position, the production

```
statement := 'precondition' block
```

is added. `precondition` is a **contextual** keyword: it is recognized only when it is immediately followed by `{`, and **not** when what follows the `{` is call-options syntax — a named option (`precondition{value: 1}()`) or an empty option list before `(` (`precondition{}()`). In those two shapes the token parses as an ordinary identifier, exactly as any other name would, so `precondition` stays a legal Solidity identifier everywhere: this production conflicts with no valid Solidity program, and the no-op corpus (§1.4) is unaffected.

**Purpose.** By default the §2.3 conversion statements are the first thing a body executes, so an encrypted input is verified *before* any authorization check the author wrote. A `precondition` block names a plaintext guard that MUST run first, so an unauthorized call reverts with the contract's own error rather than with a proof-verification error. The transpiler never reorders author statements: only the generated materializers move, and only when the author wrote the marker.

**Execution order.** For a function whose body opens with a `precondition` block:

```
ABI decode
→ modifier preludes
→ precondition block
→ input materializers      # this function's dialect inputs, source parameter order
→ ordinary body
→ modifier postludes
```

Without the marker, the materializers stay at body entry (§2.3) and the order is unchanged.

**Legality.** A `precondition` block is legal only when all of the following hold; every other occurrence is FHE1017, which refuses the whole compilation unit:

1. It is the **first statement** of the body (after `{`, ignoring trivia).
2. There is **at most one** in the function. A second block anywhere in the body — including nested inside the first — is illegal.
3. The host is a `function` or `constructor` whose parameter list declares **at least one dialect-managed encrypted input** (an `in eT` or `in(proof) eT` parameter, §2.3, or an `in shared eT` parameter, §2.8). Without one there is nothing to guard.

The parser accepts the block in every statement position; positional legality is a checker rule, so a misplaced block yields FHE1017 rather than a parse error.

**Body restrictions.** The block is a *plaintext guard*. The following are permitted:

- plaintext parameters, plaintext state **reads**, constants, and `msg.sender` / `msg.data` / `block.*`;
- local **plaintext** declarations, and assignments and `++`/`--` to the **whole** of a local **declared inside the block** — the block's scope does **not** escape, so nothing declared inside it is visible afterwards. Writing the local itself (`a = ...`, `a++`) only rebinds the name, whatever its type, so it is always permitted. A write **through** such a local — any element or member write (`a[0] = 1`, `s.f = 1`, `a[0].f = 1`) — is **never** permitted, whatever the local's declared type and however it was initialized. A Solidity reference type (array, mapping, struct, `bytes`, `string`, in any data location) binds to existing data instead of copying it, and the data reached that way can come from outside the block through the declaration, through a later rebind, through a tuple declaration, or through a reference stored inside a container the block did allocate. The transpiler does not prove freshness (§1.3): it refuses every write through a local;
- nested blocks and plaintext `if`;
- `require` / `assert` / `revert`, and the pure builtins `keccak256`, `sha256`, `ripemd160`, `ecrecover`, `addmod`, `mulmod`;
- `new` **memory allocations** (`new uint256[](n)`, `new bytes(n)`). A `new` on any other type deploys a contract and is refused;
- plaintext conversions: `uint256(x)`, `address(0)`, `payable(x)`, and an in-unit contract or type conversion, whether the type name is plain (`Money(x)`, `Money.wrap(x)`) or qualified (`Lib.Money(x)`, `Lib.Money.unwrap(x)`). A qualified type name is a conversion, not a member call: no user code runs. The named type MUST be one the transpiler can prove is plaintext: a profile encrypted type or external-input handle is refused in both spellings;
- calls to functions of **this compilation unit** that resolve statically to declarations that are `view` or `pure` **and** whose declared return types the transpiler can prove are plaintext **and** whose parameters take no `memory` reference argument. Solidity only lets an override tighten mutability, so a `view` declaration bounds every override. `view`/`pure` forbid state access, not memory mutation: a `pure` callee may still write through a `memory` array/struct/`bytes`/`string` parameter, which would let an effect escape the block by proxy. `calldata` is read-only, and `storage`/`transient` writes are already state changes `view`/`pure` forbid outright, so only `memory` parameters need this exclusion.

Naming a dialect-managed encrypted input inside the block is FHE3014: the block runs before that input's conversion, so the value does not exist yet. FHE3014 wins wherever the input appears, including nested inside a larger expression that is refused anyway (`amount == enc`): it is the more specific of the two diagnostics, and it names the input.

Everything else is FHE3015:

- **state writes** (a write to a local declared inside the block stays legal; the diagnostic MUST say *state write*), including `delete`;
- **escaping writes**: a write whose base variable is declared outside the block and outlives it — a parameter, a **named return**, or a local of an enclosing scope — and every write *through* a block-local. The diagnostic MUST name the variable and say the effect would escape the block;
- every **encrypted-typed expression** — encrypted operations, encrypted control flow, encrypted state reads, and `view` calls that return encrypted values. A type counts as encrypted when an encrypted type appears **anywhere inside it**, not only at its root: `euint32[]` and a struct with an encrypted field are refused exactly as a bare `euint32` is, wherever a declaration, a read, or a call's declared return type names one;
- a `wrap` / `unwrap` on a type the target profile owns (`euint32.wrap(x)`, `Lib.euint32.unwrap(x)`): those produce or consume an encrypted value, so they are not plaintext conversions;
- `emit`;
- calls the transpiler cannot classify: imported, unresolved, ambiguous, member (`Lib.f()`, `token.f()` — a qualified *type* conversion is not one of these), state-changing, with a return type it cannot prove plaintext, or that take a `memory` reference parameter — **even when the source declares them `view` or `pure`**;
- `return`, loops, `break` / `continue`, `try`, inline assembly, and any other statement form not listed above.

The permitted list is a whitelist. A construct the transpiler does not recognize is refused, never assumed harmless (§1.3).

**Lowering.** The transpiler removes **only** the marker (the keyword and the trivia up to the block's `{`), leaving an ordinary nested block whose bytes are untouched, and inserts the materializers immediately after that block's closing `}`. The marker patch and the insertion never overlap (§2.5). Idempotence follows: the output has no marker and no `in` parameters, so `T(T(x)) == T(x)`.

### §2.8 The shared boundary

An encrypted handle can also cross a contract boundary *directed*: its holder shares it with a named recipient, and the recipient receives it. The profile carries this as a distinct wire type per encrypted type — the **shared handle** `sharedT` — plus a `share` and a `receive` operation (CoFHE: `sharedEuint64`, `FHE.shareEuint64(handle, receiver)`, `FHE.receiveEuint64Param(handle)`). Nothing about the rules below is CoFHE-specific; a profile that lacks the boundary for an encrypted type reports FHE5001 (§1.5).

Two markers are added, one per direction:

```
parameter := 'in' 'shared' encrypted-type identifier
return     := 'shared' '(' expression ')' encrypted-type
```

`shared` is a **contextual** keyword. It is read as a marker only where plain Solidity has no other reading: directly after the reserved `in` keyword, or immediately before `(` in a declaration's type position. Everywhere else it stays an ordinary identifier, so this production conflicts with no valid Solidity program and the no-op corpus (§1.4) is unaffected.

The parser records a marker wherever it can be written unambiguously and judges nothing; every illegal position and shape below is FHE1015, a checker rule, not a parse error.

#### Shared input — `in shared eT name`

**Expansion.** For each such parameter (`eT` maps to wire type `sharedT` and receive function `receiveTParam` per the profile):

1. The parameter becomes `sharedT name_shared` in the same position. Shared handles are value types; no data location.
2. `eT name = FHE.receiveTParam(name_shared);` is inserted at the *materialization point* (§2.3, §2.7 — after a `precondition` block when the body opens with one, else at body entry).

Several shared inputs of one function receive **independently**, one statement each, in source parameter order. There is no batch: a shared handle was verified when it was shared, so — unlike the external inputs of §2.3 — it carries no input proof and nothing is appended to the parameter list. The ABI therefore gains no proof argument.

**Restrictions.** Every violation is FHE1015 unless noted.

1. The marker is permitted only in a `function` parameter list that is `external` and neither `view` nor `pure`. A shared handle is an ABI wire type an internal caller cannot produce, and receiving one changes access-control state. `public`, `internal`, `private`, constructors, modifiers, `view`, `pure`, return lists, event/error parameter lists, `try`/`catch` declaration lists, and state variables are all illegal. **⚠ Draft decision (`external` only):** `public` is refused because a `public` function is also callable internally, the expansion rewrites the declaration alone, and an internal call site would still pass the unshared `eT`.
2. `in shared` must be followed by an encrypted type.
3. The parameter must be named: the expansion declares `<name>_shared` and receives it into `<name>`.
4. A shared input takes no proof binder (`in(proof) shared eT` is illegal) and no recipient (`in shared(x) eT` is illegal — a recipient belongs on a return type).
5. **⚠ Draft decision (no mixed inputs):** one parameter list declares either shared inputs or external `in` / `in(proof)` inputs, never both. The two verify under different models — several external inputs form one atomic proof batch — and this version fixes no ordering between that batch and the receives. Splitting the function is the workaround.
6. On a declaration without a body, only the signature rewrite applies; no receive statement is generated (as §2.3 restriction 3). The visibility rule of restriction 1 still holds, so an interface or abstract declaration carrying `in shared` must be `external`.
7. The declaration takes no data location. Encrypted types and shared handles are value types, so `memory`, `calldata`, `storage`, and `transient` are all illegal — as they are in plain Solidity on the same type. The transpiler MUST refuse rather than drop the keyword while rewriting the declaration (§1.3).

On a **bodiless** declaration (an interface member or an abstract function) the expansion generates no local, so the parameter keeps the author's name and only its type changes. That name is ABI-visible: on a published interface it is what integrators read and what named-argument call sites bind to, and a signature-only rewrite must not change it.

**⚠ Draft decision (generated name):** the wire parameter is named `<name>_shared`. If that identifier is already used anywhere in the function's scope, the transpiler MUST reject with FHE1016 rather than rename silently.

#### Shared return — `returns (shared(recipient) eT)`

**Expansion.**

1. The return declaration becomes `sharedT`, so the ABI result type is the shared handle.
2. Every `return expr;` of the body becomes `return FHE.shareT(expr, recipient);`.

The returned expression is wrapped **where it stands**, never hoisted, so it is evaluated exactly once by construction and ordinary operator lowering (§4) still applies inside it. The wrap is expressed as two insertions at the expression's own boundaries, which cannot overlap any patch inside the expression or any ACL insertion before or after the statement (§2.5).

**Call sites.** A call to a function with a shared return types as **Unknown** (§3.1). Its declaration names `eT`, but the value the call yields is the `sharedT` wire handle, and this version has no way to unshare it. An encrypted operand meeting such a call is therefore FHE2001 (§3.2), not a silent `FHE.op(sharedT, …)`.

**Relation to R3.** A shared return **replaces** the §8.3 R3 grant: `FHE.shareT(..., msg.sender)` directs the handle at the caller, so the transpiler MUST NOT also insert `FHE.allowTransient(..., msg.sender)` for it. Every other ACL rule still applies unchanged; in particular an R2 grant (§8.2) for an external call inside the returned expression MUST still be inserted. A shared-boundary rewrite MUST NEVER cost an ACL grant.

**Restrictions.** Every violation is FHE1015 unless noted.

1. The host must be a `function` that is `public` or `external` and neither `view` nor `pure`.
2. **⚠ Draft decision (recipient):** the recipient MUST be exactly the expression `msg.sender`, where `msg` resolves to the Solidity builtin — not merely an expression spelled that way. Another expression is refused even when it would evaluate to the caller's address, because the transpiler cannot prove that (§1.3). Because the rewrite re-emits the literal text `msg.sender` at every `return`, a function that declares anything named `msg` anywhere in its body — a local, a `for`-init declaration, or a `try`/`catch` binder — is refused outright too: Solidity's block scoping would let such a declaration shadow the builtin from its declaration point onward. Other recipients are a later revision.
3. The shared return MUST be the only return value of its function and MUST be unnamed. Tuples, a named fallthrough return, and lists mixing a shared return with a plain or encrypted one are all refused.
4. `shared(...)` must be followed by an encrypted type, and the `in` marker has no meaning on a return type. The declaration takes no data location, for the reason given in shared-input restriction 7.
5. Every `return` in the body MUST be an explicit valued `return expr;`. A bare `return;` is refused.
6. **⚠ Draft decision (braced returns):** a `return` of a shared value MUST sit inside a braced block, not as the bare body of an `if`/`else`/`for`/`while`/`do`. ACL insertion places grant *statements* before the statement they serve, which a braceless branch body cannot hold; requiring braces keeps the construct clear of that shape.
7. **⚠ Draft decision (no assignment in the returned expression):** the returned expression MUST NOT contain an assignment or `++`/`--`. An encrypted assignment inside a `return` would state a §8.1 R1 storage-write fact anchored on the `return` statement, whose grant belongs *after* a statement that has already left the function. Assign in its own statement and return the variable.
8. The returned expression MUST type as exactly the declared `eT`; anything else — a different encrypted type, a plaintext value, or a type the checker cannot prove — is FHE2012.

   FHE2012 is an **error**, and states no site, in every case except one: it is a **warning**, and the site is still stated, when the checker could not prove any type *and* the only obstacle is a call whose callee this unit cannot see past an incomplete inheritance surface. The rewrite takes the encrypted type from the *declared* return, never from the expression, so a wrong assumption reaches solc as a type error on the generated `share` call — the profile declares one `shareT` signature per encrypted type, with no competing overload. Refusing every contract that inherits from a package would cost more than the warning does.

   The warning does not extend to a call the checker types through the profile library: an `Unknown` there comes from an operation the profile does not model, not from the unreadable surface, and stays an error.
9. **⚠ Draft decision (no rewrite site under an R2 statement):** when the `return` sits in — or *is* — a statement an R2 grant (§8.2) anchors on, the returned expression MUST NOT contain any rewrite site of its own. R2 renders its own call site and claims the statement; the operator pass then skips the whole claimed span. While R3 applied, its whole-statement re-render happened to cover the returned expression as well, and a shared return replaces R3, so nothing does any more. The typical shape is a `return` inside a `try` clause whose header calls out with an encrypted argument. Compute the value in its own statement and return the variable.

Restrictions 6, 7, and 9 are conservative refusals, not statements about what is expressible in principle.

**No-op.** Explicit `FHE.receive*` / `FHE.share*` calls written by the author are plain CoFHE Solidity and carry no marker, so they are reproduced byte for byte (§1.4). The output of this section is exactly such a source, so `T(T(x)) == T(x)`.

### §2.9 Explicit cast sugar

`eT(x)`, where `eT` is one of the profile's encrypted value types (§1.5), is sugar for `FHE.as<T>(x)` (e.g. `ebool(true)` for `FHE.asEbool(true)`, `euint32(x)` for `FHE.asEuint32(x)`).

Unlike §2.3, §2.7, and §2.8, this section adds **no new grammar production** to the forked parser. `eT(x)` already parses as an ordinary call expression whose callee is a plain identifier — the same shape as any user-defined type cast (`uint32(x)`) or function call. The sugar is a pure naming convention resolved at check time by ordinary name resolution: the callee identifier must denote an encrypted value type of the pinned profile, and it must not be shadowed by an in-scope declaration of another kind (a local, parameter, contract, or user type named `euint32` takes priority, exactly as plain Solidity name resolution already requires). Nothing about this construct is ambiguous with valid Solidity, since `eT` is never itself a valid Solidity type name outside the dialect's trusted profile bindings.

**Expansion.** The call is rewritten in place: the callee identifier `eT` becomes `FHE.as<T>`, and the argument list is left byte-identical — only the callee text is replaced. When `eT(x)` sits inside another rewritten construct — an operand of an operator or compound assignment (§4), an arm of a ternary, or an encrypted-branch rendering (§5.2) — it renders inline as part of that construct's own patch, per the nested-sites invariant of §2.5; it never produces a second, overlapping patch of its own.

**Restrictions.**

1. The call MUST have exactly one argument; a different argument count is FHE1018.
2. The argument is subject to exactly the same rules as an author-written `FHE.as<T>(x)` call (§3.3 Coercions): a plaintext argument must be convertible per coercion rule 1 (else FHE2008), a literal argument is range-checked per rule 2 (else FHE2003), and an already-encrypted argument follows the no-narrowing rule of rule 3 (else FHE2004). This sugar introduces no additional argument-type validation beyond what the equivalent explicit call already receives.

**No-op.** An explicit `FHE.as<T>(x)` call written by the author carries no bare-identifier callee, so it is reproduced byte for byte (§1.4); `eT(x)` never appears in plain CoFHE Solidity output, so `T(T(x)) == T(x)`.

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
4. **Pre-values.** For each location `L` in the write set, read a pre-value temp before the branches **only if** either branch reads `L` before assigning it, or either branch does not assign `L`: `__fhe_pre_n = L;`. A location assigned on both branches before either branch reads its incoming value MUST NOT read or declare a pre-value.
5. **Branch environments.** Walk the then-branch and the else-branch with *separate* environments, each seeded from the required pre-value temps. Each assignment in a branch produces a fresh temp holding the assigned value; subsequent reads in the SAME branch see that temp; reads in the OTHER branch see the pre-value when one is required.
6. **Merge.** After both branch bodies, for every location `L`:
   `L = FHE.select(__fhe_cond_n, <thenVal or pre>, <elseVal or pre>);`
   where `thenVal`/`elseVal` are the final temps of `L` in each branch environment, defaulting to the pre-value temp when a branch did not write `L`. When both arms assign `L` without reading its incoming value, both operands MUST be branch values and no pre-value exists.

Merge writes MUST be emitted in a deterministic order (**⚠ Draft decision:** order of first write occurrence in source).

When the write set is a single identifier `L`, an `else` is present, each arm is exactly one assignment to `L` (a bare assignment or a block whose only statement is that assignment), and the condition and both right-hand sides are free of side effects under §5.5, a conforming transpiler MAY render the statement as `L = FHE.select(<cond>, <thenRhs>, <elseRhs>);` with no condition, pre-value, or branch temporaries. This is an equivalent rendering of the algorithm above: both operands of `select` evaluate, in source order, against the pre-if state. The general form is REQUIRED when any of those conditions fail (several merged locations, several writes in one arm, nested encrypted `if`s, a missing `else`, an indexed or field lvalue, or a side-effecting operand).

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

### §8.0 Braceless branch bodies

A trigger statement MAY be the lone, braceless body of an `if`, `else`, `while`, `do` or `for`. A grant written next to such a statement would change control flow: an insertion *before* it (R2, R3) becomes the branch body and pushes the guarded statement out of the branch, and an insertion *after* it (R1) lands outside the branch and runs unconditionally. When a rule inserts at either boundary of such a statement, the transpiler MUST wrap the statement and the inserted grants in a block, so the branch keeps exactly the statements it had plus the grants. A statement that carries more than one ACL fact is wrapped once.

The wrap is part of the insertion, never of the no-op path: when every grant for a statement is already present (§8.6), the transpiler MUST NOT add braces, so §1.4 holds byte-for-byte.

Where no statement may be written at all — a trigger statement that is the initializer of a `for` header — the transpiler MUST refuse the file with FHE4004 rather than emit a grant in the wrong place.

A single statement MAY state both an R1 write and an R3 return (`return slot = value;`). R1's insertion point is exactly the end of the text R3 replaces, so an independent R1 insertion would land after the `return` and never run. R3 MUST emit the R1 grants inside its own replacement, before the `return`. When R3 does not rewrite the statement (an internal function, a `view` function, or a §8.6 dedupe hit), no legal position is left — before the statement the slot does not hold the value yet, and after it the function has returned — and the transpiler MUST refuse the file with FHE4004.

### §8.1 R1 — storage writes

After each storage write whose right-hand value is encrypted (state variable, mapping slot, array element, struct field), the transpiler MUST insert:

```solidity
FHE.allowThis(<lvalue>);
FHE.allowSender(<lvalue>);
```

immediately after the write statement.

`FHE.allowThis` is unconditional: it grants the contract access to its own slot and cannot leak. `FHE.allowSender` is a claim about who owns the value. When the written slot is a mapping slot keyed by an address-typed expression that is not `msg.sender`, that claim is false in every operator-style flow — the value belongs to the key, not to the caller — so the transpiler MUST NOT insert `FHE.allowSender` there, and MUST emit warning FHE4001 naming the withheld grant. An author who intends an escrow writes the grant explicitly. Warning about a leak and then writing it is not an option a confidentiality tool has (spec §1.3).

### §8.2 R2 — encrypted arguments to external calls

Before an external call taking one or more encrypted arguments, the transpiler MUST insert, per encrypted argument `a`:

```solidity
FHE.allowTransient(a, address(<callee>));
```

The second argument of `allowTransient` is an `address`; contract-typed callee expressions do not convert implicitly, so the transpiler MUST wrap the callee in an explicit `address(...)` cast.

R2 MUST claim ownership of the statement it rewrote, and only then: pass 1 skips any statement R2 owns, so claiming a statement R2 did not rewrite leaves that statement's other operators unlowered, and claiming nothing while rewriting an argument makes the two passes patch the same bytes (FHE9001). When a rewritten argument sits inside a larger operator, ternary or cast site, R2 MUST render that whole site with the argument substituted, because pass 1 will not re-enter the statement.

**⚠ Draft decision (callee hoisting):** when the callee expression is not a plain identifier, `this`-derived constant, or literal, it MUST be hoisted to a temp `__fhe_callee_n` **of the callee's declared type** and that temp used in both the `allowTransient` call (wrapped in `address(...)`) and the call itself, preserving single evaluation. When the declared type cannot be derived, the transpiler MUST refuse the file with FHE4003 rather than guess.

When the callee expression's type is `Unknown` to the checker, no R2 fact exists and no grant is inserted (conservative under-grant: the call reverts on the ACL check instead of leaking access). The transpiler SHOULD surface this as a note in a future revision.

### §8.3 R3 — encrypted returns

In a non-`view` `public`/`external` function returning an encrypted value, the return expression MUST be hoisted to a temp `__fhe_ret_n` and

```solidity
FHE.allowTransient(__fhe_ret_n, msg.sender);
```

inserted before `return __fhe_ret_n;`.

R3 does **not** apply to a function whose return is declared `shared(...)` (§2.8): the share call already directs the handle at the caller, and inserting `allowTransient` as well would grant twice.

### §8.4 View functions

ACL operations cannot execute in `view` context. A `view` function returning an encrypted value gets NO insertion and warning FHE4002 (the caller must have been granted access elsewhere; the getter itself cannot grant it).

### §8.5 The never-auto-allow rule

The transpiler MUST NOT auto-insert `FHE.allow(x, <address>)` for any address other than the patterns in R1–R3 (`allowThis`, `allowSender`, `allowTransient` to callee / `msg.sender`), and MUST NOT auto-insert `allowGlobal` or `allowPublic` under any circumstances. Over-broad allowance is a recognized vulnerability class; broad grants require explicit code (or a future annotation syntax, out of scope for v1).

### §8.6 Dedupe and idempotence

An insertion is suppressed when an equivalent call is already present. **⚠ Draft decision (dedupe window):** "already present" means: a statement calling the same ACL function with an argument that is syntactically identical (after trivial parenthesis stripping) to the would-be inserted argument. For R1 the window looks **forward**: in the same block after the triggering statement and before the next write to the same location, the next external call, or the end of the block, whichever comes first. For R2 and R3 the window looks **backward**: in the same block before the triggering call or `return`, after the previous write to the granted value, since the grant must precede the statement it serves. Method-syntax calls (`x.allowThis()`) count as equivalent to library-syntax calls (`FHE.allowThis(x)`). An existing grant modulo the `address(...)` wrapper counts as equivalent for R2.

CoFHE files ACL permissions against the ciphertext *handle*, not against the storage location, so for R1 a grant on the copied value counts as a grant on the slot. When the triggering statement is exactly `slot = local;` with `local` a plain identifier, the R1 window additionally looks **backward** for a grant whose argument is `local`, stopping at the statement that reassigns or declares `local`. This is the most common CoFHE idiom — compute into a local, grant on the local, then store — and without it every such site receives a redundant on-chain grant.

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
| FHE1007 | warning | no-files-matched (`project.include` matched no `.fsol` / `.sol` files under `project.src`) |
| FHE1010 | error | in-sugar-non-encrypted-type |
| FHE1011 | error | in-sugar-name-collision (§2.3) |
| FHE1012 | error | in-sugar-bad-position (§2.3) |
| FHE1013 | error | in-sugar-proof-binding-invalid (§2.3) |
| FHE1014 | error | in-sugar-proof-binding-inconsistent (§2.3) |
| FHE1015 | error | shared-boundary-bad-position (§2.8) |
| FHE1016 | error | shared-boundary-name-collision (§2.8) |
| FHE1017 | error | precondition-bad-position (§2.7) |
| FHE1018 | error | cast-sugar-bad-arity (§2.9) |
| FHE1019 | error | sugar-name-in-modifier (§2.3, §2.8) |
| FHE1021 | error | sugar-symbol-not-imported (§2.3, §2.8) |
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
| FHE2012 | error / warning | shared-boundary-type-mismatch (§2.8) — warning only for the incomplete-inheritance case in restriction 8 |
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
| FHE3014 | error | encrypted-input-used-in-precondition (§2.7) |
| FHE3015 | error | precondition-forbidden-effect (§2.7) |
| FHE3020 | error | encrypted-index |
| FHE3021 | error | encrypted-loop-condition |
| FHE3022 | error | ebool-in-plaintext-bool-context |
| FHE4001 | warning | non-sender-keyed-encrypted-write (§8.1) |
| FHE4002 | warning | view-return-without-acl (§8.4) |
| FHE4003 | error | acl-callee-type-underivable (§8.2) |
| FHE4004 | error | acl-position-illegal (§8) |
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

Non-error FHE6000 diagnostics whose span is not a discovered file under `project.src` SHOULD be suppressed by default (third-party library warnings are not actionable). Error-severity FHE6000 diagnostics MUST always be forwarded. A CLI that suppresses those warnings MUST provide a flag (`--all-solc-warnings`) that restores them.

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
- **0.3.0 (2026-08-27)** — second grammar extension: §2.7 adds the contextual `precondition` block, which moves a function's generated encrypted-input materializers after an author-written plaintext guard; §2.3 renames its insertion point to the *materialization point* and drops the "single v1 grammar extension" claim from its title; §2.1 lists both extensions; new codes FHE1017 (position), FHE3014 (managed input named in the block), FHE3015 (forbidden effect).
- **0.5.0 (2026-08-27)** — third grammar extension: §2.8 adds the shared boundary. `in shared eT name` lowers a parameter to the profile's `sharedT` wire type and receives it at the materialization point, with no input proof and no batching; `returns (shared(msg.sender) eT)` makes the ABI result `sharedT` and wraps every returned expression in one `share` call, in place, so single evaluation and nested operator lowering both hold by construction. A shared return replaces the §8.3 R3 grant and never costs any other ACL grant. MVP limits: `in shared` on `external` functions only, no data location on either marker, no mixing of shared and external inputs in one parameter list, one unnamed shared return per function, recipient exactly `msg.sender`, explicit valued `return` inside a braced block, no assignment in the returned expression, and no rewrite site in a returned expression whose statement an R2 grant already claims. A call to a shared-return function types as `Unknown`. New codes FHE1015 (bad position or shape), FHE1016 (`<name>_shared` collision), FHE2012 (returned expression is not the declared encrypted type); a profile without a shared boundary for a type reuses FHE5001.
- **0.4.0 (2026-08-27)** — §2.3 adds the explicit proof binder `in(proof) eT name`: the input verifies against an author-declared `bytes memory|calldata` parameter of the same list, which keeps its position, name, and data location, and nothing is appended to the parameter list, so an ERC-7984 `…AndCall` order (proof before `data`) is expressible. The implicit `in eT name` form and its trailing `bytes memory inputProof` are unchanged. New codes FHE1013 (binder does not name a same-list `bytes` parameter) and FHE1014 (one parameter list mixes the two forms or binds two different proofs).
- **0.6.0 (2026-08-28)** — §2.9 adds explicit cast sugar: `eT(x)` is sugar for `FHE.as<T>(x)`, rewriting only the callee identifier and leaving the argument byte-identical, so the argument gets exactly the type-checking an author-written `FHE.as<T>(x)` call already receives. This is the first grammar-adjacent extension that adds zero new parser grammar: unlike §2.3, §2.7, and §2.8, it reuses the existing call-expression grammar and resolves purely through name resolution. New code FHE1018 (a call with an argument count other than one).
- **0.6.1 (2026-08-28)** — FHE1007: the load stage warns when `project.include` matches no source files under `project.src`. Non-error FHE6000 diagnostics from files outside `project.src` are suppressed by default; `--all-solc-warnings` restores them. Errors from any file are still forwarded.
- **0.6.2 (2026-08-28)** — FHE1003 carries a `safe: true` fix-it when swapping the dialect extension of a relative import names a discovered unit file.
- **0.6.3 (2026-08-28)** — §5.2 permits rendering an `if`/`else` whose arms are each a single assignment of the same identifier as one `FHE.select` with no condition or branch temporaries, when the operands are free of side effects.
