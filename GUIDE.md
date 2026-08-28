# Writing `.fsol`

`.fsol` is Solidity plus six shortcuts for CoFHE. Every valid Solidity file is
already a valid `.fsol` file — adopt it one function at a time. `fhec build`
compiles it down to the plain, auditable Solidity you'd otherwise write by
hand; see [README.md](README.md) for setup and the CLI.

## Cheat sheet

| Write | Instead of | Feature |
|---|---|---|
| `in euint32 x` | `externalEuint32 x, bytes proof` + `FHE.asEuint32(x, proof)` | encrypted input |
| `a + b`, `a <= b`, `c ? a : b` | `FHE.add(a, b)`, `FHE.lte(a, b)`, `FHE.select(c, a, b)` | encrypted operators |
| `if (cond) { ... }` where `cond` is encrypted | hand-rolled `FHE.select` merging | encrypted `if` |
| *(nothing)* | `FHE.allowThis(x); FHE.allowSender(x);` after every encrypted write | automatic ACL |
| `precondition { ... }` | hoping nobody moves your auth check below input verification | ordering guard |
| `in shared euint64 x` / `returns (shared(msg.sender) euint64)` | `FHE.receiveEuint64Param(x)` / `FHE.shareEuint64(x, msg.sender)` | shared handles |

---

## Encrypted inputs — `in`

```solidity
function deposit(in euint32 amount) external {
    balance = balance + amount;
}
```

`amount` arrives, verifies, and decodes in one word. `fhec` expands the
parameter and inserts the conversion for you:

```solidity
function deposit(externalEuint32 amount_input, bytes memory inputProof) external {
    euint32 amount = FHE.asEuint32(amount_input, inputProof);
    balance = FHE.add(balance, amount);
    ...
}
```

Need the proof parameter somewhere other than last (e.g. before a trailing
`data` argument)? Name it explicitly:

```solidity
function transferAndCall(address to, in(proof) euint64 amount, bytes calldata proof, bytes calldata data) external
```

## Encrypted operators

Write arithmetic and comparisons as operators, not library calls:

```solidity
euint32 sum  = a + b;
ebool    ok  = sum <= max;
euint32 next = ok ? sum : a;
```

is exactly:

```solidity
euint32 sum  = FHE.add(a, b);
ebool    ok  = FHE.lte(sum, max);
euint32 next = FHE.select(ok, sum, a);
```

`+ - * / % & | ^ ~ << >> < <= > >= == != && || ! ?:` are all covered.

## Encrypted `if`

```solidity
if (balance >= amount) {
    balance = balance - amount;
}
```

Both branches always run — the compiler merges them with `FHE.select`
afterward, so the chosen branch is never observable. No `return`, `revert`,
or `emit` inside one (see *What fhec refuses* below).

## Automatic ACL

Write the storage write; `fhec` inserts the access grant right after it:

```solidity
balance = balance + amount;
```
```solidity
balance = FHE.add(balance, amount);
FHE.allowThis(balance);
FHE.allowSender(balance);
```

Same idea for an external call taking an encrypted argument
(`FHE.allowTransient` to the callee) and for an encrypted return value
(`FHE.allowTransient` to the caller) — write the call, `fhec` grants access.

## `precondition` — keep your checks first

Inputs verify before the function body runs — normally the *first* thing
that happens. Wrap an authorization check that must run even earlier:

```solidity
function spend(address from, in euint64 amount) external {
    precondition {
        if (!isOperator(from, msg.sender)) revert Unauthorized();
    }
    balance[from] = balance[from] - amount;
}
```

An unauthorized caller now reverts with `Unauthorized()`, not a proof error.

## Shared handles — `in shared` / `shared(...)`

For a value already verified elsewhere (e.g. the result of another
confidential call), skip the proof round-trip entirely:

```solidity
function send(address to, in shared euint64 amount) external returns (shared(msg.sender) euint64) {
    return _transfer(msg.sender, to, amount);
}
```

`in shared` receives the handle; `shared(msg.sender)` hands the result back
to the caller. No `FHE.receiveEuint64Param` / `FHE.shareEuint64` to write.

---

## What `fhec` refuses

- `return` / `revert` / `emit` / a plaintext write inside an encrypted `if` branch — the branch choice must stay invisible.
- Two indexed writes in one encrypted `if` that might hit the same slot — split into sequential `if`s.
- `euint256` — profile types stop at `euint128`, plus `ebool` / `eaddress`.
- Anything the checker isn't sure about: no patch, just an error. A wrong guess would be a silently wrong ciphertext, not a revert.

## More

Full grammar and diagnostics: [spec/spec.md](spec/spec.md). CLI, Hardhat/Foundry setup: [README.md](README.md).
