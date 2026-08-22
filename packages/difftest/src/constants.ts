/**
 * Addresses and keys baked into the CoFHE mock coprocessor.
 *
 * These are NOT secrets and NOT configurable: `@fhenixprotocol/cofhe-contracts`
 * hard-codes `TASK_MANAGER_ADDRESS` in `FHE.sol`, so the mock TaskManager has to
 * be installed at exactly that address for any FHE call to reach it. The signer
 * keys are declared as file-level constants in `@cofhe/mock-contracts`'
 * `MockCoFHE.sol`.
 *
 * `assertMockConstants()` re-derives the addresses from the private keys at
 * runtime, so a future version bump that rotates them fails loudly instead of
 * producing mysterious `InvalidSigner` reverts.
 */

/** `TASK_MANAGER_ADDRESS` in `@fhenixprotocol/cofhe-contracts/FHE.sol`. */
export const TASK_MANAGER_ADDRESS = '0xeA30c4B8b44078Bbf8a6ef5b9f1eC1626C7848D9';

/** `MockZkVerifierArtifact.fixedAddress` in `@cofhe/mock-contracts`. */
export const ZK_VERIFIER_ADDRESS = '0x0000000000000000000000000000000000005001';

/** `MockThresholdNetworkArtifact.fixedAddress` in `@cofhe/mock-contracts`. */
export const THRESHOLD_NETWORK_ADDRESS = '0x0000000000000000000000000000000000005002';

// `ACPShareRegistry` and `ACPTimestampRevoker` — the two contracts
// `@cofhe/mock-contracts` 0.7.0 added — have `isFixed === false`, so they get no
// constant here: they are deployed normally and linked into the ACL by address
// (`setShareRegistry` / `setDefaultRevokerContract`). See `src/mocks.ts`.

/** `ZK_VERIFIER_SIGNER_ADDRESS` in `@cofhe/mock-contracts/contracts/MockCoFHE.sol`. */
export const ZK_VERIFIER_SIGNER_ADDRESS = '0x6E12D8C87503D4287c294f2Fdef96ACd9DFf6bd2';

/** `ZK_VERIFIER_SIGNER_PRIVATE_KEY` in `MockCoFHE.sol` (decimal there, hex here). */
export const ZK_VERIFIER_SIGNER_PRIVATE_KEY =
  '0x6C8D7F768A6BB4AAFE85E8A2F5A9680355239C7E14646ED62B044E39DE154512';

/** `DECRYPT_RESULT_SIGNER_ADDRESS` in `MockCoFHE.sol` (hardhat account #1). */
export const DECRYPT_RESULT_SIGNER_ADDRESS = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

/** `DECRYPT_RESULT_SIGNER_PRIVATE_KEY` in `MockCoFHE.sol`. */
export const DECRYPT_RESULT_SIGNER_PRIVATE_KEY =
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

/**
 * `Utils.*_TFHE` in `@fhenixprotocol/cofhe-contracts/ICofhe.sol` (unchanged in
 * 0.2.0; re-verified against the 0.2.0 source).
 *
 * `euint256` is listed because `Utils.EUINT256_TFHE = 8` is declared, but no
 * `euint256` / `externalEuint256` value type exists in 0.2.0 — the code is
 * reserved, not usable.
 */
export const UTYPE = {
  ebool: 0,
  euint8: 2,
  euint16: 3,
  euint32: 4,
  euint64: 5,
  euint128: 6,
  eaddress: 7,
  euint256: 8,
} as const;

export type EncryptedTypeName = keyof typeof UTYPE;
