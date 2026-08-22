import type { HardhatRuntimeEnvironment } from 'hardhat/types';
import type { Contract } from 'ethers';
import { SigningKey, Wallet, concat, keccak256, solidityPacked, toBeHex } from 'ethers';

import {
  ACPShareRegistryArtifact,
  ACPTimestampRevokerArtifact,
  MockACLArtifact,
  MockTaskManagerArtifact,
  MockThresholdNetworkArtifact,
  MockZkVerifierArtifact,
  type MockArtifact,
} from '@cofhe/mock-contracts';

import {
  DECRYPT_RESULT_SIGNER_ADDRESS,
  DECRYPT_RESULT_SIGNER_PRIVATE_KEY,
  TASK_MANAGER_ADDRESS,
  UTYPE,
  ZK_VERIFIER_ADDRESS,
  ZK_VERIFIER_SIGNER_ADDRESS,
  ZK_VERIFIER_SIGNER_PRIVATE_KEY,
  type EncryptedTypeName,
} from './constants';

// Type augmentation for `hre.ethers`.
import '@nomicfoundation/hardhat-ethers';

/** A ciphertext handle. `euint32` is `bytes32` in cofhe-contracts >= 0.1.0. */
export type Handle = bigint | string;

/** One value to encrypt, as an element of a batch. */
export interface EncryptedInputSpec {
  value: bigint | number | boolean;
  type: EncryptedTypeName;
  /**
   * Defaults to 0, which is the only value that verifies through the
   * single-input path: `FHE.asEuintXX(handle, proof)` builds its
   * `UnsignedEncryptedInput` with `Utils.inputFromHashAndProof(...)`, whose
   * convenience overload hard-codes `securityZone = 0`.
   */
  securityZone?: number;
}

/**
 * A verified encrypted input under cofhe-contracts 0.2.0.
 *
 * The old `InEuintXX` struct is gone. An encrypted argument is now a *pair*:
 * an `externalEuintXX` handle (a plain `bytes32`) in the parameter's own
 * position, and one `bytes` proof — the batch signature — as the trailing
 * argument shared by every encrypted input of the call.
 */
export interface EncryptedInput {
  /** ABI value for the `externalEuintXX` parameter: the ct hash as `bytes32`. */
  handle: string;
  /** The same ct hash as a number, for mock-storage lookups. */
  ctHash: bigint;
  utype: number;
  securityZone: number;
  /** Batch signature, for the call's trailing `bytes inputProof` parameter. */
  signature: string;
}

/**
 * Several inputs authenticated by ONE signature.
 *
 * Needed whenever a single call carries more than one encrypted argument: the
 * signature covers the whole batch, so per-argument `FHE.asEuintXX(h, proof)`
 * calls would each rebuild a one-element digest and fail. Such a contract must
 * verify them together (`FHE.asEuintXXs` / `Impl.verifyBatchInputs`), and the
 * order here must match the order the contract builds its input array in.
 */
export interface EncryptedInputBatch {
  /** ABI values for the `externalEuintXX` parameters, in batch order. */
  handles: string[];
  /** The same ct hashes as numbers, in batch order. */
  ctHashes: bigint[];
  /** The one signature covering the whole batch. */
  signature: string;
}

export interface DeployMocksOptions {
  /**
   * Leave the mock coprocessor's per-operation `console.log` on. Off by
   * default: a differential run executes the same scenario twice, and each FHE
   * op logs a line.
   */
  logOps?: boolean;
}

/**
 * The bootstrapped mock CoFHE coprocessor, plus the accessors the differential
 * runner needs.
 */
export interface MockEnvironment {
  hre: HardhatRuntimeEnvironment;
  taskManager: Contract;
  acl: Contract;
  zkVerifier: Contract;
  thresholdNetwork: Contract;
  /** Default ACP revoker, linked into the ACL (new in mock-contracts 0.7.0). */
  acpTimestampRevoker: Contract;
  /** On-chain ACP sharing registry, linked into the ACL (new in 0.7.0). */
  acpShareRegistry: Contract;

  /** Plaintext behind a handle, or `null` when the mock has never stored one. */
  getPlaintext(handle: Handle): Promise<bigint | null>;
  /** `MockACL.isAllowed(handle, account)`, via the TaskManager facade. */
  isAllowed(handle: Handle, account: string): Promise<boolean>;
  /**
   * Mint one encrypted input the way the real ZK verifier would.
   *
   * `consumingContract` is the contract that will call `FHE.asEuintXX` on the
   * handle — mock-contracts 0.7.0 binds the signature to it, so an input signed
   * for one contract is rejected by any other. In the differential harness that
   * is `ctx.address`, which differs per side, so each run must mint its own.
   */
  encryptInput(
    value: bigint | number | boolean,
    type: EncryptedTypeName,
    sender: string,
    consumingContract: string,
    securityZone?: number
  ): Promise<EncryptedInput>;
  /** Mint several inputs under one batch signature. See `EncryptedInputBatch`. */
  encryptInputs(
    specs: EncryptedInputSpec[],
    sender: string,
    consumingContract: string
  ): Promise<EncryptedInputBatch>;
  /** Toggle the mock coprocessor's per-operation logging. */
  setLogOps(enabled: boolean): Promise<void>;
}

/** Normalise a `bytes32` handle (ethers decodes `euint32` as a hex string). */
export function toHandle(handle: Handle): bigint {
  return typeof handle === 'bigint' ? handle : BigInt(handle);
}

/**
 * Fail fast if a `@cofhe/mock-contracts` bump rotates the hard-coded mock keys.
 */
export function assertMockConstants(): void {
  const zk = new Wallet(ZK_VERIFIER_SIGNER_PRIVATE_KEY).address;
  if (zk.toLowerCase() !== ZK_VERIFIER_SIGNER_ADDRESS.toLowerCase()) {
    throw new Error(
      `ZK verifier signer key/address mismatch: key derives ${zk}, expected ${ZK_VERIFIER_SIGNER_ADDRESS}. ` +
        'Re-read MockCoFHE.sol in @cofhe/mock-contracts.'
    );
  }
  const dec = new Wallet(DECRYPT_RESULT_SIGNER_PRIVATE_KEY).address;
  if (dec.toLowerCase() !== DECRYPT_RESULT_SIGNER_ADDRESS.toLowerCase()) {
    throw new Error(
      `Decrypt-result signer key/address mismatch: key derives ${dec}, expected ${DECRYPT_RESULT_SIGNER_ADDRESS}. ` +
        'Re-read MockCoFHE.sol in @cofhe/mock-contracts.'
    );
  }
  if (MockTaskManagerArtifact.isFixed && MockTaskManagerArtifact.fixedAddress !== TASK_MANAGER_ADDRESS) {
    throw new Error(
      `MockTaskManager fixed address ${MockTaskManagerArtifact.fixedAddress} != FHE.sol TASK_MANAGER_ADDRESS ${TASK_MANAGER_ADDRESS}.`
    );
  }
  if (MockZkVerifierArtifact.isFixed && MockZkVerifierArtifact.fixedAddress !== ZK_VERIFIER_ADDRESS) {
    throw new Error(
      `MockZkVerifier fixed address ${MockZkVerifierArtifact.fixedAddress} != ZK_VERIFIER_ADDRESS ${ZK_VERIFIER_ADDRESS}.`
    );
  }
}

/**
 * Install a mock contract.
 *
 * ABI and bytecode come from Hardhat's own artifact registry, which is why
 * `contracts/mocks/CofheMocksImports.sol` exists: `@cofhe/mock-contracts` >= 0.5
 * ships Solidity sources and ABIs but no bytecode, and compiling the mocks into
 * this project also lets Hardhat decode reverts raised inside them.
 *
 * Contracts whose address is baked into `FHE.sol` (the TaskManager) or into the
 * SDK (ZkVerifier, ThresholdNetwork) are installed with `hardhat_setCode`, which
 * ignores both the constructor and EIP-170. The rest have no fixed address —
 * the ACL has a meaningful constructor (it sets up its EIP-712 domain
 * separator) — so they are deployed normally and linked in afterwards.
 */
async function installMock(hre: HardhatRuntimeEnvironment, artifact: MockArtifact): Promise<Contract> {
  const hardhatArtifact = await hre.artifacts.readArtifact(artifact.contractName);

  if (artifact.isFixed) {
    await hre.network.provider.send('hardhat_setCode', [artifact.fixedAddress, hardhatArtifact.deployedBytecode]);
    return (await hre.ethers.getContractAt(hardhatArtifact.abi, artifact.fixedAddress)) as unknown as Contract;
  }

  const [signer] = await hre.ethers.getSigners();
  const factory = new hre.ethers.ContractFactory(hardhatArtifact.abi, hardhatArtifact.bytecode, signer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  return contract as unknown as Contract;
}

async function assertExists(contract: Contract, name: string): Promise<void> {
  if (!(await contract.exists())) {
    throw new Error(`${name} did not install correctly (exists() returned false)`);
  }
}

/**
 * The mock bootstrap ritual, transcribed from `@cofhe/hardhat-plugin@0.7.0`
 * (`src/deploy.ts` + `src/utils.ts`). The order matters: the ACP contracts must
 * be linked into the ACL and the ACL into the TaskManager before any FHE op
 * runs, and the verifier signers must be set before any encrypted input is
 * submitted.
 */
export async function deployMockEnvironment(
  hre: HardhatRuntimeEnvironment,
  options: DeployMocksOptions = {}
): Promise<MockEnvironment> {
  assertMockConstants();

  const [deployer] = await hre.ethers.getSigners();

  // 1. MockTaskManager at the address FHE.sol hard-codes, then initialise it
  //    (setCode does not run constructors, so ownership must be set by hand).
  const taskManager = await installMock(hre, MockTaskManagerArtifact);
  await (await taskManager.initialize(deployer.address)).wait();
  await assertExists(taskManager, 'MockTaskManager');

  // 2. MockACL: real deployment, so its EIP-712 domain separator is built.
  const acl = await installMock(hre, MockACLArtifact);
  await assertExists(acl, 'MockACL');

  // 3. ACP infrastructure, new in mock-contracts 0.7.0 (permits became
  //    scoped, revocable ACPs). Both are plain deployments the ACL points at:
  //    the revoker answers `disabled(issuer, id)` during ACP validation, and
  //    the registry is the on-chain hand-off for shared ACPs. Neither is on the
  //    FHE-op path, but leaving either unset makes any ACP-authenticated read
  //    revert inside the ACL.
  const acpTimestampRevoker = await installMock(hre, ACPTimestampRevokerArtifact);
  await (await acl.setDefaultRevokerContract(await acpTimestampRevoker.getAddress())).wait();

  const acpShareRegistry = await installMock(hre, ACPShareRegistryArtifact);
  await (await acl.setShareRegistry(await acpShareRegistry.getAddress())).wait();

  // 4. Link. Without this every FHE op reverts inside the TaskManager.
  await (await taskManager.setACLContract(await acl.getAddress())).wait();

  // 5. Input- and decrypt-signature authorities. A zero address here disables
  //    signature checking entirely, which would silently weaken the harness.
  await (await taskManager.setVerifierSigner(ZK_VERIFIER_SIGNER_ADDRESS)).wait();
  await (await taskManager.setDecryptResultSigner(DECRYPT_RESULT_SIGNER_ADDRESS)).wait();

  // 6. Fund the ZK verifier signer (the SDK sends transactions from it).
  await hre.network.provider.send('hardhat_setBalance', [
    ZK_VERIFIER_SIGNER_ADDRESS,
    '0x' + hre.ethers.parseEther('10').toString(16),
  ]);

  // 7. MockZkVerifier and MockThresholdNetwork at their fixed addresses.
  const zkVerifier = await installMock(hre, MockZkVerifierArtifact);
  await assertExists(zkVerifier, 'MockZkVerifier');

  const thresholdNetwork = await installMock(hre, MockThresholdNetworkArtifact);
  await (await thresholdNetwork.initialize(TASK_MANAGER_ADDRESS, await acl.getAddress())).wait();
  await assertExists(thresholdNetwork, 'MockThresholdNetwork');

  const setLogOps = async (enabled: boolean) => {
    await (await taskManager.setLogOps(enabled)).wait();
  };

  // 8. Silence the coprocessor's per-op logging unless asked for.
  await setLogOps(options.logOps === true);

  /**
   * Mint ct hashes for a batch and sign the batch digest.
   *
   * `MockTaskManager.extractBatchSigner` (0.7.0) rebuilds, per input,
   *   h_i = keccak256(abi.encodePacked(
   *           uint256 ctHash, uint8 utype, uint8 securityZone,
   *           address sender, uint256 block.chainid, address consumingContract))
   * and recovers the signer from `keccak256(h_0 || h_1 || ... || h_n)` with a
   * raw `ECDSA.recover` — no EIP-191 prefix, so the digest is signed directly.
   *
   * `consumingContract` is `msg.sender` as seen by `batchVerifyInputs`, i.e.
   * the contract whose code runs `FHE.asEuintXX`; `sender` is `msg.sender` as
   * seen by that contract, i.e. the account sending the transaction.
   */
  const mintBatch = async (
    specs: EncryptedInputSpec[],
    sender: string,
    consumingContract: string
  ): Promise<{ inputs: Array<{ ctHash: bigint; utype: number; securityZone: number }>; signature: string }> => {
    const chainId = (await hre.ethers.provider.getNetwork()).chainId;

    const inputs: Array<{ ctHash: bigint; utype: number; securityZone: number }> = [];
    for (const spec of specs) {
      const utype = UTYPE[spec.type];
      const securityZone = spec.securityZone ?? 0;
      const raw = typeof spec.value === 'boolean' ? (spec.value ? 1n : 0n) : BigInt(spec.value);

      // The ct hash depends on MockZkVerifier's internal salt, which
      // `insertCtHash` bumps. Read the hash first, then insert.
      const ctHash: bigint = await zkVerifier.zkVerifyCalcCtHash.staticCall(
        raw,
        utype,
        sender,
        securityZone,
        chainId
      );
      await (await zkVerifier.insertCtHash(ctHash, raw)).wait();

      inputs.push({ ctHash, utype, securityZone });
    }

    const messageHashes = inputs.map((input) =>
      keccak256(
        solidityPacked(
          ['uint256', 'uint8', 'uint8', 'address', 'uint256', 'address'],
          [input.ctHash, input.utype, input.securityZone, sender, chainId, consumingContract]
        )
      )
    );
    const batchDigest = keccak256(concat(messageHashes));
    const signature = new SigningKey(ZK_VERIFIER_SIGNER_PRIVATE_KEY).sign(batchDigest).serialized;

    return { inputs, signature };
  };

  const env: MockEnvironment = {
    hre,
    taskManager,
    acl,
    zkVerifier,
    thresholdNetwork,
    acpTimestampRevoker,
    acpShareRegistry,

    async getPlaintext(handle) {
      const key = toHandle(handle);
      if (!(await taskManager.inMockStorage(key))) return null;
      return BigInt(await taskManager.mockStorage(key));
    },

    async isAllowed(handle, account) {
      return taskManager.isAllowed(toHandle(handle), account);
    },

    async encryptInput(value, type, sender, consumingContract, securityZone = 0) {
      const { inputs, signature } = await mintBatch([{ value, type, securityZone }], sender, consumingContract);
      const [input] = inputs;
      return {
        handle: toBeHex(input.ctHash, 32),
        ctHash: input.ctHash,
        utype: input.utype,
        securityZone: input.securityZone,
        signature,
      };
    },

    async encryptInputs(specs, sender, consumingContract) {
      const { inputs, signature } = await mintBatch(specs, sender, consumingContract);
      return {
        handles: inputs.map((input) => toBeHex(input.ctHash, 32)),
        ctHashes: inputs.map((input) => input.ctHash),
        signature,
      };
    },

    setLogOps,
  };

  return env;
}
