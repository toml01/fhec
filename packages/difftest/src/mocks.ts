import type { HardhatRuntimeEnvironment } from 'hardhat/types';
import type { Contract } from 'ethers';
import { SigningKey, Wallet, keccak256, solidityPacked } from 'ethers';

import {
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

/** Solidity `InEuintXX` / `EncryptedInput` struct, ready to pass to ethers. */
export interface EncryptedInputStruct {
  ctHash: bigint;
  securityZone: number;
  utype: number;
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

  /** Plaintext behind a handle, or `null` when the mock has never stored one. */
  getPlaintext(handle: Handle): Promise<bigint | null>;
  /** `MockACL.isAllowed(handle, account)`, via the TaskManager facade. */
  isAllowed(handle: Handle, account: string): Promise<boolean>;
  /** Build a signed `InEuintXX` the way the real ZK verifier would. */
  encryptInput(
    value: bigint | number | boolean,
    type: EncryptedTypeName,
    sender: string,
    securityZone?: number
  ): Promise<EncryptedInputStruct>;
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
 * ignores both the constructor and EIP-170. The ACL has no fixed address and a
 * meaningful constructor (it sets up its EIP-712 domain separator), so it is
 * deployed normally and linked into the TaskManager afterwards.
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
 * The mock bootstrap ritual, transcribed from `@cofhe/hardhat-plugin@0.6.1`
 * (`src/deploy.ts` + `src/utils.ts`). The order matters: the ACL must be linked
 * before any FHE op runs, and the verifier signers must be set before any
 * encrypted input is submitted.
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

  // 3. Link. Without this every FHE op reverts inside the TaskManager.
  await (await taskManager.setACLContract(await acl.getAddress())).wait();

  // 4. Input- and decrypt-signature authorities. A zero address here disables
  //    signature checking entirely, which would silently weaken the harness.
  await (await taskManager.setVerifierSigner(ZK_VERIFIER_SIGNER_ADDRESS)).wait();
  await (await taskManager.setDecryptResultSigner(DECRYPT_RESULT_SIGNER_ADDRESS)).wait();

  // 5. Fund the ZK verifier signer (the SDK sends transactions from it).
  await hre.network.provider.send('hardhat_setBalance', [
    ZK_VERIFIER_SIGNER_ADDRESS,
    '0x' + hre.ethers.parseEther('10').toString(16),
  ]);

  // 6. MockZkVerifier and MockThresholdNetwork at their fixed addresses.
  const zkVerifier = await installMock(hre, MockZkVerifierArtifact);
  await assertExists(zkVerifier, 'MockZkVerifier');

  const thresholdNetwork = await installMock(hre, MockThresholdNetworkArtifact);
  await (await thresholdNetwork.initialize(TASK_MANAGER_ADDRESS, await acl.getAddress())).wait();
  await assertExists(thresholdNetwork, 'MockThresholdNetwork');

  const setLogOps = async (enabled: boolean) => {
    await (await taskManager.setLogOps(enabled)).wait();
  };

  // 7. Silence the coprocessor's per-op logging unless asked for.
  await setLogOps(options.logOps === true);

  const env: MockEnvironment = {
    hre,
    taskManager,
    acl,
    zkVerifier,
    thresholdNetwork,

    async getPlaintext(handle) {
      const key = toHandle(handle);
      if (!(await taskManager.inMockStorage(key))) return null;
      return BigInt(await taskManager.mockStorage(key));
    },

    async isAllowed(handle, account) {
      return taskManager.isAllowed(toHandle(handle), account);
    },

    async encryptInput(value, type, sender, securityZone = 0) {
      const utype = UTYPE[type];
      const raw = typeof value === 'boolean' ? (value ? 1n : 0n) : BigInt(value);
      const chainId = (await hre.ethers.provider.getNetwork()).chainId;

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

      // MockTaskManager.extractSigner: raw ECDSA over
      // keccak256(abi.encodePacked(ctHash, utype, securityZone, sender, chainid)).
      // No EIP-191 prefix, so sign the digest directly.
      const digest = keccak256(
        solidityPacked(
          ['uint256', 'uint8', 'uint8', 'address', 'uint256'],
          [ctHash, utype, securityZone, sender, chainId]
        )
      );
      const signature = new SigningKey(ZK_VERIFIER_SIGNER_PRIVATE_KEY).sign(digest).serialized;

      return { ctHash, securityZone, utype, signature };
    },

    setLogOps,
  };

  return env;
}
