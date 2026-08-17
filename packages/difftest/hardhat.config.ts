import type { HardhatUserConfig } from 'hardhat/config';

import '@nomicfoundation/hardhat-ethers';
import '@nomicfoundation/hardhat-chai-matchers';
import '@nomicfoundation/hardhat-network-helpers';

/**
 * Differential-execution harness for the `fhec` transpiler.
 *
 * `contracts/mocks/CofheMocksImports.sol` pulls every `@cofhe/mock-contracts`
 * Solidity source into this project's compilation unit, so that
 * `hre.artifacts.readArtifact('MockTaskManager')` resolves and Hardhat can
 * decode reverts raised inside the mock coprocessor.
 *
 * Solc settings mirror `@cofhe/hardhat-plugin`'s own test project:
 * 0.8.28 + evmVersion cancun (CoFHE requires cancun; cofhe-contracts has a
 * 0.8.25 pragma floor).
 */
const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.28',
    settings: {
      evmVersion: 'cancun',
    },
  },
  networks: {
    hardhat: {
      // MockTaskManager is far over EIP-170. It is installed with
      // `hardhat_setCode` (which ignores the limit), but MockACL and
      // MockThresholdNetwork are deployed normally.
      allowUnlimitedContractSize: true,
    },
  },
  paths: {
    sources: 'contracts',
    tests: 'test',
  },
  mocha: {
    timeout: 120_000,
  },
};

export default config;
