// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * Hand-written reference contract for the differential harness.
 *
 * Verbatim copy of the canonical CoFHE example
 * (`cofhesdk/packages/site/snippets/EncryptedCounter.sol`) with two mechanical
 * edits only:
 *   - the `// [!region ...]` docs-site markers are dropped;
 *   - the import is quoted the same way the rest of this package quotes imports.
 *
 * Nothing else changed: the manual `FHE.allowThis` / `FHE.allowSender` pairs
 * after every encrypted storage write stay exactly where the human wrote them,
 * because reproducing them is precisely what the transpiler's ACL pass (rule R1)
 * has to prove.
 */
contract EncryptedCounterRef {
  address public owner;

  euint32 public count;
  bool public decrypted;
  uint32 public decryptedCount;

  constructor(uint32 initialValue) {
    owner = msg.sender;
    count = FHE.asEuint32(initialValue);
    FHE.allowThis(count);
    FHE.allowSender(count);
  }

  error OnlyOwnerAllowed(address caller);

  modifier onlyOwner() {
    if (msg.sender != owner) revert OnlyOwnerAllowed(msg.sender);
    _;
  }

  function getCount() external view returns (euint32) {
    return count;
  }

  function setCount(InEuint32 memory _inCount) external onlyOwner {
    count = FHE.asEuint32(_inCount);
    FHE.allowThis(count);
    FHE.allowSender(count);
    decrypted = false;
    decryptedCount = 0;
  }

  function incrementCount() external onlyOwner {
    count = FHE.add(count, FHE.asEuint32(1));
    FHE.allowThis(count);
    FHE.allowSender(count);
    decrypted = false;
    decryptedCount = 0;
  }

  function allowCountPublicly() external onlyOwner {
    FHE.allowPublic(count);
  }

  function revealCount(uint32 _decrypted, bytes memory _signature) external {
    FHE.verifyDecryptResult(count, _decrypted, _signature);
    decrypted = true;
    decryptedCount = _decrypted;
  }
}
