// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * Deliberately wrong twins of `EncryptedCounterRef`.
 *
 * These exist so the harness can prove it *detects* divergence. Each one is
 * ABI-identical to the reference and differs by a single line, modelling one of
 * the two failure modes the transpiler is most likely to produce.
 *
 * They are never expected to pass a differential comparison. The test suite
 * asserts that comparing them against the reference FAILS.
 */

/// Wrong constant: increments by 2 instead of 1.
/// Models a codegen bug in the operator-lowering pass. Detected by the
/// plaintext probes (axis A).
contract EncryptedCounterWrongConstant {
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
    // BUG (intentional): the reference adds 1.
    count = FHE.add(count, FHE.asEuint32(2));
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

/// Missing ACL grant: `FHE.allowSender` is dropped from `incrementCount`.
/// Models an under-grant bug in the ACL inference pass (rule R1). Plaintexts
/// stay identical, so only the `isAllowed` probes (axis B) can catch it.
contract EncryptedCounterMissingAcl {
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
    // BUG (intentional): the reference also calls FHE.allowSender(count) here.
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
