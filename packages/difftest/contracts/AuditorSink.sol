// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * Shared harness helper for the rule-R2 scenario step: receives an encrypted
 * value as an external-call argument and immediately *uses* it in an FHE
 * operation. The mock coprocessor checks operand ACL, so if the calling vault
 * failed to `FHE.allowTransient` the argument to this contract, `report`
 * reverts — which the differential runner surfaces as a revert-parity or
 * expectation divergence. Each side of a comparison gets its own instance.
 */
contract AuditorSink {
    euint64 public lastSeen;

    function report(euint64 value) external {
        lastSeen = FHE.add(value, FHE.asEuint64(0));
        FHE.allowThis(lastSeen);
    }

    function lastSeenHandle() external view returns (euint64) {
        return lastSeen;
    }
}
