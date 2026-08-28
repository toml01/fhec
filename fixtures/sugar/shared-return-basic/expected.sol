// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A shared return replaces the §8.3 R3 `allowTransient` grant: the share call
// directs the handle at the caller, so no R3 insertion is made (§2.8).
contract SharedReturnBasic {
    euint64 balance;

    function take() public returns (sharedEuint64) {
        return FHE.shareEuint64(balance, msg.sender);
    }

    function pick(bool which) external returns (sharedEuint64) {
        if (which) {
            return FHE.shareEuint64(balance, msg.sender);
        }
        return FHE.shareEuint64(balance, msg.sender);
    }
}
