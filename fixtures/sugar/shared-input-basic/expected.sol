// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A shared input arrives as an already-verified handle its sharer directed at
// this contract, so it carries no input proof: the wire parameter is the
// `sharedEuint32` handle alone (§2.8).
contract SharedInputBasic {
    euint32 a;

    function deposit(sharedEuint32 amount_shared, uint256 tag) external {
        euint32 amount = FHE.receiveEuint32Param(amount_shared);
        a = amount;
        FHE.allowThis(a);
        FHE.allowSender(a);
        tag;
    }
}
