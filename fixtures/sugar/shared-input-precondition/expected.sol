// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A shared input is a dialect-managed encrypted input, so it may be guarded by
// a `precondition` block (§2.7): the receive moves after the block, and an
// unauthorized caller reverts with the contract's own error.
contract SharedInputPrecondition {
    mapping(address => euint64) balances;
    address owner;

    error NotOwner();

    function deposit(sharedEuint64 amount_shared) external {
        {
            if (msg.sender != owner) revert NotOwner();
        }
        euint64 amount = FHE.receiveEuint64Param(amount_shared);
        balances[msg.sender] = amount;
        FHE.allowThis(balances[msg.sender]);
        FHE.allowSender(balances[msg.sender]);
    }
}
