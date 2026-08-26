// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Spec §2.7: a `precondition` block may declare and assign plaintext locals.
// `cap` is scoped to the block, so the body after it cannot see the name.
contract PreconditionLocalAssign {
    euint32 balance;
    uint256 limit;

    error TooBig(uint256 requested, uint256 cap);

    function deposit(uint256 requested, externalEuint32 amount_input, bytes memory inputProof) public {
        {
            uint256 cap = limit;
            cap = cap * 2;
            if (requested > cap) revert TooBig(requested, cap);
        }
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        limit = requested;
        balance = amount;
        FHE.allowThis(balance);
        FHE.allowSender(balance);
    }
}
