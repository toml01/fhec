// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Spec §2.7: a `precondition` block may declare plaintext locals and assign
// them as a whole, including a reference-typed local it only rebinds. `cap`
// is scoped to the block, so the body after it cannot see the name.
contract PreconditionLocalAssign {
    euint32 balance;
    uint256 limit;
    uint256[] bounds;

    error TooBig(uint256 requested, uint256 cap);

    function deposit(uint256 requested, externalEuint32 amount_input, bytes memory inputProof) public {
        {
            uint256[] memory window;
            window = bounds;
            uint256 cap = limit;
            if (window.length > 0) cap = window[0];
            cap = cap * 2;
            if (requested > cap) revert TooBig(requested, cap);
        }
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        limit = requested;
        balance = amount;
        if (FHE.isInitialized(balance)) { FHE.allowThis(balance); }
    }
}
