// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// The ERC-7984 `AndCall` parameter order: the proof sits before `data`, not
// last, so the implicit trailing-proof form cannot express it.
contract SugarProofBinderBasic {
    euint32 a;

    function transferAndCall(
        address to,
        externalEuint32 amount_input,
        bytes calldata inputProof,
        bytes calldata data
    ) public {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        a = amount;
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        to;
        data;
    }
}
