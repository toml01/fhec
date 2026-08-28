// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SugarImplicitInMultiline {
    euint64 a;

    function confidentialTransfer(
        address to,
        externalEuint64 amount_input,
        bytes memory inputProof
    ) external {
        euint64 amount = FHE.asEuint64(amount_input, inputProof);
        a = amount;
        FHE.allowThis(a);
        to;
    }
}
