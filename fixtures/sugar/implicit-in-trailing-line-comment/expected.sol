// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SugarImplicitInTrailingLineComment {
    euint32 a;

    function setAmount(
        externalEuint32 amount_input // note
        ,
        bytes memory inputProof
    ) external {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        a = amount;
        FHE.allowThis(a);
        FHE.allowSender(a);
    }

    function setOther(
        externalEuint32 amount_input // note €
        ,
        bytes memory inputProof
    ) external {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        a = amount;
        FHE.allowThis(a);
        FHE.allowSender(a);
    }
}
