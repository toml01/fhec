// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SugarBasic {
    euint32 a;

    function deposit(externalEuint32 amount_input, uint256 tag, bytes memory inputProof) public {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        a = amount;
        FHE.allowThis(a);
        FHE.allowSender(a);
        tag;
    }
}
