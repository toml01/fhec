// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SugarBasic {
    euint32 a;

    function deposit(InEuint32 memory amount_input, uint256 tag) public {
        euint32 amount = FHE.asEuint32(amount_input);
        a = amount;
        FHE.allowThis(a);
        FHE.allowSender(a);
        tag;
    }
}
