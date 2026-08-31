// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CastBasic {
    ebool flag;
    euint32 amount;

    function setFlag() public {
        flag = FHE.asEbool(true);
        if (FHE.isInitialized(flag)) { FHE.allowThis(flag); }
    }

    function setAmount() public {
        amount = FHE.asEuint32(5);
        if (FHE.isInitialized(amount)) { FHE.allowThis(amount); }
    }
}
