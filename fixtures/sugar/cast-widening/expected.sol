// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CastWidening {
    euint8 small;
    euint32 big;

    function widen(externalEuint8 amount_input, bytes memory inputProof) public {
        euint8 amount = FHE.asEuint8(amount_input, inputProof);
        small = amount;
        FHE.allowThis(small);
        big = FHE.asEuint32(small);
        FHE.allowThis(big);
    }
}
