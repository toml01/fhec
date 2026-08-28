// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// `return slot = value;` states an R1 write and an R3 return on one
// statement. R1's insertion point is R3's replacement end, so the storage
// grants must be emitted inside R3's own text (spec §8.0).
contract R1InsideR3Return {
    euint32 balance;

    function set(euint32 amount) public returns (euint32) {
        euint32 __fhe_ret_0 = balance = amount;
        FHE.allowThis(balance);
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
    }
}
