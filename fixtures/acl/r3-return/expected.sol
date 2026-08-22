// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract R3Return {
    euint32 a;
    euint32 b;

    function get() public returns (euint32) {
        euint32 __fhe_ret_0 = FHE.add(a, b);
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
    }
}
