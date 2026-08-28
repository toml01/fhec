// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract BothArmsNamedReturn {
    function bothArms(ebool success, euint64 difference) external returns (euint64 res) {
        {
            ebool __fhe_cond_0 = success;
            euint64 __fhe_then_2;
            {
                __fhe_then_2 = difference;
            }
            euint64 __fhe_else_3;
            {
                __fhe_else_3 = FHE.asEuint64(0);
            }
            res = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_else_3);
        }
    }
}
