// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract ElseLessState {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        {
            ebool __fhe_cond_0 = eb;
            euint32 __fhe_pre_1 = a;
            euint32 __fhe_then_2;
            {
                __fhe_then_2 = b;
            }
            a = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);
            if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        }
    }
}
