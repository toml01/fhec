// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract MultiWrite {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        {
            ebool __fhe_cond_0 = eb;
            euint32 __fhe_then_2;
            euint32 __fhe_then_3;
            {
                __fhe_then_2 = b;
                __fhe_then_3 = FHE.add(__fhe_then_2, FHE.asEuint32(1));
            }
            euint32 __fhe_else_4;
            {
                __fhe_else_4 = b;
            }
            a = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_else_4);
            if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        }
    }
}
