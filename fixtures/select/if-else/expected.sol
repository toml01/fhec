// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract IfElse {
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
            euint32 __fhe_else_3;
            {
                __fhe_else_3 = FHE.add(__fhe_pre_1, b);
            }
            a = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_else_3);
            FHE.allowThis(a);
            FHE.allowSender(a);
        }
    }
}
