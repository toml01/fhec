// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SimpleLocal {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        euint32 x = a;
        {
            ebool __fhe_cond_0 = eb;
            euint32 __fhe_pre_1 = x;
            euint32 __fhe_then_2;
            {
                __fhe_then_2 = b;
            }
            x = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);
        }
        a = x;
        FHE.allowThis(a);
        FHE.allowSender(a);
    }
}
