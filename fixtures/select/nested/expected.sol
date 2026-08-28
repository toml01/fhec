// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract Nested {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        {
            ebool __fhe_cond_0 = eb;
            euint32 __fhe_pre_1 = a;
            euint32 __fhe_then_5;
            {
                {
                    ebool __fhe_cond_2 = FHE.lt(__fhe_pre_1, b);
                    euint32 __fhe_pre_3 = __fhe_pre_1;
                    euint32 __fhe_then_4;
                    {
                        __fhe_then_4 = b;
                    }
                    __fhe_then_5 = FHE.select(__fhe_cond_2, __fhe_then_4, __fhe_pre_3);
                }
            }
            a = FHE.select(__fhe_cond_0, __fhe_then_5, __fhe_pre_1);
            FHE.allowThis(a);
        }
    }
}
