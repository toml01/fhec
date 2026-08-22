// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract DistinctLiteralKeys {
    euint32 a;
    euint32 b;
    ebool eb;
    mapping(uint256 => euint32) byId;

    function f() public {
        {
            ebool __fhe_cond_0 = eb;
            euint32 __fhe_pre_1 = byId[1];
            euint32 __fhe_pre_2 = byId[2];
            euint32 __fhe_then_3;
            {
                __fhe_then_3 = a;
            }
            euint32 __fhe_else_4;
            {
                __fhe_else_4 = b;
            }
            byId[1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_1);
            FHE.allowThis(byId[1]);
            FHE.allowSender(byId[1]);
            byId[2] = FHE.select(__fhe_cond_0, __fhe_pre_2, __fhe_else_4);
            FHE.allowThis(byId[2]);
            FHE.allowSender(byId[2]);
        }
    }
}
