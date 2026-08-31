// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract MappingHoistedKey {
    euint32 a;
    ebool eb;
    mapping(address => euint32) balances;

    function f(address who) public {
        {
            ebool __fhe_cond_0 = eb;
            address __fhe_key_1 = who;
            euint32 __fhe_pre_2 = balances[__fhe_key_1];
            euint32 __fhe_then_3;
            {
                __fhe_then_3 = a;
            }
            balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);
            if (FHE.isInitialized(balances[__fhe_key_1])) { FHE.allowThis(balances[__fhe_key_1]); }
        }
    }
}
