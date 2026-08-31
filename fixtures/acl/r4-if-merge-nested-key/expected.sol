// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// R4 at an encrypted-branch merge (spec §8.9 "Encrypted-branch merges"): the
// reader path must bind to the merge's hoisted key temp, never to the
// author's key expression — this is the path where issue #81 found a live
// disclosure.
contract PolicyOnMerge {
    /// @custom:fhe-allow balances: account
    mapping(address account => euint32) balances;

    function maybeCredit(address other, ebool eb, euint32 v) public {
        {
            ebool __fhe_cond_0 = eb;
            address __fhe_key_1 = other;
            euint32 __fhe_pre_2 = balances[__fhe_key_1];
            euint32 __fhe_then_3;
            {
                __fhe_then_3 = v;
            }
            balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);
            if (FHE.isInitialized(balances[__fhe_key_1])) {
                FHE.allowThis(balances[__fhe_key_1]);
                if (__fhe_key_1 != address(0)) FHE.allow(balances[__fhe_key_1], __fhe_key_1);
            }
        }
    }
}
