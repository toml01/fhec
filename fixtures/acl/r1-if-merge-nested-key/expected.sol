// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// The encrypted-if merge path's sender-ownership proof looks at the write's
// own top-level key (spec §8.1), matching R1's direct-write proof.
contract NestedKey {
    struct Acct {
        euint32 balance;
    }

    mapping(address => mapping(address => euint32)) m;
    mapping(address => Acct) accts;

    // The sender key is the write's own top-level key, even though an outer
    // key (`other`) is also present: still provable.
    function topLevelSenderKey(address other, ebool eb, euint32 v) public {
        {
            ebool __fhe_cond_0 = eb;
            address __fhe_key_1 = other;
            address __fhe_key_2 = msg.sender;
            euint32 __fhe_pre_3 = m[__fhe_key_1][__fhe_key_2];
            euint32 __fhe_then_4;
            {
                __fhe_then_4 = v;
            }
            m[__fhe_key_1][__fhe_key_2] = FHE.select(__fhe_cond_0, __fhe_then_4, __fhe_pre_3);
            FHE.allowThis(m[__fhe_key_1][__fhe_key_2]);
            FHE.allowSender(m[__fhe_key_1][__fhe_key_2]);
        }
    }

    // The write's own top level is the struct field, not the mapping index,
    // so it carries no owner key of its own — not provable, even though the
    // mapping underneath is sender-keyed.
    function structFieldOffSenderKey(ebool eb, euint32 v) public {
        {
            ebool __fhe_cond_0 = eb;
            address __fhe_key_1 = msg.sender;
            euint32 __fhe_pre_2 = accts[__fhe_key_1].balance;
            euint32 __fhe_then_3;
            {
                __fhe_then_3 = v;
            }
            accts[__fhe_key_1].balance = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);
            FHE.allowThis(accts[__fhe_key_1].balance);
        }
    }
}
