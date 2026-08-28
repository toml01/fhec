// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// The encrypted-if merge path must prove `msg.sender` ownership by name
// resolution, not by spelling (issue #61's bug class, found again in #70's
// follow-up review). A parameter named `msg` shadows the builtin, so
// `msg.sender` inside `shadowed` is NOT the caller and must not earn the
// sender grant; `(msg).sender` inside `parenthesized` IS still the builtin
// once parens are peeled, and must still earn it.
contract MsgShadow {
    struct Msg {
        address sender;
    }

    mapping(address => euint32) balances;

    function shadowed(Msg memory msg, ebool eb, euint32 v) public {
        {
            ebool __fhe_cond_0 = eb;
            address __fhe_key_1 = msg.sender;
            euint32 __fhe_pre_2 = balances[__fhe_key_1];
            euint32 __fhe_then_3;
            {
                __fhe_then_3 = v;
            }
            balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);
            FHE.allowThis(balances[__fhe_key_1]);
        }
    }

    function parenthesized(ebool eb, euint32 v) public {
        {
            ebool __fhe_cond_0 = eb;
            address __fhe_key_1 = (msg).sender;
            euint32 __fhe_pre_2 = balances[__fhe_key_1];
            euint32 __fhe_then_3;
            {
                __fhe_then_3 = v;
            }
            balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);
            FHE.allowThis(balances[__fhe_key_1]);
            FHE.allowSender(balances[__fhe_key_1]);
        }
    }
}
