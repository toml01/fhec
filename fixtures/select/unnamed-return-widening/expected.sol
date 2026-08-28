// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A call to a function with an *unnamed* return parameter now carries that
// return's declared type. That widens lowering, not only the shared boundary:
// the condition below is an encrypted `if`, and the return states an R3 fact.
// Both were `Unknown` before, so both were left alone.
contract UnnamedReturnWidening {
    euint32 a;

    function cond() internal returns (ebool) {
        return FHE.lt(a, a);
    }

    function val() internal view returns (euint32) {
        return a;
    }

    function branch() public returns (euint32 out) {
        out = a;
        {
            ebool __fhe_cond_0 = cond();
            euint32 __fhe_pre_1 = out;
            euint32 __fhe_then_2;
            {
                __fhe_then_2 = val();
            }
            out = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);
        }
    }

    function ret() public returns (euint32) {
        euint32 __fhe_ret_0 = val();
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
    }
}
