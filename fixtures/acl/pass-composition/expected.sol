// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IVault { function push(euint64 v) external; }

// Cross-feature coverage: the §8.0 brace wrap, the §8.6 local-grant dedupe,
// the R1/R3 handover and the §5.2 both-arm merge all meet here. Each pass
// must compose with the others without overlapping a patch (FHE9001).
contract PassComposition {
    mapping(address => euint64) internal _bal;
    euint64 internal _total;
    IVault internal vault;

    // brace-wrap + R1 dedupe on a local, in one braceless branch
    function a(bool ok, euint64 amt) public {
        euint64 ptr = amt;
        FHE.allowThis(ptr);
        FHE.allowSender(ptr);
        if (ok) { _bal[msg.sender] = ptr;
        FHE.allowThis(_bal[msg.sender]);
        FHE.allowSender(_bal[msg.sender]);
        }
    }

    // brace-wrap + R2 + operator lowering in a braceless loop body
    function b(euint64 x, euint64 y) public {
        for (uint256 i = 0; i < 2; i++) { euint64 __fhe_val_0 = FHE.add(x, y);
        FHE.allowTransient(__fhe_val_0, address(vault));
        vault.push(__fhe_val_0);
        }
    }

    // R1 + R3 composition inside a braceless branch
    function c(bool ok, euint64 amt) public returns (euint64) {
        if (ok) { euint64 __fhe_ret_0 = _total = amt;
        FHE.allowThis(_total);
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
        }
        euint64 __fhe_ret_1 = _total;
        FHE.allowTransient(__fhe_ret_1, msg.sender);
        return __fhe_ret_1;
    }

    // encrypted if/else assigning both arms, no pre-value needed
    function d(ebool cond, euint64 p, euint64 q) public returns (euint64 r) {
        r = FHE.select(cond, p, q);
    }
}
