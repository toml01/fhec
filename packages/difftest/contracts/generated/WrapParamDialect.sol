// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/// Regression pair for issue #103 (the MockFHESafeMath shape): a
/// `.wrap`-derived zero sentinel passed through a function parameter and then
/// written to storage. The wrap sits at the call site, one frame away from
/// the write, so the transpiler cannot see it statically — it must guard the
/// inserted grants with `FHE.isInitialized` so `reset` executes instead of
/// reverting with `SenderNotAllowed`. Zero manual ACL calls here: every grant
/// and every guard must come from the ACL pass.
contract WrapParamDialect {
    euint64 public spent;

    /// The reported gap: wrap at the call site, write in the callee.
    function reset() external {
        _store(euint64.wrap(bytes32(0)));
    }

    /// The initialized path: the same write must still receive its grant.
    function bump(uint64 v) external {
        _store(FHE.asEuint64(v));
    }

    /// Rule R3 on a handle that may be the zero sentinel: the transient
    /// grant must be guarded too, or this reverts right after `reset`.
    function getSpent() external returns (euint64) {
        euint64 __fhe_ret_0 = spent;
        if (FHE.isInitialized(__fhe_ret_0)) { FHE.allowTransient(__fhe_ret_0, msg.sender); }
        return __fhe_ret_0;
    }

    function _store(euint64 sp) private {
        spent = sp;
        if (FHE.isInitialized(spent)) { FHE.allowThis(spent); }
    }
}
