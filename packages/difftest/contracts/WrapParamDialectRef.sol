// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/// Hand-written reference twin of `WrapParamDialect` (issue #103).
///
/// Written independently of the transpiler's output, the way the reference
/// corpus guards this hazard by hand: every grant on a handle that may be the
/// uninitialized zero sentinel sits behind `FHE.isInitialized`, because the
/// TaskManager's `allow` reverts on a handle nobody holds permission on.
contract WrapParamDialectRef {
    euint64 public spent;

    function reset() external {
        _store(euint64.wrap(bytes32(0)));
    }

    function bump(uint64 v) external {
        _store(FHE.asEuint64(v));
    }

    function getSpent() external returns (euint64) {
        euint64 ret = spent;
        if (FHE.isInitialized(ret)) {
            FHE.allowTransient(ret, msg.sender);
        }
        return ret;
    }

    function _store(euint64 sp) private {
        spent = sp;
        if (FHE.isInitialized(spent)) {
            FHE.allowThis(spent);
        }
    }
}
