// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IVault {
    function push(euint64 v) external;
    function ping(euint64 v) external returns (bytes32);
}

// R2 must own exactly the statements it rewrote (spec §8.2): owning too
// little overlaps with pass 1 (FHE9001), owning too much leaves the other
// operators of the statement unlowered.
contract R2Ownership {
    euint64 a; euint64 b; euint64 c;
    IVault vault;

    // Already granted: R2 still rewrites the argument, so it owns the statement.
    function deduped() public {
        FHE.allowTransient(FHE.add(a, b), address(vault));
        vault.push(FHE.add(a, b));
    }

    // A plain-identifier argument needs no rewrite, so pass 1 keeps the
    // statement and lowers the other operator.
    function plainArg() public returns (euint64) {
        if (FHE.isInitialized(a)) { FHE.allowTransient(a, address(vault)); }
        euint64 x = FHE.add(euint64.wrap(vault.ping(a)), b);
        euint64 __fhe_ret_0 = x;
        if (FHE.isInitialized(__fhe_ret_0)) { FHE.allowTransient(__fhe_ret_0, msg.sender); }
        return __fhe_ret_0;
    }

    // A hoisted argument sits inside a larger operator site: R2 renders that
    // whole site with the temp substituted.
    function hoistedArg() public returns (euint64) {
        euint64 __fhe_val_0 = FHE.add(a, b);
        if (FHE.isInitialized(__fhe_val_0)) { FHE.allowTransient(__fhe_val_0, address(vault)); }
        euint64 y = FHE.add(euint64.wrap(vault.ping(__fhe_val_0)), c);
        euint64 __fhe_ret_1 = y;
        if (FHE.isInitialized(__fhe_ret_1)) { FHE.allowTransient(__fhe_ret_1, msg.sender); }
        return __fhe_ret_1;
    }
}
