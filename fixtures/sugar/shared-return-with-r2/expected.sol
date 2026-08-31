// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IVault {
    function pull(euint64 v) external returns (euint64);
}

// A shared return must never cost an ACL grant. Here the §8.2 R2 rule owns the
// `try` statement — it grants the vault transient access to the encrypted
// argument and takes over the statement's inner rendering — while the shared
// return wraps the two `return` expressions inside the clause blocks. The two
// rewrites never overlap, because the share wrap is a pair of zero-width
// insertions at the returned expression's own boundaries (§2.8).
contract SharedReturnWithR2 {
    euint64 balance;
    euint64 fallbackValue;
    IVault vault;

    function drain() public returns (sharedEuint64) {
        if (FHE.isInitialized(balance)) { FHE.allowTransient(balance, address(vault)); }
        try vault.pull(balance) returns (euint64 pulled) {
            return FHE.shareEuint64(pulled, msg.sender);
        } catch {
            return FHE.shareEuint64(fallbackValue, msg.sender);
        }
    }
}
