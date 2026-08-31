// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// A struct's type must still resolve correctly at signature level (a
// parameter, or another struct's field) when the enclosing contract's own
// linearization is INCOMPLETE because it inherits an unseen/external base
// (`Ownable` here). An unseen base makes every name looked up through that
// contract's scope come back wrapped in
// `Unresolved(IncompleteInheritance { fallback })` instead of a plain file
// scope lookup — the checker must unwrap that fallback (the same way
// `Trust::encrypted_type`/`is_fhe_library` already do) rather than treat
// the wrapper itself as an unrecognized type. Getting this wrong drops the
// declared type to `Unknown`, which silently drops R1's ACL fact entirely
// (issue #92 review fix): no `allowThis`, no FHE4001, nothing.
struct D {
    euint64 bal;
}

abstract contract C is Ownable {
    struct Wrap {
        D inner;
    }

    mapping(uint256 => Wrap) w;

    function f(D storage d, euint64 v) internal {
        d.bal = v;
        if (FHE.isInitialized(d.bal)) { FHE.allowThis(d.bal); }
    }

    function g(uint256 k, euint64 v) internal {
        w[k].inner.bal = v;
        if (FHE.isInitialized(w[k].inner.bal)) { FHE.allowThis(w[k].inner.bal); }
    }
}
