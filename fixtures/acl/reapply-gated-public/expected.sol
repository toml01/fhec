// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Gated disclosure and re-application (spec §8.11): every write to `secret`
// carries the `if (revealed)` guard from its own R4 site, and a write to
// `revealed` re-applies the same guard for `secret`'s current handle — the
// guard evaluates false until the reveal, then true from that point on.
contract GatedReveal {
    bool revealed;

    /// @custom:fhe-allow secret: public if revealed
    euint32 secret;

    function setSecret(euint32 v) public {
        secret = v;
        if (FHE.isInitialized(secret)) {
            FHE.allowThis(secret);
            if (revealed) FHE.allowPublic(secret);
        }
    }

    function reveal() public {
        revealed = true;
        if (FHE.isInitialized(secret)) {
            FHE.allowThis(secret);
            if (revealed) FHE.allowPublic(secret);
        }
    }
}
