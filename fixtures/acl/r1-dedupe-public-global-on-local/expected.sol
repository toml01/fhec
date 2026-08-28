// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A broad grant on a local handle already lets this contract read the handle
// after the store. It does not replace R1's separate owner-proven sender grant.
contract BroadGrantOnLocal {
    euint64 pub;
    euint64 global;
    euint64 plain;
    mapping(address => euint64) owned;

    function viaPublic(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        FHE.allowPublic(s);
        pub = s;
    }

    function viaGlobal(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        FHE.allowGlobal(s);
        global = s;
    }

    // No existing grant: R1 must still grant the contract access.
    function control(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        plain = s;
        FHE.allowThis(plain);
    }

    // A broad grant suppresses only allowThis, not the separate sender grant.
    function senderStillInserted(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        FHE.allowPublic(s);
        owned[msg.sender] = s;
        FHE.allowSender(owned[msg.sender]);
    }

    // A broad grant before a conditional write applies only to the old handle.
    function conditionalWrite(uint64 v, uint64 replacement, bool replace) external {
        euint64 s = FHE.asEuint64(v);
        FHE.allowPublic(s);
        if (replace) {
            s = FHE.asEuint64(replacement);
        }
        pub = s;
        FHE.allowThis(pub);
    }

    // Tuple components are writes for the local-grant window too.
    function tupleWrite(uint64 v, uint64 otherV) external {
        euint64 s = FHE.asEuint64(v);
        euint64 other = FHE.asEuint64(otherV);
        FHE.allowGlobal(s);
        (s, other) = (other, s);
        global = s;
        FHE.allowThis(global);
    }

    // A same-named call through an unrelated library is not an FHE grant.
    function fakeGrant(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        FakeAcl.allowPublic(s);
        plain = s;
        FHE.allowThis(plain);
    }

    // CoFHE's encrypted-receiver bindings are genuine broad grants.
    function methodPublic(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        s.allowPublic();
        pub = s;
    }

    function methodGlobal(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        s.allowGlobal();
        global = s;
    }

    // Broad access subsumes allowThis, while this explicit sender grant is
    // already the exact owner-proven grant R1 would otherwise insert.
    function broadAndSender(uint64 v) external {
        euint64 s = FHE.asEuint64(v);
        FHE.allowGlobal(s);
        FHE.allowSender(s);
        owned[msg.sender] = s;
    }
}

library FakeAcl {
    function allowPublic(euint64) internal {}
}
