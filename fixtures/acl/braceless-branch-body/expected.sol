// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IVault {
    function push(euint32 v) external;
}

// A grant written next to the lone body of a branch would change control
// flow: R2/R3 insert before the statement and would become the body, R1
// inserts after it and would run unconditionally. Spec §8.0 braces the pair.
contract BracelessBranchBody {
    mapping(address => euint32) internal _bal;
    IVault vault;

    // R2 — the guarded call must stay guarded.
    function r2(bool notPaused, euint32 a) public {
        if (notPaused) { FHE.allowTransient(a, address(vault));
        vault.push(a);
        }
    }

    // R1 — both grants must stay inside the branch.
    function r1(bool ok, euint32 amt) public {
        if (ok) { _bal[msg.sender] = amt;
        FHE.allowThis(_bal[msg.sender]);
        FHE.allowSender(_bal[msg.sender]);
        }
    }

    // R1 in an `else`, and in a loop body.
    function r1Else(bool ok, euint32 amt) public {
        if (ok) { _bal[msg.sender] = amt;
        FHE.allowThis(_bal[msg.sender]);
        FHE.allowSender(_bal[msg.sender]);
        }
        else { _bal[msg.sender] = amt;
        FHE.allowThis(_bal[msg.sender]);
        FHE.allowSender(_bal[msg.sender]);
        }
    }

    function r1Loop(euint32 amt) public {
        for (uint256 i = 0; i < 2; i++) { _bal[msg.sender] = amt;
        FHE.allowThis(_bal[msg.sender]);
        FHE.allowSender(_bal[msg.sender]);
        }
    }

    function r1While(bool ok, euint32 amt) public {
        while (ok) { _bal[msg.sender] = amt;
        FHE.allowThis(_bal[msg.sender]);
        FHE.allowSender(_bal[msg.sender]);
        }
    }

    // R3 — the hoisted return declaration needs the block too.
    function r3(bool ok) public returns (euint32) {
        if (ok) { euint32 __fhe_ret_0 = _bal[msg.sender];
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
        }
        euint32 __fhe_ret_1 = _bal[msg.sender];
        FHE.allowTransient(__fhe_ret_1, msg.sender);
        return __fhe_ret_1;
    }

    // Already granted: §8.6 suppresses the insertion, so §1.4 must hold and
    // no braces may appear.
    function alreadyGranted(bool notPaused, euint32 a) public {
        if (notPaused) { FHE.allowTransient(a, address(vault)); vault.push(a); }
    }
}
