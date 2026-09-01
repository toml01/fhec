// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// R5 with an INCOMPLETE linearization (spec §8.10, issue #104): `Token`
// inherits the policy-carrying interface AND an unseen external base
// (`Ownable`) that precedes the interface in C3 lookup order, so each
// `emit`'s name lookup degrades to `Unresolved(IncompleteInheritance)`
// instead of the event. The true declaration's policy cannot be read from
// there — the fallback is not a resolution, and inserting grants from it
// would be a guess — so R5 inserts nothing and MUST warn with FHE4015
// instead of staying silent: the author's stated grants for `from`/`to`
// are not transcribed, and nothing else would say so. The plaintext-only
// `PlainMoved` emit resolves through the same degraded lookup but stays
// silent: no encrypted argument means no policy could matter there (§8.2's
// conservative under-grant principle).
interface IERC7984 {
    /// @custom:fhe-allow amount: from, to
    event ConfidentialTransfer(address indexed from, address indexed to, euint64 indexed amount);

    event PlainMoved(address indexed from, address indexed to);
}

abstract contract Token is IERC7984, Ownable {
    function transfer(address from, address to, euint64 amount) public {
        emit ConfidentialTransfer(from, to, amount);
    }

    function move(address from, address to) public {
        emit PlainMoved(from, to);
    }
}
