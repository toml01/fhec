// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// R5 with `global` mixed into an ordinary reader list (spec §8.8, §8.10,
// issue #106): unlike `public`, `global` is an ordinary list member — it
// widens computation without disclosing the value, so the rest of the list
// still states who may read it. `this` produces no second call, `global`
// renders unguarded in its list position, and `from` keeps the §8.9
// zero-address guard.
contract GlobalDeposit {
    /// @custom:fhe-allow amount: this, global, from
    event Deposited(address indexed from, euint64 amount);

    function deposit(address from, euint64 v) public {
        if (FHE.isInitialized(v)) {
            FHE.allowThis(v);
            FHE.allowGlobal(v);
            if (from != address(0)) FHE.allow(v, from);
        }
        emit Deposited(from, v);
    }
}
