// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A `view` function CAN legally call another `view`/`pure` external
// function, but `FHE.allowTransient` is itself not `view` -- it makes a
// real external call -- so inserting it here would make the generated code
// invalid Solidity (issue #96). R2 gets the same warn-only treatment R3
// already has for a `view` return (spec §8.2, §8.4), not a guessed grant
// that would not compile.
interface IPeek {
    function peek(euint32 a) external view returns (euint32);
}

contract R2View {
    IPeek other;

    function f(euint32 a) public view returns (euint32) {
        return other.peek(a);
    }
}
