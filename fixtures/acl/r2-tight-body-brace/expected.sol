// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IVault {
    function push(euint32 v, uint256 tag) external;
}

// The first body statement starts on the `{` line, with no whitespace after
// it. The §2.3 materializer and the §8.2 R2 grant then anchor at the same
// byte offset, and the materializer must still come first.
contract R2TightBrace {
    IVault vault;

    function f(externalEuint32 amount_input, bytes memory inputProof) public {
euint32 amount = FHE.asEuint32(amount_input, inputProof);if (FHE.isInitialized(amount)) { FHE.allowTransient(amount, address(vault)); }
    vault.push(amount, 1);
    }
}
