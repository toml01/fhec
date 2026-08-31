// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IVault {
    function push(euint32 v, uint256 tag) external;
}

// The statement after the `precondition` block starts on the same line as the
// block's closing `}`. The §2.7 materializer insertion and the §8.2 R2 grant
// then anchor at the same byte offset, and the materializer must still come
// first: the grant names the handle the materializer declares.
contract PreconditionTightBrace {
    IVault vault;
    mapping(address => bool) operators;

    function deposit(externalEuint32 amount_input, bytes memory inputProof) public {
        { require(operators[msg.sender], "not an operator"); }
        euint32 amount = FHE.asEuint32(amount_input, inputProof);if (FHE.isInitialized(amount)) { FHE.allowTransient(amount, address(vault)); }
        vault.push(amount, 1);
    }
}
