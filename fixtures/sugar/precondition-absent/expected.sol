// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Regression guard for spec §2.7: the same shape without the marker must
// keep the §2.3 body-entry conversion, byte for byte.
contract PreconditionAbsent {
    euint32 balance;
    mapping(address => mapping(address => bool)) operators;

    error UnauthorizedSpender(address owner, address spender);

    function isOperator(address owner, address spender) public view returns (bool) {
        return operators[owner][spender];
    }

    function deposit(address from, externalEuint32 amount_input, bytes memory inputProof) public {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        if (!isOperator(from, msg.sender)) revert UnauthorizedSpender(from, msg.sender);
        balance = amount;
        if (FHE.isInitialized(balance)) { FHE.allowThis(balance); }
    }
}
