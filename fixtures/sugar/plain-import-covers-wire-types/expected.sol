// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// A plain import brings the whole profile surface into scope, so neither the
// source type nor the generated wire type needs naming.
import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract PlainImport {
    euint64 stored;

    function deposit(externalEuint64 amount_input, bytes memory inputProof) public {
        euint64 amount = FHE.asEuint64(amount_input, inputProof);
        stored = amount;
        FHE.allowThis(stored);
        FHE.allowSender(stored);
    }

    function receiveShared(sharedEuint64 amount_shared) external {
        euint64 amount = FHE.receiveEuint64Param(amount_shared);
        stored = amount;
        FHE.allowThis(stored);
        FHE.allowSender(stored);
    }
}
