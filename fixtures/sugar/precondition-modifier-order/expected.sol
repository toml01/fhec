// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Spec §2.7 execution order: modifier prelude, precondition block, input
// materializer, ordinary body, modifier postlude.
contract PreconditionModifierOrder {
    euint32 balance;
    uint256 entered;
    bool open;

    error Closed();

    modifier nonReentrant() {
        entered = 1;
        _;
        entered = 0;
    }

    function deposit(externalEuint32 amount_input, externalEuint32 fee_input, bytes memory inputProof) public nonReentrant {
        {
            if (!open) revert Closed();
        }
        UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](2);
        __fhe_inputs_0[0] = UnsignedEncryptedInput(uint256(externalEuint32.unwrap(amount_input)), 0, Utils.EUINT32_TFHE);
        __fhe_inputs_0[1] = UnsignedEncryptedInput(uint256(externalEuint32.unwrap(fee_input)), 0, Utils.EUINT32_TFHE);
        bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, inputProof);
        euint32 amount = euint32.wrap(__fhe_hashes_1[0]);
        euint32 fee = euint32.wrap(__fhe_hashes_1[1]);
        balance = FHE.add(amount, fee);
        FHE.allowThis(balance);
    }
}
