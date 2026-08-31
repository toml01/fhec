// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// The bound proof is declared first, before every input that verifies against
// it. The narrow encrypted widths bind a proof like any other profile type.
contract SugarProofBinderFirst {
    euint8 small;
    euint16 mid;

    function setOne(bytes calldata proof, externalEuint8 v_input) public {
        euint8 v = FHE.asEuint8(v_input, proof);
        small = v;
        if (FHE.isInitialized(small)) { FHE.allowThis(small); }
    }

    function setBoth(
        bytes memory proof,
        externalEuint8 a_input,
        externalEuint16 b_input
    ) public {
        UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](2);
        __fhe_inputs_0[0] = UnsignedEncryptedInput(uint256(externalEuint8.unwrap(a_input)), 0, Utils.EUINT8_TFHE);
        __fhe_inputs_0[1] = UnsignedEncryptedInput(uint256(externalEuint16.unwrap(b_input)), 0, Utils.EUINT16_TFHE);
        bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, proof);
        euint8 a = euint8.wrap(__fhe_hashes_1[0]);
        euint16 b = euint16.wrap(__fhe_hashes_1[1]);
        small = a;
        if (FHE.isInitialized(small)) { FHE.allowThis(small); }
        mid = b;
        if (FHE.isInitialized(mid)) { FHE.allowThis(mid); }
    }
}
