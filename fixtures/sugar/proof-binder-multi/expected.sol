// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Several encrypted inputs bind one proof. The batch follows encrypted
// parameter source order, not the position of the bound proof parameter.
contract SugarProofBinderMulti {
    ebool eb;
    eaddress ea;
    euint128 ev;

    function setup(
        externalEbool flag_input,
        bytes memory proof,
        externalEaddress owner__input,
        externalEuint128 value_input,
        uint256 tag
    ) public {
        UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](3);
        __fhe_inputs_0[0] = UnsignedEncryptedInput(uint256(externalEbool.unwrap(flag_input)), 0, Utils.EBOOL_TFHE);
        __fhe_inputs_0[1] = UnsignedEncryptedInput(uint256(externalEaddress.unwrap(owner__input)), 0, Utils.EADDRESS_TFHE);
        __fhe_inputs_0[2] = UnsignedEncryptedInput(uint256(externalEuint128.unwrap(value_input)), 0, Utils.EUINT128_TFHE);
        bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, proof);
        ebool flag = ebool.wrap(__fhe_hashes_1[0]);
        eaddress owner_ = eaddress.wrap(__fhe_hashes_1[1]);
        euint128 value = euint128.wrap(__fhe_hashes_1[2]);
        eb = flag;
        if (FHE.isInitialized(eb)) { FHE.allowThis(eb); }
        ea = owner_;
        if (FHE.isInitialized(ea)) { FHE.allowThis(ea); }
        ev = value;
        if (FHE.isInitialized(ev)) { FHE.allowThis(ev); }
        tag;
    }
}
