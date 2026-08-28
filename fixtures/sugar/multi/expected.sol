// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SugarMulti {
    ebool eb;
    eaddress ea;

    function setup(externalEbool flag_input, externalEaddress owner__input, bytes memory inputProof) public {
        UnsignedEncryptedInput[] memory __fhe_inputs_0 = new UnsignedEncryptedInput[](2);
        __fhe_inputs_0[0] = UnsignedEncryptedInput(uint256(externalEbool.unwrap(flag_input)), 0, Utils.EBOOL_TFHE);
        __fhe_inputs_0[1] = UnsignedEncryptedInput(uint256(externalEaddress.unwrap(owner__input)), 0, Utils.EADDRESS_TFHE);
        bytes32[] memory __fhe_hashes_1 = Impl.verifyBatchInputs(__fhe_inputs_0, inputProof);
        ebool flag = ebool.wrap(__fhe_hashes_1[0]);
        eaddress owner_ = eaddress.wrap(__fhe_hashes_1[1]);
        eb = flag;
        FHE.allowThis(eb);
        ea = owner_;
        FHE.allowThis(ea);
    }
}
