// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract EncryptedCounter {
    address public owner;
    euint32 count;
    ebool frozen;

    error OnlyOwnerAllowed(address caller);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwnerAllowed(msg.sender);
        _;
    }

    constructor(uint32 initialValue) {
        owner = msg.sender;
        count = FHE.asEuint32(initialValue);
        FHE.allowThis(count);
        FHE.allowSender(count);
        frozen = FHE.asEbool(false);
        FHE.allowThis(frozen);
    }

    function getCount() external view returns (euint32) {
        return count;
    }

    function setCount(externalEuint32 next_input, bytes memory inputProof) external onlyOwner {
        euint32 next = FHE.asEuint32(next_input, inputProof);
        count = next;
        FHE.allowThis(count);
    }

    function incrementBy(externalEuint32 amount_input, bytes memory inputProof) external onlyOwner {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        euint32 next = FHE.add(count, amount);
        {
            ebool __fhe_cond_0 = frozen;
            euint32 __fhe_pre_1 = next;
            euint32 __fhe_then_2;
            {
                __fhe_then_2 = count;
            }
            next = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);
        }
        count = next;
        FHE.allowThis(count);
    }

    function take() external onlyOwner returns (euint32) {
        euint32 __fhe_ret_0 = count;
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
    }
}
