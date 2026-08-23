// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/// Dialect twin of the canonical EncryptedCounter, extended with a cap so the
/// encrypted `if` has real work to do.
///
/// Everything the transpiler exists for is exercised here and NOTHING is done
/// by hand: `in euint32` input sugar, `+` and `<=` on encrypted values, an
/// encrypted `if`, and zero manual ACL calls — rules R1's grants must all be
/// inserted by the ACL pass.
contract EncryptedCounterDialect {
    address public owner;

    euint32 public count;
    euint32 private cap;

    error OnlyOwnerAllowed(address caller);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwnerAllowed(msg.sender);
        _;
    }

    constructor(uint32 initialValue, uint32 capValue) {
        owner = msg.sender;
        count = FHE.asEuint32(initialValue);
        FHE.allowThis(count);
        FHE.allowSender(count);
        cap = FHE.asEuint32(capValue);
        FHE.allowThis(cap);
        FHE.allowSender(cap);
    }

    function getCount() external view returns (euint32) {
        return count;
    }

    /// Capped add: the increment only lands when the new total stays within
    /// the cap. Both branches execute; the write must merge through select.
    function increment(externalEuint32 amount_input, bytes memory inputProof) external onlyOwner {
        euint32 amount = FHE.asEuint32(amount_input, inputProof);
        euint32 next = FHE.add(count, amount);
        {
            ebool __fhe_cond_0 = FHE.lte(next, cap);
            euint32 __fhe_pre_1 = count;
            euint32 __fhe_then_2;
            {
                __fhe_then_2 = next;
            }
            count = FHE.select(__fhe_cond_0, __fhe_then_2, __fhe_pre_1);
            FHE.allowThis(count);
            FHE.allowSender(count);
        }
    }

    /// Literal operand: `1` must be range-checked and trivially encrypted.
    function incrementByOne() external onlyOwner {
        count = FHE.add(count, FHE.asEuint32(1));
        FHE.allowThis(count);
        FHE.allowSender(count);
    }
}
