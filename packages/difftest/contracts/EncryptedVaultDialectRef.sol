// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IAuditorSinkRef {
    function report(euint64 value) external;
}

/**
 * Hand-written reference for `contracts-dialect/EncryptedVaultDialect.fsol`.
 *
 * Written independently from the spec, NOT copied from fhec output:
 *  - §5: each guarded slot update merges through `FHE.select` against the
 *    value the slot held before the `if`;
 *  - §8.1 (R1): allowThis after every encrypted storage write, plus
 *    allowSender only where the slot's owner is provably `msg.sender`
 *    (issue #70) — `balances[msg.sender]` qualifies, `balances[to]` does
 *    not (it is keyed by the recipient, not the caller), so the transferer
 *    must NOT gain read access to the recipient's balance there;
 *  - §8.2 (R2): transient grant to the callee before the external call;
 *  - §8.3 (R3): hoist the return value, transient grant to msg.sender;
 *  - §8.4: the view getter grants nothing.
 */
contract EncryptedVaultDialectRef {
    mapping(address => euint64) private balances;

    error SelfTransfer();

    function deposit(externalEuint64 amountInput, bytes memory inputProof) external {
        euint64 amount = FHE.asEuint64(amountInput, inputProof);
        balances[msg.sender] = FHE.add(balances[msg.sender], amount);
        FHE.allowThis(balances[msg.sender]);
        FHE.allowSender(balances[msg.sender]);
    }

    function transfer(address to, externalEuint64 amountInput, bytes memory inputProof) external {
        euint64 amount = FHE.asEuint64(amountInput, inputProof);
        if (to == msg.sender) revert SelfTransfer();
        euint64 fromBalance = balances[msg.sender];
        euint64 toBalance = balances[to];
        ebool ok = FHE.lte(amount, fromBalance);

        balances[msg.sender] = FHE.select(ok, FHE.sub(fromBalance, amount), fromBalance);
        FHE.allowThis(balances[msg.sender]);
        FHE.allowSender(balances[msg.sender]);

        // Keyed by `to`, not `msg.sender`: not provably owned by the
        // transferer, so only allowThis is granted (issue #70).
        balances[to] = FHE.select(ok, FHE.add(toBalance, amount), toBalance);
        FHE.allowThis(balances[to]);
    }

    function getBalance() external returns (euint64) {
        euint64 ret = balances[msg.sender];
        FHE.allowTransient(ret, msg.sender);
        return ret;
    }

    function reportBalance(address auditor) external {
        euint64 value = balances[msg.sender];
        FHE.allowTransient(value, auditor);
        IAuditorSinkRef(auditor).report(value);
    }

    function balanceOf(address account) external view returns (euint64) {
        return balances[account];
    }
}
