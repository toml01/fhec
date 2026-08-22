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
 *  - §8.1 (R1): allowThis + allowSender after every encrypted storage write —
 *    note allowSender grants to the *transaction sender* even on the
 *    recipient-keyed slot; that is what R1 says, so the reference does the
 *    same;
 *  - §8.2 (R2): transient grant to the callee before the external call;
 *  - §8.3 (R3): hoist the return value, transient grant to msg.sender;
 *  - §8.4: the view getter grants nothing.
 */
contract EncryptedVaultDialectRef {
    mapping(address => euint64) private balances;

    error SelfTransfer();

    function deposit(InEuint64 memory amountInput) external {
        euint64 amount = FHE.asEuint64(amountInput);
        balances[msg.sender] = FHE.add(balances[msg.sender], amount);
        FHE.allowThis(balances[msg.sender]);
        FHE.allowSender(balances[msg.sender]);
    }

    function transfer(address to, InEuint64 memory amountInput) external {
        euint64 amount = FHE.asEuint64(amountInput);
        if (to == msg.sender) revert SelfTransfer();
        euint64 fromBalance = balances[msg.sender];
        euint64 toBalance = balances[to];
        ebool ok = FHE.lte(amount, fromBalance);

        balances[msg.sender] = FHE.select(ok, FHE.sub(fromBalance, amount), fromBalance);
        FHE.allowThis(balances[msg.sender]);
        FHE.allowSender(balances[msg.sender]);

        balances[to] = FHE.select(ok, FHE.add(toBalance, amount), toBalance);
        FHE.allowThis(balances[to]);
        FHE.allowSender(balances[to]);
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
