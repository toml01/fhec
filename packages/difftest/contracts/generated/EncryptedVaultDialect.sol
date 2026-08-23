// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

interface IAuditorSink {
    function report(euint64 value) external;
}

/// Mapping- and if-heavy dialect contract: encrypted balances keyed by
/// address, an encrypted-guarded transfer, an encrypted return (rule R3), an
/// encrypted argument to an external call (rule R2), and a view getter that
/// legitimately cannot grant (FHE4002).
contract EncryptedVaultDialect {
    mapping(address => euint64) private balances;

    error SelfTransfer();

    function deposit(externalEuint64 amount_input, bytes memory inputProof) external {
        euint64 amount = FHE.asEuint64(amount_input, inputProof);
        balances[msg.sender] = FHE.add(balances[msg.sender], amount);
        FHE.allowThis(balances[msg.sender]);
        FHE.allowSender(balances[msg.sender]);
    }

    /// Transfer under an encrypted sufficiency check. Each mapping slot must
    /// merge through select against its pre-value when the check fails.
    ///
    /// The two slot updates sit in two sequential encrypted `if`s on the same
    /// condition, not one: two syntactically different non-literal keys
    /// (`msg.sender`, `to`) inside a single encrypted `if` are exactly what
    /// spec §5.2's aliasing rule rejects (FHE3011) — the transpiler cannot
    /// prove the slots are distinct. The plaintext self-transfer guard is what
    /// makes the split sound.
    function transfer(address to, externalEuint64 amount_input, bytes memory inputProof) external {
        euint64 amount = FHE.asEuint64(amount_input, inputProof);
        if (to == msg.sender) revert SelfTransfer();
        euint64 fromBalance = balances[msg.sender];
        euint64 toBalance = balances[to];
        ebool ok = FHE.lte(amount, fromBalance);
        {
            ebool __fhe_cond_0 = ok;
            address __fhe_key_1 = msg.sender;
            euint64 __fhe_pre_2 = balances[__fhe_key_1];
            euint64 __fhe_then_3;
            {
                __fhe_then_3 = FHE.sub(fromBalance, amount);
            }
            balances[__fhe_key_1] = FHE.select(__fhe_cond_0, __fhe_then_3, __fhe_pre_2);
            FHE.allowThis(balances[__fhe_key_1]);
            FHE.allowSender(balances[__fhe_key_1]);
        }
        {
            ebool __fhe_cond_4 = ok;
            address __fhe_key_5 = to;
            euint64 __fhe_pre_6 = balances[__fhe_key_5];
            euint64 __fhe_then_7;
            {
                __fhe_then_7 = FHE.add(toBalance, amount);
            }
            balances[__fhe_key_5] = FHE.select(__fhe_cond_4, __fhe_then_7, __fhe_pre_6);
            FHE.allowThis(balances[__fhe_key_5]);
            FHE.allowSender(balances[__fhe_key_5]);
        }
    }

    /// Rule R3: non-view encrypted return needs a transient grant to the caller.
    function getBalance() external returns (euint64) {
        euint64 __fhe_ret_0 = balances[msg.sender];
        FHE.allowTransient(__fhe_ret_0, msg.sender);
        return __fhe_ret_0;
    }

    /// Rule R2: encrypted argument to an external call needs a transient grant
    /// to the callee.
    function reportBalance(address auditor) external {
        IAuditorSink __fhe_callee_0 = IAuditorSink(auditor);
        euint64 __fhe_val_1 = balances[msg.sender];
        FHE.allowTransient(__fhe_val_1, address(__fhe_callee_0));
        __fhe_callee_0.report(__fhe_val_1);
    }

    /// FHE4002 territory: a view getter cannot grant; the caller must already
    /// have access. Used by the harness probes, which read via the mocks.
    function balanceOf(address account) external view returns (euint64) {
        return balances[account];
    }
}
