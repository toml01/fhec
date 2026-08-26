// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {FHE, ebool, euint64, sharedEbool, sharedEuint64} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {IERC7984Receiver} from "fhenix-confidential-contracts/contracts/interfaces/IERC7984Receiver.sol";

/**
 * @dev Hand-written ERC-7984 callback receiver used by the differential tests.
 * It deliberately has no dependency on either FHERC20 implementation.
 */
contract FHERC20Receiver is IERC7984Receiver {
    enum Mode {
        Accept,
        Reject,
        EmptyRevert
    }

    Mode public immutable mode;
    euint64 private _lastAmount;
    address public lastOperator;
    address public lastFrom;
    bytes32 public lastDataHash;

    constructor(Mode mode_) {
        mode = mode_;
    }

    function lastAmount() external view returns (euint64) {
        return _lastAmount;
    }

    function onConfidentialTransferReceived(
        address operator,
        address from,
        sharedEuint64 amount,
        bytes calldata data
    ) external returns (sharedEbool) {
        // Consume the directed input before selecting any callback behavior.
        euint64 received = FHE.receiveEuint64Param(amount);
        _lastAmount = received;
        FHE.allowThis(_lastAmount);
        lastOperator = operator;
        lastFrom = from;
        lastDataHash = keccak256(data);

        if (mode == Mode.EmptyRevert) {
            assembly ("memory-safe") {
                revert(0, 0)
            }
        }

        ebool accepted = FHE.asEbool(mode == Mode.Accept);
        return FHE.shareEbool(accepted, msg.sender);
    }
}
