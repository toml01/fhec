// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {
    FHE,
    euint64,
    externalEuint64,
    sharedEuint64
} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IFHERC20, IERC7984} from "fhenix-confidential-contracts/contracts/interfaces/IFHERC20.sol";

/** @dev Creates deliberately malformed directed-share handoffs in one transaction. */
contract FHERC20SharedHelper {
    function reshare(sharedEuint64 incoming, address recipient) external returns (sharedEuint64) {
        euint64 amount = FHE.receiveEuint64Param(incoming);
        return FHE.shareEuint64(amount, recipient);
    }

    function consume(sharedEuint64 incoming) external {
        euint64 amount = FHE.receiveEuint64Param(incoming);
        FHE.allowThis(amount);
    }
}

/**
 * @dev Hand-written driver for all four IERC7984 shared-input overloads.
 * External inputs are consumed by this contract, shared to its paired token,
 * and successful directed results are received and persisted for probes.
 */
contract FHERC20SharedDriver {
    IERC7984 public immutable token;
    FHERC20SharedHelper public immutable helper;
    euint64 private _lastResult;

    constructor(IERC7984 token_) {
        token = token_;
        helper = new FHERC20SharedHelper();
    }

    function lastResult() external view returns (euint64) {
        return _lastResult;
    }

    function driverBalance() external view returns (euint64) {
        return token.confidentialBalanceOf(address(this));
    }

    function tokenBalanceOf(address account) external view returns (euint64) {
        return token.confidentialBalanceOf(account);
    }

    function tokenTotalSupply() external view returns (euint64) {
        return token.confidentialTotalSupply();
    }

    function driverIsOperator(address holder) external view returns (bool) {
        return token.isOperator(holder, address(this));
    }

    function transferShared(
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        sharedEuint64 result = token.confidentialTransfer(to, FHE.shareEuint64(amount, address(token)));
        _persist(result);
    }

    function transferFromShared(
        address from,
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        sharedEuint64 result = token.confidentialTransferFrom(from, to, FHE.shareEuint64(amount, address(token)));
        _persist(result);
    }

    function transferAndCallShared(
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof,
        bytes calldata data
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        sharedEuint64 result = token.confidentialTransferAndCall(
            to,
            FHE.shareEuint64(amount, address(token)),
            data
        );
        _persist(result);
    }

    function transferFromAndCallShared(
        address from,
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof,
        bytes calldata data
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        sharedEuint64 result = token.confidentialTransferFromAndCall(
            from,
            to,
            FHE.shareEuint64(amount, address(token)),
            data
        );
        _persist(result);
    }

    function transferFromMissingShare(
        address from,
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        token.confidentialTransferFrom(from, to, sharedEuint64.wrap(euint64.unwrap(amount)));
    }

    function transferFromWrongRecipient(
        address from,
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        token.confidentialTransferFrom(from, to, FHE.shareEuint64(amount, address(helper)));
    }

    function transferFromAndCallWrongSharer(
        address from,
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof,
        bytes calldata data
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        sharedEuint64 wrongSharer = helper.reshare(
            FHE.shareEuint64(amount, address(helper)),
            address(token)
        );
        token.confidentialTransferFromAndCall(from, to, wrongSharer, data);
    }

    function transferWrongResultRecipient(
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external {
        euint64 amount = FHE.asEuint64(encryptedAmount, inputProof);
        sharedEuint64 result = token.confidentialTransfer(to, FHE.shareEuint64(amount, address(token)));
        // The token directed this result to the driver, not the helper.
        helper.consume(result);
    }

    function _persist(sharedEuint64 result) private {
        _lastResult = FHE.receiveEuint64FromCall(result, address(token));
        FHE.allowThis(_lastResult);
    }
}

/** @dev Recomputes the pinned interfaces' ERC-165 IDs with Solidity itself. */
contract FHERC20InterfaceIds {
    function fherc20() external pure returns (bytes4) {
        return type(IFHERC20).interfaceId;
    }

    function ierc7984() external pure returns (bytes4) {
        return type(IERC7984).interfaceId;
    }

    function ierc20() external pure returns (bytes4) {
        return type(IERC20).interfaceId;
    }
}
