// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { IERC165 } from "@openzeppelin/contracts/interfaces/IERC165.sol";
import { ERC165 } from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IFHERC20, IERC7984 } from "fhenix-confidential-contracts/contracts/interfaces/IFHERC20.sol";
import { FHERC20Utils } from "fhenix-confidential-contracts/contracts/FHERC20/utils/FHERC20Utils.sol";
import {
    FHERC20InvalidReceiver,
    FHERC20InvalidSender,
    FHERC20UnauthorizedSpender,
    FHERC20ZeroBalance,
    FHERC20UnauthorizedUseOfEncryptedAmount,
    FHERC20IncompatibleFunction
} from "fhenix-confidential-contracts/contracts/FHERC20/utils/FHERC20Errors.sol";

/**
 * @dev `.fsol` dialect version of the {IFHERC20} reference implementation.
 *
 * One concrete constructor-based contract replaces the reference's
 * FHERC20 host + FHERC20Core split, with plain storage variables instead of
 * the ERC-7201 namespaced struct (the upgradeable, namespaced-storage variant
 * stays with the plain-Solidity reference).
 *
 * Dialect syntax used below:
 * - ordinary external inputs use `in euint64`; positioned-proof inputs use
 *   `in(inputProof) euint64`;
 * - shared inputs use `in shared euint64`, and directed shared outputs use
 *   `shared(msg.sender) euint64`;
 * - a `precondition` block runs before input proof verification, so the
 *   operator check keeps its upstream position in the From overloads;
 * - the {FHESafeMath} library disappears: its checked arithmetic is written
 *   inline in `_update` with encrypted operators (`+`, `-`, `>=`) and
 *   encrypted ternaries (`cond ? a : b`), which lower to `FHE.add`/`FHE.sub`/
 *   `FHE.gte`/`FHE.select`;
 *
 * ACL policy stays fully explicit (this project builds with `acl.mode =
 * "suggest"`): FHERC20 grants balance handles to the affected account, not to
 * `msg.sender`, so the transpiler's default allowThis/allowSender insertion
 * would over-grant. Every `FHE.allowThis`/`FHE.allow` below mirrors the
 * reference 1:1.
 */
contract FHERC20 is IFHERC20, ERC165, ReentrancyGuardTransient {
    mapping(address account => euint64) private _balances;
    mapping(address holder => mapping(address spender => uint48)) private _operators;
    euint64 private _totalSupply;
    string private _name;
    string private _symbol;
    uint8 private _decimals;
    string private _contractURI;
    mapping(address account => uint32) private _indicatedBalances;
    uint32 private _indicatedTotalSupply;
    uint256 private _indicatorTick;

    uint32 private constant _INDICATOR_BASE = 79_840_000;
    uint32 private constant _INDICATOR_TRANSFER = 79_840_001;

    /// @dev Emitted when an encrypted amount `encryptedAmount` is requested for disclosure by `requester`.
    event AmountDiscloseRequested(euint64 indexed encryptedAmount, address indexed requester);

    constructor(string memory name_, string memory symbol_, uint8 decimals_, string memory contractURI_) {
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        _contractURI = contractURI_;
        _indicatorTick = decimals_ <= 4 ? 1 : 10 ** (decimals_ - 4);
    }

    // =========================================================================
    //  ERC-165
    // =========================================================================

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view override(IERC165, ERC165) returns (bool) {
        return
            interfaceId == type(IFHERC20).interfaceId ||
            interfaceId == type(IERC7984).interfaceId ||
            interfaceId == type(IERC20).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //  ERC-20 indicator (backwards-compatible view layer) — plain code,
    //  kept verbatim from the reference.
    // =========================================================================

    /// @dev Indicator of the encrypted total supply, NOT the real supply.
    function totalSupply() public view returns (uint256) {
        return uint256(_indicatedTotalSupply) * _indicatorTick;
    }

    /// @dev Indicator of the encrypted balance, NOT the real balance.
    function balanceOf(address account) public view returns (uint256) {
        return uint256(_indicatedBalances[account]) * _indicatorTick;
    }

    /// @dev Always reverts. Use {confidentialTransfer} instead.
    function transfer(address, uint256) public pure returns (bool) {
        revert FHERC20IncompatibleFunction();
    }

    /// @dev Always reverts. Use {confidentialTransferFrom} instead.
    function transferFrom(address, address, uint256) public pure returns (bool) {
        revert FHERC20IncompatibleFunction();
    }

    /// @dev Always reverts. Use {setOperator} instead.
    function approve(address, uint256) public pure returns (bool) {
        revert FHERC20IncompatibleFunction();
    }

    /// @dev Always reverts. Allowances are replaced by time-bound operators.
    function allowance(address, address) public pure returns (uint256) {
        revert FHERC20IncompatibleFunction();
    }

    /// @dev Returns `true`: {balanceOf} returns an indicator, not a real balance.
    function balanceOfIsIndicator() public pure returns (bool) {
        return true;
    }

    /// @dev The raw unit size of a single indicator tick (scales with {decimals}).
    function indicatorTick() public view returns (uint256) {
        return _indicatorTick;
    }

    /// @dev Resets the caller's indicated balance to `0` (no interaction).
    function resetIndicatedBalance() external {
        _indicatedBalances[msg.sender] = 0;
    }

    // =========================================================================
    //  IERC7984 view functions
    // =========================================================================

    function name() public view returns (string memory) {
        return _name;
    }

    function symbol() public view returns (string memory) {
        return _symbol;
    }

    function decimals() public view returns (uint8) {
        return _decimals;
    }

    function contractURI() public view returns (string memory) {
        return _contractURI;
    }

    function confidentialTotalSupply() public view returns (euint64) {
        return _totalSupply;
    }

    function confidentialBalanceOf(address account) public view returns (euint64) {
        return _balances[account];
    }

    function isOperator(address holder, address spender) public view returns (bool) {
        return holder == spender || block.timestamp <= _operators[holder][spender];
    }

    // =========================================================================
    //  IERC7984 mutative functions
    // =========================================================================

    function setOperator(address operator, uint48 until) public {
        _setOperator(msg.sender, operator, until);
    }

    /// @dev `in euint64` sugar: the lowered signature is exactly ERC-7984's
    /// (address to, externalEuint64 encryptedAmount, bytes inputProof).
    function confidentialTransfer(address to, externalEuint64 encryptedAmount_input, bytes memory inputProof) public nonReentrant returns (sharedEuint64) {
        euint64 encryptedAmount = FHE.asEuint64(encryptedAmount_input, inputProof);
        return FHE.shareEuint64(_transfer(msg.sender, to, encryptedAmount), msg.sender);
    }

    function confidentialTransfer(address to, sharedEuint64 amount_shared) external nonReentrant returns (sharedEuint64) {
        euint64 amount = FHE.receiveEuint64Param(amount_shared);
        return FHE.shareEuint64(_transfer(msg.sender, to, amount), msg.sender);
    }

    /// @dev A precondition preserves operator-check-before-proof-verification.
    function confidentialTransferFrom(
        address from,
        address to,
        externalEuint64 encryptedAmount_input
    , bytes memory inputProof) public nonReentrant returns (sharedEuint64) {
        {
            if (!isOperator(from, msg.sender)) revert FHERC20UnauthorizedSpender(from, msg.sender);
        }
        euint64 encryptedAmount = FHE.asEuint64(encryptedAmount_input, inputProof);
        return FHE.shareEuint64(_transfer(from, to, encryptedAmount), msg.sender);
    }

    function confidentialTransferFrom(
        address from,
        address to,
        sharedEuint64 amount_shared
    ) external nonReentrant returns (sharedEuint64) {
        euint64 amount = FHE.receiveEuint64Param(amount_shared);
        if (!isOperator(from, msg.sender)) revert FHERC20UnauthorizedSpender(from, msg.sender);
        return FHE.shareEuint64(_transfer(from, to, amount), msg.sender);
    }

    function confidentialTransferAndCall(
        address to,
        externalEuint64 encryptedAmount_input,
        bytes calldata inputProof,
        bytes calldata data
    ) public nonReentrant returns (sharedEuint64) {
        euint64 encryptedAmount = FHE.asEuint64(encryptedAmount_input, inputProof);
        return FHE.shareEuint64(_transferAndCall(msg.sender, to, encryptedAmount, data), msg.sender);
    }

    function confidentialTransferAndCall(
        address to,
        sharedEuint64 amount_shared,
        bytes calldata data
    ) external nonReentrant returns (sharedEuint64) {
        euint64 amount = FHE.receiveEuint64Param(amount_shared);
        return FHE.shareEuint64(_transferAndCall(msg.sender, to, amount, data), msg.sender);
    }

    /// @dev A precondition preserves operator-check-before-proof-verification.
    function confidentialTransferFromAndCall(
        address from,
        address to,
        externalEuint64 encryptedAmount_input,
        bytes calldata inputProof,
        bytes calldata data
    ) public nonReentrant returns (sharedEuint64) {
        {
            if (!isOperator(from, msg.sender)) revert FHERC20UnauthorizedSpender(from, msg.sender);
        }
        euint64 encryptedAmount = FHE.asEuint64(encryptedAmount_input, inputProof);
        return FHE.shareEuint64(_transferAndCall(from, to, encryptedAmount, data), msg.sender);
    }

    function confidentialTransferFromAndCall(
        address from,
        address to,
        sharedEuint64 amount_shared,
        bytes calldata data
    ) external nonReentrant returns (sharedEuint64) {
        euint64 amount = FHE.receiveEuint64Param(amount_shared);
        if (!isOperator(from, msg.sender)) revert FHERC20UnauthorizedSpender(from, msg.sender);
        return FHE.shareEuint64(_transferAndCall(from, to, amount, data), msg.sender);
    }

    // =========================================================================
    //  Disclosure
    // =========================================================================

    /// @dev Starts public disclosure of `encryptedAmount`. Both `msg.sender`
    /// and this contract must already have access to the handle.
    function requestDiscloseEncryptedAmount(euint64 encryptedAmount) public {
        if (!FHE.isAllowed(encryptedAmount, msg.sender))
            revert FHERC20UnauthorizedUseOfEncryptedAmount(encryptedAmount, msg.sender);

        FHE.allowPublic(encryptedAmount);
        emit AmountDiscloseRequested(encryptedAmount, msg.sender);
    }

    /// @dev Publicly discloses an encrypted value with a decryption proof.
    function discloseEncryptedAmount(
        euint64 encryptedAmount,
        uint64 cleartextAmount,
        bytes calldata decryptionProof
    ) public {
        FHE.verifyDecryptResult(encryptedAmount, cleartextAmount, decryptionProof);
        emit AmountDisclosed(encryptedAmount, cleartextAmount);
    }

    // =========================================================================
    //  Internal helpers
    // =========================================================================

    function _setOperator(address holder, address operator, uint48 until) internal {
        _operators[holder][operator] = until;
        emit OperatorSet(holder, operator, until);
    }

    function _mint(address to, euint64 amount) internal returns (euint64 transferred) {
        if (to == address(0)) revert FHERC20InvalidReceiver(address(0));
        return _update(address(0), to, amount);
    }

    function _burn(address from, euint64 amount) internal returns (euint64 transferred) {
        if (from == address(0)) revert FHERC20InvalidSender(address(0));
        return _update(from, address(0), amount);
    }

    function _transfer(address from, address to, euint64 amount) internal returns (euint64 transferred) {
        if (from == address(0)) revert FHERC20InvalidSender(address(0));
        if (to == address(0)) revert FHERC20InvalidReceiver(address(0));
        return _update(from, to, amount);
    }

    function _transferAndCall(
        address from,
        address to,
        euint64 amount,
        bytes calldata data
    ) internal returns (euint64 transferred) {
        euint64 sent = _transfer(from, to, amount);

        ebool success = FHERC20Utils.checkOnTransferReceived(msg.sender, from, to, sent, data);

        // Rejected transfers refund the full `sent` amount.
        euint64 refund = _update(to, from, FHE.select(success, FHE.asEuint64(0), sent));
        transferred = FHE.sub(sent, refund);
    }

    function _incrementIndicator(uint32 current) internal pure returns (uint32) {
        if (current == 0) return _INDICATOR_BASE + 1;
        return current + 1;
    }

    function _decrementIndicator(uint32 current) internal pure returns (uint32) {
        if (current == 0) return _INDICATOR_BASE;
        return current - 1;
    }

    /// @dev The reference's `_update`, with {FHESafeMath} inlined in dialect
    /// form. The debit leg is `trySpend`: `transferred` is `amount` only when
    /// it fully fits (0 otherwise), so the subtraction can never wrap and the
    /// credit leg can reuse `transferred` directly.
    function _update(address from, address to, euint64 amount) internal returns (euint64 transferred) {
        if (from == address(0)) {
            // Mint: FHESafeMath.tryIncrease, inlined. The first mint adopts
            // the amount handle as the supply; later mints saturate on
            // overflow and keep the old supply.
            ebool success;
            if (!FHE.isInitialized(_totalSupply)) {
                success = FHE.asEbool(true);
                _totalSupply = amount;
            } else {
                euint64 newSupply = FHE.add(_totalSupply, amount);
                success = FHE.gte(newSupply, _totalSupply);
                _totalSupply = FHE.select(success, newSupply, _totalSupply);
            }
            FHE.allowThis(_totalSupply);
            _indicatedTotalSupply = _incrementIndicator(_indicatedTotalSupply);
            transferred = FHE.select(success, amount, FHE.asEuint64(0));
        } else {
            euint64 fromBalance = _balances[from];
            if (!FHE.isInitialized(fromBalance)) revert FHERC20ZeroBalance(from);
            // FHESafeMath.trySpend, inlined: all-or-nothing debit.
            ebool success = FHE.gte(fromBalance, amount);
            transferred = FHE.select(success, amount, FHE.asEuint64(0));
            _balances[from] = FHE.sub(fromBalance, transferred);
            FHE.allowThis(_balances[from]);
            FHE.allow(_balances[from], from);
            _indicatedBalances[from] = _decrementIndicator(_indicatedBalances[from]);
        }

        if (to == address(0)) {
            // Burn: `transferred` was debited from a balance the supply is the
            // sum of, so this cannot underflow.
            _totalSupply = FHE.sub(_totalSupply, transferred);
            FHE.allowThis(_totalSupply);
            _indicatedTotalSupply = _decrementIndicator(_indicatedTotalSupply);
        } else {
            _balances[to] = FHE.add(_balances[to], transferred);
            FHE.allowThis(_balances[to]);
            FHE.allow(_balances[to], to);
            _indicatedBalances[to] = _incrementIndicator(_indicatedBalances[to]);
        }

        if (from != address(0)) FHE.allow(transferred, from);
        if (to != address(0)) FHE.allow(transferred, to);
        FHE.allowThis(transferred);

        emit Transfer(from, to, uint256(_INDICATOR_TRANSFER) * _indicatorTick);
        emit ConfidentialTransfer(from, to, transferred);
    }
}
