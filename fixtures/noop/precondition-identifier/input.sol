// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/* Spec §2.7: `precondition` is a contextual keyword, recognized only
   immediately before `{`. Plain Solidity that spells it as an ordinary
   identifier MUST come back byte-for-byte. */

contract PreconditionIdentifier {
    uint256 public precondition;

    struct Check {
        uint256 precondition;
    }

    event Checked(uint256 precondition);

    error Unmet(uint256 precondition);

    mapping(uint256 => uint256) precondition_;

    function setPrecondition(uint256 precondition_value) external {
        precondition = precondition_value;
        precondition_[precondition] = precondition;
        emit Checked(precondition);
    }

    function readPrecondition(Check memory check) external view returns (uint256) {
        if (check.precondition == 0) revert Unmet(precondition);
        return check.precondition;
    }
}

contract PreconditionLocals {
    function compute(uint256 n) external pure returns (uint256) {
        uint256 precondition = n + 1;
        precondition = precondition * 2;
        return precondition;
    }
}

/* A statement may begin with `precondition` followed immediately by `{` and
   still be an ordinary call: `precondition{value: 1}()` passes call options
   to a function pointer. The block production must not claim it. */
contract PreconditionCallOptions {
    event Paid(uint256 amount);

    function pay() external payable {
        emit Paid(msg.value);
    }

    function callWithOptions() external {
        function() external payable precondition = this.pay;
        precondition{value: 1}();
        precondition{gas: 100000, value: 2}();
    }
}
