// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {CounterBase} from "./Base.sol";

contract ImportRewrite is CounterBase {
    function bump() public {
        total = FHE.add(total, FHE.asEuint32(1));
        FHE.allowThis(total);
    }
}
