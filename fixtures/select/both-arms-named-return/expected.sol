// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract BothArmsNamedReturn {
    function bothArms(ebool success, euint64 difference) external returns (euint64 res) {
        res = FHE.select(success, difference, FHE.asEuint64(0));
    }
}
