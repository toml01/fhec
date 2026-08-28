// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A bodiless declaration rewrites its signature only (§2.8, §2.3 restriction
// 3): the wire types change, and no receive statement is generated.
interface ISharedInputBodiless {
    function deposit(sharedEuint32 amount) external;

    function peek() external returns (sharedEuint64);
}

abstract contract SharedInputBodiless {
    function withdraw(
        sharedEuint64 amount,
        uint256 tag
    ) external virtual returns (sharedEuint64);
}
