// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract NonSenderKey {
    euint32 a;
    mapping(address => euint32) balances;

    function f(address who) public {
        balances[who] = a;
        FHE.allowThis(balances[who]);
        FHE.allowSender(balances[who]);
    }
}
