// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract SugarMulti {
    ebool eb;
    eaddress ea;

    function setup(InEbool memory flag_input, InEaddress memory owner__input) public {
        ebool flag = FHE.asEbool(flag_input);
        eaddress owner_ = FHE.asEaddress(owner__input);
        eb = flag;
        FHE.allowThis(eb);
        FHE.allowSender(eb);
        ea = owner_;
        FHE.allowThis(ea);
        FHE.allowSender(ea);
    }
}
