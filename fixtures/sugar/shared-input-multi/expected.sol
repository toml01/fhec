// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Several shared inputs do NOT batch: each handle was verified when it was
// shared, so each receives on its own, in source parameter order (§2.8).
contract SharedInputMulti {
    euint32 a;
    euint64 b;
    ebool flag;

    function settle(
        sharedEuint32 amount_shared,
        uint256 tag,
        sharedEuint64 total_shared,
        sharedEbool ok_shared
    ) external {
        euint32 amount = FHE.receiveEuint32Param(amount_shared);
        euint64 total = FHE.receiveEuint64Param(total_shared);
        ebool ok = FHE.receiveEboolParam(ok_shared);
        a = amount;
        FHE.allowThis(a);
        FHE.allowSender(a);
        b = total;
        FHE.allowThis(b);
        FHE.allowSender(b);
        flag = ok;
        FHE.allowThis(flag);
        FHE.allowSender(flag);
        tag;
    }
}
