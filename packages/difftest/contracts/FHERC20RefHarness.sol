// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { FHE, euint64 } from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import { FHERC20 } from "fhenix-confidential-contracts/contracts/FHERC20/FHERC20.sol";

/**
 * @dev Reference side of the FHERC20 differential pair: the UNMODIFIED
 * upstream implementation (fhenix-confidential-contracts v0.4.0), extended
 * only with the same mint/burn surface as the upstream FHERC20_Harness.
 * The dialect twin is contracts-dialect-fherc20/FHERC20Harness.fsol.
 */
contract FHERC20RefHarness is FHERC20 {
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        string memory contractURI_
    ) FHERC20(name_, symbol_, decimals_, contractURI_) {}

    function mint(address account, uint64 value) public {
        _mint(account, FHE.asEuint64(value));
    }

    function burn(address account, uint64 value) public {
        _burn(account, FHE.asEuint64(value));
    }
}
