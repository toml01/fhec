// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/* Nasty formatting corpus: comments, unicode, odd whitespace.
   The transpiler MUST reproduce this file byte-for-byte. */

contract Nasty {
	// tab-indented line, then spaces:
        uint256   public   weird ;

    string public snowman = unicode"☃ frosty — em-dash & «guillemets»";

    /* block /* not nested in solidity */
    string public tricky = "a } string { with braces // and a fake comment";

    function   spaced_out ( uint256   x )   external   pure   returns(uint256){
        unchecked { x += 1 ; }
        return x;   // trailing spaces after this comment:
    }

    // A line with only whitespace follows:

    fallback() external {}
}
