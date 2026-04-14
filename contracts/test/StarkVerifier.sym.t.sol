// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "halmos-cheatcodes/SymTest.sol";
import "../src/StarkVerifier.sol";

contract StarkVerifierSymTest is SymTest, Test {
    StarkVerifier verifier;

    function setUp() public {
        verifier = new StarkVerifier();
    }

    function check_public_input_bounds(uint64[17] memory pubInputs) public {
        // Create symbolic inputs
        uint256 p = 18446744069414584321; // Goldilocks prime
        
        // Assume one input is out of bounds
        vm.assume(pubInputs[0] >= p);
        
        bytes memory dummyProof = new bytes(32); // Create a dummy proof array
        
        bool result = verifier.verifyProof(dummyProof, pubInputs);
        // It must return false if public input is out of bounds
        assert(!result);
    }
}
