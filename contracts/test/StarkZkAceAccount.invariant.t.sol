// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./ZkAceHandler.sol";

contract StarkZkAceAccountInvariantTest is Test {
    ZkAceHandler handler;

    function setUp() public {
        handler = new ZkAceHandler();
        targetContract(address(handler));
    }

    function invariant_nonce_never_decreases() public {
        assertGe(handler.currentNonce(), handler.previousNonce());
        // Additionally check the actual contract nonce
        assertGe(handler.account().zkNonce(), handler.previousNonce());
    }

    function invariant_timelock_respected() public {
        assertTrue(handler.timelockRespected(), "Timelock was bypassed");
    }
}
