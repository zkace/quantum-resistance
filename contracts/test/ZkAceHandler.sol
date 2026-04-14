// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StarkZkAceAccount.sol";
import "../src/IStarkVerifier.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

// Dummy EntryPoint and Verifier for fuzzing
contract DummyEntryPoint is IEntryPoint {
    // Implement required IEntryPoint interface (minmal required for compilation)
    // Actually, we don't need a real EntryPoint implementation to test the Account's state changes
    // We just mock the behavior of _requireFromEntryPoint()
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external {}
    function handleAggregatedOps(UserOpsPerAggregator[] calldata opsPerAggregator, address payable beneficiary) external {}
    function getSenderAddress(bytes memory initCode) external {}
    function delegateAndRevert(address target, bytes calldata data) external {}
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce) { return 0; }
    function incrementNonce(uint192 key) external {}
    function depositTo(address account) external payable {}
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external {}
    function addStake(uint32 unstakeDelaySec) external payable {}
    function unlockStake() external {}
    function withdrawStake(address payable withdrawAddress) external {}
    function getDepositInfo(address account) external view returns (DepositInfo memory info) { return DepositInfo(0, false, 0, 0, 0); }
    function balanceOf(address account) external view returns (uint256) { return 0; }
    function getAccountNonce(address sender, uint192 key) external view returns (uint256 nonce) { return 0; }

    function getCurrentUserOpHash() external view returns (bytes32) { return bytes32(0); }
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32) { return bytes32(0); }
    // senderCreator usually returns ISenderCreator, just return address(0) casted
    function senderCreator() external view returns (ISenderCreator) { return ISenderCreator(address(0)); }
}

contract DummyStarkVerifier is IStarkVerifier {
    function verifyProof(bytes calldata proof, uint64[17] calldata pubInputs) external view returns (bool) {
        return true;
    }
}

// A harness to bypass the EntryPoint check for fuzzing state changes
// StarkZkAceAccount relies on _requireFromEntryPoint() for state-mutating functions
// We override it to allow the handler to call them directly
contract TestableStarkZkAceAccount is StarkZkAceAccount {
    constructor(IEntryPoint entryPoint_, IStarkVerifier verifier_, bytes32 idCom_)
        StarkZkAceAccount(entryPoint_, verifier_, idCom_) {}

    function _requireFromEntryPoint() internal view override {
        // Bypass for testing
    }
    
    // Helper to simulate a successful transaction which bumps zkNonce
    // In reality, this happens in _validateSignature
    function simulateValidTransaction() external {
        zkNonce++;
    }
}

contract ZkAceHandler is Test {
    TestableStarkZkAceAccount public account;
    DummyEntryPoint public entryPoint;
    DummyStarkVerifier public verifier;

    uint256 public previousNonce;
    uint256 public currentNonce;
    bool public timelockRespected = true;

    constructor() {
        entryPoint = new DummyEntryPoint();
        verifier = new DummyStarkVerifier();
        account = new TestableStarkZkAceAccount(entryPoint, verifier, bytes32(uint256(1)));
    }

    function proposeIdentityRotation(bytes32 newIdCom) public {
        account.proposeIdentityRotation(newIdCom);
    }

    function confirmIdentityRotation() public {
        uint256 unlocksAt = account.rotationUnlocksAt();
        bytes32 pendingIdCom = account.pendingIdCom();
        
        bool expectedRevert = (pendingIdCom == bytes32(0)) || (block.timestamp < unlocksAt);
        
        try account.confirmIdentityRotation() {
            if (expectedRevert) {
                timelockRespected = false; // It should have reverted!
            }
        } catch {
            // Expected to revert if timelock not met or no rotation pending
        }
    }

    function cancelIdentityRotation() public {
        account.cancelIdentityRotation();
    }

    function setPaused(bool paused) public {
        account.setPaused(paused);
    }

    function advanceTime(uint256 secondsToAdvance) public {
        // Bound the time advance to avoid excessive timestamps
        secondsToAdvance = bound(secondsToAdvance, 1, 30 days);
        vm.warp(block.timestamp + secondsToAdvance);
    }
    
    function simulateTransaction() public {
        previousNonce = account.zkNonce();
        account.simulateValidTransaction();
        currentNonce = account.zkNonce();
    }
}
