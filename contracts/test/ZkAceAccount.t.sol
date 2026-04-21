// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ZkAceAccount.sol";
import "../src/IZkAceVerifier.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "account-abstraction/interfaces/PackedUserOperation.sol";

/// @dev Mock verifier that always returns a configurable result
contract MockVerifier is IZkAceVerifier {
    bool public result;

    constructor(bool result_) {
        result = result_;
    }

    function setResult(bool result_) external {
        result = result_;
    }

    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[5] memory
    ) external view override returns (bool) {
        return result;
    }
}

contract ZkAceAccountTest is Test {
    ZkAceAccount account;
    MockVerifier mockVerifier;
    IEntryPoint entryPoint;

    bytes32 constant TEST_ID_COM = bytes32(uint256(0x1234));
    uint256 constant BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function setUp() public {
        entryPoint = IEntryPoint(address(0xBEEF));
        mockVerifier = new MockVerifier(true);

        account = new ZkAceAccount(
            entryPoint,
            IZkAceVerifier(address(mockVerifier)),
            TEST_ID_COM
        );
    }

    function test_constructorSetsImmutables() public view {
        assertEq(address(account.entryPoint()), address(entryPoint));
        assertEq(address(account.verifier()), address(mockVerifier));
        assertEq(account.idCom(), TEST_ID_COM);
        assertEq(account.domainTag(), block.chainid);
        assertEq(account.zkNonce(), 0);
    }

    function test_domainTagMatchesChainId() public view {
        assertEq(account.domainTag(), block.chainid);
    }

    function test_receiveEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(account).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(account).balance, 1 ether);
    }

    function test_rejectInvalidProof() public {
        // Set mock verifier to return false
        mockVerifier.setResult(false);

        // Build a minimal encoded signature
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 txHash = uint256(keccak256(callData)) % BN254_FR_MODULUS;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [uint256(TEST_ID_COM), txHash, block.chainid, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        // Call validateUserOp as the entry point
        vm.prank(address(entryPoint));
        vm.expectRevert(ZkAceAccount.InvalidProof.selector);
        account.validateUserOp(userOp, bytes32(0), 0);
    }

    function test_rejectTxHashMismatch() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 wrongTxHash = 999; // Not matching keccak256(callData)

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [uint256(TEST_ID_COM), wrongTxHash, block.chainid, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        vm.prank(address(entryPoint));
        vm.expectRevert(); // TxHashMismatch
        account.validateUserOp(userOp, bytes32(0), 0);
    }

    function test_rejectIdComMismatch() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 txHash = uint256(keccak256(callData)) % BN254_FR_MODULUS;
        uint256 wrongIdCom = 0xDEAD;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [wrongIdCom, txHash, block.chainid, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        vm.prank(address(entryPoint));
        vm.expectRevert(); // IdComMismatch
        account.validateUserOp(userOp, bytes32(0), 0);
    }

    function test_rejectDomainMismatch() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 txHash = uint256(keccak256(callData)) % BN254_FR_MODULUS;
        uint256 wrongDomain = 999;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [uint256(TEST_ID_COM), txHash, wrongDomain, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        vm.prank(address(entryPoint));
        vm.expectRevert(); // DomainMismatch
        account.validateUserOp(userOp, bytes32(0), 0);
    }

    function test_acceptValidProof() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 txHash = uint256(keccak256(callData)) % BN254_FR_MODULUS;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [uint256(TEST_ID_COM), txHash, block.chainid, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        // Mock verifier returns true
        vm.prank(address(entryPoint));
        uint256 result = account.validateUserOp(userOp, bytes32(0), 0);
        assertEq(result, 0); // SIG_VALIDATION_SUCCESS
    }

    function test_zkNonceAdvancesOnValidProof() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 txHash = uint256(keccak256(callData)) % BN254_FR_MODULUS;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [uint256(TEST_ID_COM), txHash, block.chainid, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        assertEq(account.zkNonce(), 0, "Nonce starts at 0");

        // First call succeeds, nonce advances
        vm.prank(address(entryPoint));
        account.validateUserOp(userOp, bytes32(0), 0);
        assertEq(account.zkNonce(), 1, "Nonce advanced to 1");

        // Second call also succeeds with mock (mock always returns true).
        // With a REAL verifier, replay would fail because rp_com = H(idCom, nonce)
        // would not match the new zkNonce. The mock bypasses this check.
        vm.prank(address(entryPoint));
        account.validateUserOp(userOp, bytes32(0), 0);
        assertEq(account.zkNonce(), 2, "Nonce advanced to 2");
    }

    function test_replayRejectedByRealVerifier() public {
        // When the mock verifier returns false on a second call,
        // it simulates the real verifier rejecting a replayed proof
        // (because rp_com = H(idCom, nonce) would be stale).
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        uint256 txHash = uint256(keccak256(callData)) % BN254_FR_MODULUS;

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        uint256[5] memory pubInputs = [uint256(TEST_ID_COM), txHash, block.chainid, 0, 0];

        bytes memory sig = abi.encode(a, b, c, pubInputs);

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.callData = callData;
        userOp.signature = sig;

        // First call succeeds
        vm.prank(address(entryPoint));
        account.validateUserOp(userOp, bytes32(0), 0);

        // Simulate verifier rejection on replay (stale rp_com)
        mockVerifier.setResult(false);

        vm.prank(address(entryPoint));
        vm.expectRevert(ZkAceAccount.InvalidProof.selector);
        account.validateUserOp(userOp, bytes32(0), 0);
    }
}
