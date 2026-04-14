// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StarkZkAceAccount.sol";
import "../src/IStarkVerifier.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "account-abstraction/interfaces/PackedUserOperation.sol";

contract MockStarkVerifier is IStarkVerifier {
    bool public result = true;

    function setResult(bool nextResult) external {
        result = nextResult;
    }

    function verifyProof(bytes calldata, uint64[17] calldata) external view returns (bool) {
        return result;
    }
}

contract StarkZkAceAccountTest is Test {
    StarkZkAceAccount account;
    MockStarkVerifier verifier;
    IEntryPoint entryPoint;

    bytes32 constant TEST_ID_COM = hex"445a9f401ea4933db6033576fed84f2b6580d3b664e6270e55401033e4fb796f";

    function setUp() public {
        entryPoint = IEntryPoint(address(0xBEEF));
        verifier = new MockStarkVerifier();
        account = new StarkZkAceAccount(entryPoint, verifier, TEST_ID_COM);
    }

    function _signatureFor(bytes memory callData) internal view returns (bytes memory) {
        uint256 hval = uint256(keccak256(callData));
        uint64[17] memory pubInputs = [
            uint64(uint256(TEST_ID_COM) >> 192),
            uint64(uint256(TEST_ID_COM) >> 128),
            uint64(uint256(TEST_ID_COM) >> 64),
            uint64(uint256(TEST_ID_COM)),
            uint64(1),
            uint64(2),
            uint64(3),
            uint64(4),
            uint64(0),
            uint64(0),
            uint64(0),
            uint64(0),
            uint64(block.chainid),
            uint64((hval >> 192) % 18446744069414584321),
            uint64(((hval >> 128) & 0xFFFFFFFFFFFFFFFF) % 18446744069414584321),
            uint64(((hval >> 64) & 0xFFFFFFFFFFFFFFFF) % 18446744069414584321),
            uint64((hval & 0xFFFFFFFFFFFFFFFF) % 18446744069414584321)
        ];
        return abi.encode(hex"1234", pubInputs);
    }

    function _userOp(uint256 nonce, bytes memory callData, bytes memory signature)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(account);
        op.nonce = nonce;
        op.callData = callData;
        op.signature = signature;
    }

    function test_validateUserOp_acceptsValidProofAndAdvancesNonce() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        PackedUserOperation memory op = _userOp(0, callData, _signatureFor(callData));

        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(op, bytes32(uint256(1)), 0);

        assertEq(validationData, 0);
        assertEq(account.zkNonce(), 1);
    }

    function test_validateUserOp_doesNotBindToUserOpHash() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        PackedUserOperation memory op = _userOp(0, callData, _signatureFor(callData));

        vm.prank(address(entryPoint));
        account.validateUserOp(op, bytes32(uint256(1)), 0);

        vm.prank(address(entryPoint));
        account.validateUserOp(op, bytes32(uint256(2)), 0);

        assertEq(account.zkNonce(), 2, "userOpHash changes do not affect validation");
    }

    function test_validateUserOp_acceptsSameSignatureWithFreshEntryPointNonceAtAccountLayer() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        bytes memory signature = _signatureFor(callData);
        PackedUserOperation memory first = _userOp(0, callData, signature);
        PackedUserOperation memory second = _userOp(1, callData, signature);

        vm.prank(address(entryPoint));
        account.validateUserOp(first, bytes32(uint256(11)), 0);

        vm.prank(address(entryPoint));
        account.validateUserOp(second, bytes32(uint256(22)), 0);

        assertEq(account.zkNonce(), 2, "account layer alone accepts the reused proof payload");
    }

    function test_validateUserOp_rejectsTxHashMismatch() public {
        bytes memory callData = abi.encodeWithSelector(bytes4(0x12345678));
        bytes memory otherCallData = abi.encodeWithSelector(bytes4(0x87654321));
        PackedUserOperation memory op = _userOp(0, callData, _signatureFor(otherCallData));

        vm.prank(address(entryPoint));
        vm.expectRevert();
        account.validateUserOp(op, bytes32(uint256(1)), 0);
    }
}
