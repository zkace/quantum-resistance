// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/ZkAceAccountFactory.sol";
import "../src/ZkAceVerifier.sol";
import "../src/ZkAceAccount.sol";
import "../src/IZkAceVerifier.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "account-abstraction/core/EntryPoint.sol";

contract ZkAceAccountFactoryTest is Test {
    EntryPoint entryPoint;
    ZkAceVerifier verifier;
    ZkAceAccountFactory factory;

    bytes32 constant ID_COM_A = 0x12b7f9cb3057db4e01ceb6fa4ea933901775fec553ffc916f12de78ba12c40cc;
    bytes32 constant ID_COM_B = 0x1a2f61b4cd6650e1b7e128d4ad3712228b051dadbc836ef9f73a1784b05a4b14;

    function setUp() public {
        entryPoint = new EntryPoint();
        verifier = new ZkAceVerifier();
        factory = new ZkAceAccountFactory(
            IEntryPoint(address(entryPoint)),
            IZkAceVerifier(address(verifier))
        );
    }

    /// @notice Create account via factory and verify idCom and domainTag are correct
    function test_createAccount() public {
        ZkAceAccount account = factory.createAccount(ID_COM_A, 0);
        assertEq(account.idCom(), ID_COM_A, "idCom must match");
        assertEq(account.domainTag(), block.chainid, "domainTag must match current chain ID");
    }

    /// @notice getAddress returns the same address as createAccount
    function test_getAddressMatchesCreate() public {
        address predicted = factory.getAddress(ID_COM_A, 42);
        ZkAceAccount account = factory.createAccount(ID_COM_A, 42);
        assertEq(address(account), predicted, "getAddress must predict the CREATE2 address");
    }

    /// @notice Two different idComs produce different addresses
    function test_createDifferentIdentities() public {
        ZkAceAccount accountA = factory.createAccount(ID_COM_A, 0);
        ZkAceAccount accountB = factory.createAccount(ID_COM_B, 0);
        assertTrue(
            address(accountA) != address(accountB),
            "Different idComs must produce different addresses"
        );
        assertEq(accountA.idCom(), ID_COM_A, "Account A idCom");
        assertEq(accountB.idCom(), ID_COM_B, "Account B idCom");
    }

    /// @notice Create account via factory, fund it, verify it can receive ETH
    function test_accountFunctional() public {
        ZkAceAccount account = factory.createAccount(ID_COM_A, 99);
        vm.deal(address(account), 5 ether);
        assertEq(address(account).balance, 5 ether, "Account must be able to receive ETH");

        // Send more ETH to the account directly
        (bool success,) = address(account).call{value: 1 ether}("");
        assertTrue(success, "Account must accept ETH via receive()");
        assertEq(address(account).balance, 6 ether, "Balance updated after receiving ETH");
    }

    receive() external payable {}
}
