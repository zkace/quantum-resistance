// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./StarkZkAceAccount.sol";
import "./IStarkVerifier.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

/// @title StarkZkAceAccountFactory — CREATE2 factory for STARK-based accounts
contract StarkZkAceAccountFactory {
    IEntryPoint public immutable entryPoint;
    IStarkVerifier public immutable verifier;

    event AccountCreated(address indexed account, bytes32 indexed idCom);

    constructor(IEntryPoint entryPoint_, IStarkVerifier verifier_) {
        entryPoint = entryPoint_;
        verifier = verifier_;
    }

    function createAccount(bytes32 idCom, uint256 salt) external returns (StarkZkAceAccount) {
        bytes32 create2Salt = keccak256(abi.encodePacked(idCom, salt));
        StarkZkAceAccount account = new StarkZkAceAccount{salt: create2Salt}(
            entryPoint, verifier, idCom
        );
        emit AccountCreated(address(account), idCom);
        return account;
    }

    function getAddress(bytes32 idCom, uint256 salt) external view returns (address) {
        bytes32 create2Salt = keccak256(abi.encodePacked(idCom, salt));
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), create2Salt,
            keccak256(abi.encodePacked(
                type(StarkZkAceAccount).creationCode,
                abi.encode(entryPoint, verifier, idCom)
            ))
        ));
        return address(uint160(uint256(hash)));
    }
}
