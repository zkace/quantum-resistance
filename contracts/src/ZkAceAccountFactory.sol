// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./ZkAceAccount.sol";
import "./IZkAceVerifier.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

contract ZkAceAccountFactory {
    IEntryPoint public immutable entryPoint;
    IZkAceVerifier public immutable verifier;

    event AccountCreated(address indexed account, bytes32 indexed idCom);

    constructor(IEntryPoint entryPoint_, IZkAceVerifier verifier_) {
        entryPoint = entryPoint_;
        verifier = verifier_;
    }

    function createAccount(bytes32 idCom, uint256 salt) external returns (ZkAceAccount) {
        bytes32 create2Salt = keccak256(abi.encodePacked(idCom, salt));
        ZkAceAccount account = new ZkAceAccount{salt: create2Salt}(
            entryPoint, verifier, idCom
        );
        emit AccountCreated(address(account), idCom);
        return account;
    }

    function getAddress(bytes32 idCom, uint256 salt) external view returns (address) {
        bytes32 create2Salt = keccak256(abi.encodePacked(idCom, salt));
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            create2Salt,
            keccak256(abi.encodePacked(
                type(ZkAceAccount).creationCode,
                abi.encode(entryPoint, verifier, idCom)
            ))
        ));
        return address(uint160(uint256(hash)));
    }
}
