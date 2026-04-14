// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/ZkAceVerifier.sol";
import "../src/StarkVerifier.sol";
import "../src/ZkAceAccount.sol";
import "../src/StarkZkAceAccount.sol";
import "../src/ZkAceAccountFactory.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

contract Deploy is Script {
    function run() external {
        address entryPointAddr = vm.envOr("ENTRY_POINT", address(0x0000000071727De22E5E9d8BAf0edAc6f37da032));
        bytes32 idCom = vm.envBytes32("ID_COM");

        vm.startBroadcast();

        // Deploy STARK verifier (post-quantum)
        StarkVerifier starkVerifier = new StarkVerifier();
        console.log("StarkVerifier:", address(starkVerifier));

        // Deploy Groth16 verifier (classical, fast)
        ZkAceVerifier groth16Verifier = new ZkAceVerifier();
        console.log("Groth16Verifier:", address(groth16Verifier));

        // Deploy account factory (uses Groth16 verifier for factory-created accounts)
        ZkAceAccountFactory factory = new ZkAceAccountFactory(
            IEntryPoint(entryPointAddr),
            IZkAceVerifier(address(groth16Verifier))
        );
        console.log("Factory:", address(factory));

        vm.stopBroadcast();
    }
}
