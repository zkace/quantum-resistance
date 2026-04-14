// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/StarkVerifier.sol";

contract StarkVerifierDifferentialTest is Test {
    StarkVerifier verifier;
    uint64[17] publicInputs;

    function setUp() public {
        verifier = new StarkVerifier();
        _loadPublicInputs();
    }

    function _loadPublicInputs() internal {
        string memory path = string.concat(vm.projectRoot(), "/contracts/test/fixtures/fuzz/pub_inputs.hex");
        string memory hexStr = vm.readFile(path);
        bytes memory b = vm.parseBytes(hexStr);
        require(b.length == 17 * 8, "Invalid pub inputs length");
        
        for (uint256 i = 0; i < 17; i++) {
            uint64 val = 0;
            for (uint256 j = 0; j < 8; j++) {
                val = (val << 8) | uint8(b[i * 8 + j]);
            }
            publicInputs[i] = val;
        }
    }

    function _loadProof(string memory name) internal view returns (bytes memory) {
        string memory path = string.concat(vm.projectRoot(), "/contracts/test/fixtures/fuzz/proof_", name, ".hex");
        string memory hexStr = vm.readFile(path);
        return vm.parseBytes(hexStr);
    }

    function test_fuzz_valid_proof() public {
        bytes memory proof = _loadProof("valid");
        bool result = verifier.verifyProof(proof, publicInputs);
        assertTrue(result, "Valid proof should pass");
    }

    function test_fuzz_tampered_trace_comm() public {
        bytes memory proof = _loadProof("trace_comm");
        vm.expectRevert();
        verifier.verifyProof(proof, publicInputs);
    }

    function test_fuzz_tampered_constr_comm() public {
        bytes memory proof = _loadProof("constr_comm");
        vm.expectRevert();
        verifier.verifyProof(proof, publicInputs);
    }

    function test_fuzz_tampered_fri_comm() public {
        bytes memory proof = _loadProof("fri_comm");
        vm.expectRevert();
        verifier.verifyProof(proof, publicInputs);
    }

    function test_fuzz_tampered_ood_digest() public {
        bytes memory proof = _loadProof("ood_digest");
        vm.expectRevert();
        verifier.verifyProof(proof, publicInputs);
    }

    function test_fuzz_tampered_pow_nonce() public {
        bytes memory proof = _loadProof("pow_nonce");
        vm.expectRevert();
        verifier.verifyProof(proof, publicInputs);
    }
}
