// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IZkAceVerifier {
    /// @notice Verify a Groth16 proof for ZK-ACE authorization.
    /// @param a G1 point A of the proof
    /// @param b G2 point B of the proof
    /// @param c G1 point C of the proof
    /// @param input Public inputs: [id_com, tx_hash, domain, target, rp_com]
    /// @return True if the proof is valid
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[5] memory input
    ) external view returns (bool);
}
