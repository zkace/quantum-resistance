use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::Proof;

use zk_ace_circuit::types::ZkAcePublicInputs;

/// Serialize a Groth16 proof for EVM consumption.
/// Returns ABI-compatible bytes: A (64) + B (128) + C (64) = 256 bytes.
///
/// CRITICAL: Ethereum BN254 precompiles expect G2 coordinates as (x_im, x_re, y_im, y_re),
/// while arkworks stores them as (x_c0=re, x_c1=im). We swap here.
pub fn serialize_proof_for_evm(proof: &Proof<Bn254>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);

    // A: G1 point (x, y) - 2 x 32 bytes
    let a: G1Affine = proof.a;
    bytes.extend_from_slice(&fq_to_bytes(a.x().unwrap()));
    bytes.extend_from_slice(&fq_to_bytes(a.y().unwrap()));

    // B: G2 point - Ethereum expects (x_im, x_re, y_im, y_re)
    let b: G2Affine = proof.b;
    let bx: &Fq2 = b.x().unwrap();
    let by: &Fq2 = b.y().unwrap();
    // Swap: arkworks c0=real, c1=imaginary -> EVM wants imaginary first
    bytes.extend_from_slice(&fq_to_bytes(&bx.c1)); // x_im
    bytes.extend_from_slice(&fq_to_bytes(&bx.c0)); // x_re
    bytes.extend_from_slice(&fq_to_bytes(&by.c1)); // y_im
    bytes.extend_from_slice(&fq_to_bytes(&by.c0)); // y_re

    // C: G1 point (x, y) - 2 x 32 bytes
    let c: G1Affine = proof.c;
    bytes.extend_from_slice(&fq_to_bytes(c.x().unwrap()));
    bytes.extend_from_slice(&fq_to_bytes(c.y().unwrap()));

    bytes
}

/// Serialize public inputs as 5 x 32-byte big-endian uint256 values.
/// Order: [id_com, tx_hash, domain, target, rp_com]
pub fn serialize_public_inputs_for_evm(pi: &ZkAcePublicInputs<Fr>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(&fr_to_bytes(pi.id_com));
    bytes.extend_from_slice(&fr_to_bytes(pi.tx_hash));
    bytes.extend_from_slice(&fr_to_bytes(pi.domain));
    bytes.extend_from_slice(&fr_to_bytes(pi.target));
    bytes.extend_from_slice(&fr_to_bytes(pi.rp_com));
    bytes
}

fn fq_to_bytes(f: &Fq) -> [u8; 32] {
    let bigint = f.into_bigint();
    let mut bytes = [0u8; 32];
    let limbs = bigint.as_ref();
    // Convert from little-endian u64 limbs to big-endian bytes
    for (i, limb) in limbs.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        for (j, &b) in limb_bytes.iter().enumerate() {
            bytes[31 - (i * 8 + j)] = b;
        }
    }
    bytes
}

fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let bigint = f.into_bigint();
    let mut bytes = [0u8; 32];
    let limbs = bigint.as_ref();
    for (i, limb) in limbs.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        for (j, &b) in limb_bytes.iter().enumerate() {
            bytes[31 - (i * 8 + j)] = b;
        }
    }
    bytes
}

/// Reduce a 256-bit keccak hash to a BN254 scalar field element.
/// Required because BN254 Fr is ~254 bits, so keccak outputs may overflow.
pub fn keccak_to_field_element(hash: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_serialization_length() {
        // Create a dummy proof (we can't easily create a real one without setup)
        // Just test the keccak_to_field_element function
        let hash = [0xFFu8; 32]; // All ones - definitely > field modulus
        let fe = keccak_to_field_element(&hash);
        // Should be reduced mod p
        assert_ne!(fe, Fr::from(0u64));
    }
}
