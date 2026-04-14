mod bridge;

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;

use zk_ace_circuit::circuit::ZkAceCircuit;
use zk_ace_circuit::poseidon::poseidon_config;
use zk_ace_circuit::types::{Ctx, ZkAceWitness};
use zk_ace_circuit::witness::compute_public_inputs;
use zk_ace_prover::serialization::{keccak_to_field_element, serialize_proof_for_evm, serialize_public_inputs_for_evm};

#[derive(Serialize, Deserialize)]
pub struct WitnessInput {
    pub rev: String,        // hex-encoded 32 bytes
    pub salt: String,       // hex-encoded 32 bytes
    pub alg_id: u64,
    pub domain: u64,        // chain ID
    pub index: u64,
    pub nonce: u64,
    pub tx_hash: String,    // hex-encoded 32 bytes (keccak256 of calldata)
}

#[derive(Serialize, Deserialize)]
pub struct ProofOutput {
    pub proof: String,          // hex-encoded 256-byte Groth16 proof
    pub public_inputs: String,  // hex-encoded 160-byte public inputs
    pub id_com: String,         // hex-encoded identity commitment
    pub rp_com: String,         // hex-encoded replay-prevention commitment
}

/// Generate a ZK-ACE Groth16 proof from witness inputs.
/// The proving key must be provided as raw bytes.
#[wasm_bindgen]
pub fn generate_proof(witness_json: &str, pk_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let input: WitnessInput = serde_json::from_str(witness_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid witness JSON: {}", e)))?;

    // Deserialize proving key
    let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proving key: {}", e)))?;

    // Parse witness fields
    let rev = hex_to_field(&input.rev)?;
    let salt = hex_to_field(&input.salt)?;
    let tx_hash_bytes = hex_decode(&input.tx_hash)?;
    let mut tx_hash_arr = [0u8; 32];
    tx_hash_arr.copy_from_slice(&tx_hash_bytes);
    let tx_hash = keccak_to_field_element(&tx_hash_arr);

    let witness = ZkAceWitness {
        rev,
        salt,
        ctx: Ctx {
            alg_id: Fr::from(input.alg_id),
            domain: Fr::from(input.domain),
            index: Fr::from(input.index),
        },
        nonce: Fr::from(input.nonce),
    };

    let public_inputs = compute_public_inputs(&witness, tx_hash);
    let circuit = ZkAceCircuit::new(witness, public_inputs.clone());

    // Generate proof
    let mut rng = ark_std::rand::rngs::OsRng;
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

    // Serialize for EVM
    let proof_bytes = serialize_proof_for_evm(&proof);
    let pi_bytes = serialize_public_inputs_for_evm(&public_inputs);

    let output = ProofOutput {
        proof: hex::encode(&proof_bytes),
        public_inputs: hex::encode(&pi_bytes),
        id_com: hex::encode(&pi_bytes[0..32]),
        rp_com: hex::encode(&pi_bytes[128..160]),
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

/// Compute identity commitment off-chain.
#[wasm_bindgen]
pub fn compute_id_commitment(rev_hex: &str, salt_hex: &str, domain: u64) -> Result<String, JsValue> {
    let config = poseidon_config::<Fr>();
    let rev = hex_to_field(rev_hex)?;
    let salt = hex_to_field(salt_hex)?;
    let domain_f = Fr::from(domain);

    let id_com = zk_ace_didp::commitment::compute_id_commitment(&config, rev, salt, domain_f);

    let bytes = fr_to_bytes(id_com);
    Ok(hex::encode(bytes))
}

/// Compute target binding off-chain.
#[wasm_bindgen]
pub fn compute_target(rev_hex: &str, alg_id: u64, domain: u64, index: u64) -> Result<String, JsValue> {
    let config = poseidon_config::<Fr>();
    let rev = hex_to_field(rev_hex)?;

    let target = zk_ace_didp::commitment::compute_target(
        &config, rev, Fr::from(alg_id), Fr::from(domain), Fr::from(index),
    );

    let bytes = fr_to_bytes(target);
    Ok(hex::encode(bytes))
}

fn hex_to_field(hex_str: &str) -> Result<Fr, JsValue> {
    let bytes = hex_decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Expected 32-byte hex string"));
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn hex_decode(s: &str) -> Result<Vec<u8>, JsValue> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))
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
