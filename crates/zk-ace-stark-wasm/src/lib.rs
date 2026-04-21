//! WASM wrapper for the ZK-ACE STARK prover.
//!
//! Provides browser-compatible bindings for:
//! - Computing Rescue-Prime identity commitments
//! - Generating STARK proofs
//! - Extracting public inputs without proof generation

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

use winterfell::math::fields::f64::BaseElement;
use winterfell::Prover;

use zk_ace_stark::prover::{
    compute_public_inputs, default_proof_options, ZkAceProver, ZkAceWitness,
};
use zk_ace_stark::rescue::rescue_hash_full;

// ---------------------------------------------------------------------------
// JSON types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WitnessInput {
    rev: String,
    salt: String,
    alg_id: u64,
    domain: u64,
    index: u64,
    nonce: u64,
    tx_hash: String,
}

#[derive(Serialize)]
struct ProofOutput {
    proof: String,
    pub_inputs: Vec<u64>,
    id_com: String,
}

#[derive(Serialize)]
struct PublicInputsOutput {
    pub_inputs: Vec<u64>,
    id_com: String,
    target: String,
    rp_com: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip optional "0x" prefix and decode hex to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, JsValue> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| JsValue::from_str(&format!("Invalid hex: {}", e)))
}

/// Parse an 8-byte (or shorter) hex string into a Goldilocks field element.
/// The value is interpreted as big-endian and reduced into the field.
fn hex_to_goldilocks(hex_str: &str) -> Result<BaseElement, JsValue> {
    let bytes = hex_decode(hex_str)?;
    if bytes.len() > 8 {
        return Err(JsValue::from_str(
            "Goldilocks field element hex must be at most 8 bytes",
        ));
    }
    // Big-endian: pad on the left to 8 bytes
    let mut buf = [0u8; 8];
    let offset = 8 - bytes.len();
    buf[offset..].copy_from_slice(&bytes);
    Ok(BaseElement::new(u64::from_be_bytes(buf)))
}

/// Parse a 32-byte tx_hash into 4 Goldilocks elements.
/// Each 8-byte chunk is read as big-endian u64.
fn tx_hash_to_elements(hex_str: &str) -> Result<[BaseElement; 4], JsValue> {
    let bytes = hex_decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("tx_hash must be exactly 32 bytes"));
    }
    let mut elems = [BaseElement::new(0); 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        elems[i] = BaseElement::new(u64::from_be_bytes(buf));
    }
    Ok(elems)
}

/// Encode 4 Goldilocks elements as a 32-byte hex string (big-endian packed).
fn elements_to_hex(elems: &[BaseElement; 4]) -> String {
    let mut be_bytes = [0u8; 32];
    for i in 0..4 {
        let val = elems[i].inner();
        be_bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_be_bytes());
    }
    format!("0x{}", hex::encode(be_bytes))
}

/// Convert public inputs to a Vec<u64> for JSON serialization (17 values).
fn pub_inputs_to_u64_vec(
    id_com: &[BaseElement; 4],
    target: &[BaseElement; 4],
    rp_com: &[BaseElement; 4],
    domain: BaseElement,
    tx_hash: &[BaseElement; 4],
) -> Vec<u64> {
    let mut v = Vec::with_capacity(17);
    for e in id_com {
        v.push(e.inner());
    }
    for e in target {
        v.push(e.inner());
    }
    for e in rp_com {
        v.push(e.inner());
    }
    v.push(domain.inner());
    for e in tx_hash {
        v.push(e.inner());
    }
    v
}

/// Parse JSON witness into structured types.
fn parse_witness(
    json: &str,
) -> Result<(ZkAceWitness, [BaseElement; 4]), JsValue> {
    let input: WitnessInput = serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("Invalid witness JSON: {}", e)))?;

    let rev = hex_to_goldilocks(&input.rev)?;
    let salt = hex_to_goldilocks(&input.salt)?;
    let tx_hash = tx_hash_to_elements(&input.tx_hash)?;

    let witness = ZkAceWitness {
        rev,
        salt,
        alg_id: BaseElement::new(input.alg_id),
        ctx_domain: BaseElement::new(input.domain),
        ctx_index: BaseElement::new(input.index),
        nonce: BaseElement::new(input.nonce),
    };

    Ok((witness, tx_hash))
}

// ---------------------------------------------------------------------------
// Exported WASM functions
// ---------------------------------------------------------------------------

/// Compute the Rescue-Prime identity commitment from (rev, salt, domain).
///
/// Returns a hex-encoded 32-byte string (4 x 8-byte big-endian Goldilocks elements).
#[wasm_bindgen]
pub fn compute_id_commitment(
    rev_hex: &str,
    salt_hex: &str,
    domain: u64,
) -> Result<String, JsValue> {
    let rev = hex_to_goldilocks(rev_hex)?;
    let salt = hex_to_goldilocks(salt_hex)?;
    let domain_elem = BaseElement::new(domain);

    let id_com = rescue_hash_full(&[rev, salt, domain_elem]);

    Ok(elements_to_hex(&id_com))
}

/// Generate a STARK proof from a JSON witness.
///
/// Witness JSON format:
/// ```json
/// {
///   "rev": "0x...",
///   "salt": "0x...",
///   "alg_id": 1,
///   "domain": 42161,
///   "index": 0,
///   "nonce": 0,
///   "tx_hash": "0x..."
/// }
/// ```
///
/// Returns JSON:
/// ```json
/// {
///   "proof": "0x...",
///   "pub_inputs": [17 uint64 values],
///   "id_com": "0x..."
/// }
/// ```
#[wasm_bindgen]
pub fn generate_stark_proof(witness_json: &str) -> Result<String, JsValue> {
    let (witness, tx_hash) = parse_witness(witness_json)?;

    // Compute public inputs
    let public_inputs = compute_public_inputs(&witness, tx_hash);

    // Build trace and generate proof
    let options = default_proof_options();
    let prover = ZkAceProver::new(options);
    let trace = prover.build_trace(&witness, &public_inputs);

    let proof = prover
        .prove(trace)
        .map_err(|e| JsValue::from_str(&format!("STARK proof generation failed: {}", e)))?;

    let proof_bytes = proof.to_bytes();

    let pub_inputs_vec = pub_inputs_to_u64_vec(
        &public_inputs.id_com,
        &public_inputs.target,
        &public_inputs.rp_com,
        public_inputs.domain,
        &public_inputs.tx_hash,
    );

    let output = ProofOutput {
        proof: format!("0x{}", hex::encode(&proof_bytes)),
        pub_inputs: pub_inputs_vec,
        id_com: elements_to_hex(&public_inputs.id_com),
    };

    serde_json::to_string(&output)
        .map_err(|e| JsValue::from_str(&format!("JSON serialization failed: {}", e)))
}

/// Compute and return the public inputs without generating a proof.
///
/// This is useful for computing the vault address (which depends on id_com
/// and target) without the cost of STARK proof generation.
///
/// Same witness JSON format as `generate_stark_proof`.
///
/// Returns JSON:
/// ```json
/// {
///   "pub_inputs": [17 uint64 values],
///   "id_com": "0x...",
///   "target": "0x...",
///   "rp_com": "0x..."
/// }
/// ```
#[wasm_bindgen]
pub fn get_proof_public_inputs(witness_json: &str) -> Result<String, JsValue> {
    let (witness, tx_hash) = parse_witness(witness_json)?;

    let public_inputs = compute_public_inputs(&witness, tx_hash);

    let pub_inputs_vec = pub_inputs_to_u64_vec(
        &public_inputs.id_com,
        &public_inputs.target,
        &public_inputs.rp_com,
        public_inputs.domain,
        &public_inputs.tx_hash,
    );

    let output = PublicInputsOutput {
        pub_inputs: pub_inputs_vec,
        id_com: elements_to_hex(&public_inputs.id_com),
        target: elements_to_hex(&public_inputs.target),
        rp_com: elements_to_hex(&public_inputs.rp_com),
    };

    serde_json::to_string(&output)
        .map_err(|e| JsValue::from_str(&format!("JSON serialization failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_id_commitment() {
        let result = compute_id_commitment("0xDEADBEEFCAFEBABE", "0x123456789ABCDEF0", 42161);
        assert!(result.is_ok());
        let hex_str = result.unwrap();
        assert!(hex_str.starts_with("0x"));
        // 0x + 64 hex chars = 32 bytes
        assert_eq!(hex_str.len(), 66);
    }

    #[test]
    fn test_compute_id_commitment_deterministic() {
        let r1 = compute_id_commitment("0xDEADBEEF", "0x12345678", 1).unwrap();
        let r2 = compute_id_commitment("0xDEADBEEF", "0x12345678", 1).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_get_proof_public_inputs() {
        let witness = r#"{
            "rev": "0xDEADBEEFCAFEBABE",
            "salt": "0x123456789ABCDEF0",
            "alg_id": 1,
            "domain": 42161,
            "index": 0,
            "nonce": 0,
            "tx_hash": "0xAAAABBBBCCCCDDDD11112222333344445555666677778888999900001111BBBB"
        }"#;
        let result = get_proof_public_inputs(witness);
        assert!(result.is_ok());
        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["pub_inputs"].is_array());
        assert_eq!(parsed["pub_inputs"].as_array().unwrap().len(), 17);
        assert!(parsed["id_com"].as_str().unwrap().starts_with("0x"));
        assert!(parsed["target"].as_str().unwrap().starts_with("0x"));
        assert!(parsed["rp_com"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn test_generate_stark_proof() {
        let witness = r#"{
            "rev": "0xDEADBEEFCAFEBABE",
            "salt": "0x123456789ABCDEF0",
            "alg_id": 1,
            "domain": 42161,
            "index": 0,
            "nonce": 0,
            "tx_hash": "0xAAAABBBBCCCCDDDD11112222333344445555666677778888999900001111BBBB"
        }"#;
        let result = generate_stark_proof(witness);
        assert!(result.is_ok());
        let json_str = result.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["proof"].as_str().unwrap().starts_with("0x"));
        assert_eq!(parsed["pub_inputs"].as_array().unwrap().len(), 17);
        assert!(parsed["id_com"].as_str().unwrap().starts_with("0x"));
    }
}
