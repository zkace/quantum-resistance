//! Generates a real Groth16 proof and outputs all fixture data as JSON.
//! Used by the Forge FFI integration tests to bridge Rust proofs to Solidity.

use ark_bn254::{Bn254, Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use std::path::PathBuf;

use zk_ace_circuit::types::{Ctx, ZkAceWitness};
use zk_ace_circuit::witness::compute_public_inputs;
use zk_ace_prover::prover::{prove, public_inputs_to_vec};
use zk_ace_prover::serialization::{
    keccak_to_field_element, serialize_proof_for_evm, serialize_public_inputs_for_evm,
};
use zk_ace_prover::verifier::{prepare_vk, verify};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse optional chain ID argument (default: 31337 for Anvil)
    let chain_id: u64 = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(31337);

    // 1. Load proving key and verifying key from artifacts (production or dev)
    let artifacts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    let pk_path = artifacts_dir.join("pk.bin");
    let vk_path = artifacts_dir.join("vk.bin");

    let pk_bytes = std::fs::read(&pk_path)
        .unwrap_or_else(|_| panic!("Cannot read {}. Run setup first.", pk_path.display()));
    let vk_bytes = std::fs::read(&vk_path)
        .unwrap_or_else(|_| panic!("Cannot read {}. Run setup first.", vk_path.display()));

    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..]).expect("Invalid pk.bin");
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).expect("Invalid vk.bin");
    let pvk = prepare_vk(&vk);

    // 2. Create a realistic identity (deterministic for reproducible fixtures)
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF_CAFE_BABEu64);
    let rev = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);
    let nonce_value = 0u64;

    let witness = ZkAceWitness {
        rev,
        salt,
        ctx: Ctx {
            alg_id: Fr::from(1u64), // Ed25519
            domain: Fr::from(chain_id),
            index: Fr::from(0u64),
        },
        nonce: Fr::from(nonce_value),
    };

    // 3. Compute TxHash from calldata
    // If calldata provided as arg, use it; otherwise use a test calldata
    let calldata_hex = if args.len() > 2 {
        args[2].clone()
    } else {
        // Default: execute(address,uint256,bytes) call to transfer 0.001 ETH to 0xdead
        "b61d27f6000000000000000000000000000000000000000000000000000000000000dead00000000000000000000000000000000000000000000000000038d7ea4c6800000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000".to_string()
    };

    let calldata_bytes = hex::decode(calldata_hex.strip_prefix("0x").unwrap_or(&calldata_hex)).unwrap();

    // Compute keccak256 of calldata (what the contract does)
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(&calldata_bytes);
    let keccak_result = hasher.finalize();
    let mut tx_hash_bytes = [0u8; 32];
    tx_hash_bytes.copy_from_slice(&keccak_result);

    // Reduce to BN254 field element
    let tx_hash = keccak_to_field_element(&tx_hash_bytes);

    // 4. Compute public inputs
    let public_inputs = compute_public_inputs(&witness, tx_hash);

    // 5. Generate the real Groth16 proof
    let mut prove_rng = ChaCha20Rng::seed_from_u64(0x1234);
    let proof = prove(&pk, witness, public_inputs.clone(), &mut prove_rng);

    // 6. VERIFY NATIVELY first — if this fails, nothing else matters
    let native_valid = verify(&pvk, &proof, &public_inputs);
    assert!(native_valid, "CRITICAL: Native Groth16 verification failed!");

    // 7. Serialize for EVM
    let proof_evm = serialize_proof_for_evm(&proof);
    let pi_evm = serialize_public_inputs_for_evm(&public_inputs);

    // 8. Extract individual proof components for Solidity
    let pi_vec = public_inputs_to_vec(&public_inputs);

    // Output JSON fixture
    let fixture = json!({
        "chainId": chain_id,
        "nonce": nonce_value,
        "calldata": format!("0x{}", hex::encode(&calldata_bytes)),
        "txHash": fr_to_hex(tx_hash),
        "idCom": fr_to_hex(public_inputs.id_com),
        "domain": fr_to_hex(public_inputs.domain),
        "target": fr_to_hex(public_inputs.target),
        "rpCom": fr_to_hex(public_inputs.rp_com),
        "proof": {
            "a": [
                format!("0x{}", hex::encode(&proof_evm[0..32])),
                format!("0x{}", hex::encode(&proof_evm[32..64])),
            ],
            "b": [
                [
                    format!("0x{}", hex::encode(&proof_evm[64..96])),
                    format!("0x{}", hex::encode(&proof_evm[96..128])),
                ],
                [
                    format!("0x{}", hex::encode(&proof_evm[128..160])),
                    format!("0x{}", hex::encode(&proof_evm[160..192])),
                ],
            ],
            "c": [
                format!("0x{}", hex::encode(&proof_evm[192..224])),
                format!("0x{}", hex::encode(&proof_evm[224..256])),
            ],
        },
        "publicInputs": [
            fr_to_hex(pi_vec[0]),
            fr_to_hex(pi_vec[1]),
            fr_to_hex(pi_vec[2]),
            fr_to_hex(pi_vec[3]),
            fr_to_hex(pi_vec[4]),
        ],
        "nativeVerification": native_valid,
    });

    println!("{}", serde_json::to_string(&fixture).unwrap());
}

fn fr_to_hex(f: Fr) -> String {
    let bigint = f.into_bigint();
    let mut bytes = [0u8; 32];
    let limbs = bigint.as_ref();
    for (i, limb) in limbs.iter().enumerate() {
        let limb_bytes = limb.to_le_bytes();
        for (j, &b) in limb_bytes.iter().enumerate() {
            bytes[31 - (i * 8 + j)] = b;
        }
    }
    format!("0x{}", hex::encode(bytes))
}
