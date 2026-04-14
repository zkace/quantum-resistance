//! ZK-ACE CLI — quantum-resistant identity and proof management.
//!
//! Subcommands:
//!   new-identity  Generate a new quantum-resistant identity
//!   show          Display the current identity (without secrets)
//!   prove         Generate a Groth16 proof for a transaction
//!   info          Show contract addresses and system info

use ark_bn254::{Bn254, Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use sha3::{Digest, Keccak256};
use std::path::PathBuf;

use zk_ace_circuit::poseidon::poseidon_config;
use zk_ace_circuit::types::{Ctx, ZkAceWitness};
use zk_ace_circuit::witness::compute_public_inputs;
use zk_ace_prover::prover::prove;
use zk_ace_prover::serialization::{
    keccak_to_field_element, serialize_proof_for_evm, serialize_public_inputs_for_evm,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("--help");

    match subcommand {
        "new-identity" => cmd_new_identity(&args[2..]),
        "show" => cmd_show(),
        "prove" => cmd_prove(&args[2..]),
        "info" => cmd_info(),
        _ => {
            eprintln!("ZK-ACE CLI — quantum-resistant vault toolkit");
            eprintln!();
            eprintln!("Usage: cli <COMMAND>");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  new-identity  Generate a new quantum-resistant identity");
            eprintln!("  show          Display the current identity (secrets hidden)");
            eprintln!("  prove         Generate a Groth16 proof for a transaction");
            eprintln!("  info          Show contract addresses and system info");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  new-identity --chain-id <N>   Chain ID (default: 42161)");
            eprintln!("  prove --calldata <hex>        Transaction calldata (hex)");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand: new-identity
// ---------------------------------------------------------------------------

fn cmd_new_identity(args: &[String]) {
    let chain_id = parse_flag_u64(args, "--chain-id").unwrap_or(42161);

    // Generate random REV and salt using OS entropy
    let mut rng = ark_std::rand::rngs::OsRng;
    let rev = Fr::rand(&mut rng);
    let salt = Fr::rand(&mut rng);

    // Compute IDcom = Poseidon(REV, salt, domain) — same as circuit C1
    let domain = Fr::from(chain_id);
    let config = poseidon_config::<Fr>();
    let id_com = zk_ace_circuit::witness::native_poseidon_hash(&config, &[rev, salt, domain]);

    let rev_hex = fr_to_hex(rev);
    let salt_hex = fr_to_hex(salt);
    let id_com_hex = fr_to_hex(id_com);

    println!("=== ZK-ACE New Identity ===");
    println!("REV:      {}", rev_hex);
    println!("Salt:     {}", salt_hex);
    println!("IDcom:    {}", id_com_hex);
    println!("Chain ID: {}", chain_id);
    println!();
    println!("SECURITY: Store your REV offline. Anyone with your REV controls your vault.");

    // Save to ~/.zkace/identity.json
    let identity = serde_json::json!({
        "rev": rev_hex,
        "salt": salt_hex,
        "chain_id": chain_id,
        "id_com": id_com_hex,
        "nonce": 0
    });

    let zkace_dir = home_dir().join(".zkace");
    std::fs::create_dir_all(&zkace_dir)
        .unwrap_or_else(|e| panic!("Failed to create {}: {}", zkace_dir.display(), e));

    let identity_path = zkace_dir.join("identity.json");
    let json_str = serde_json::to_string_pretty(&identity).unwrap();
    std::fs::write(&identity_path, &json_str)
        .unwrap_or_else(|e| panic!("Failed to write {}: {}", identity_path.display(), e));

    println!();
    println!("Identity saved to {}", identity_path.display());
}

// ---------------------------------------------------------------------------
// Subcommand: show
// ---------------------------------------------------------------------------

fn cmd_show() {
    let identity_path = home_dir().join(".zkace").join("identity.json");
    let data = std::fs::read_to_string(&identity_path)
        .unwrap_or_else(|_| {
            eprintln!("No identity found at {}", identity_path.display());
            eprintln!("Run: cli new-identity");
            std::process::exit(1);
        });

    let identity: serde_json::Value = serde_json::from_str(&data)
        .unwrap_or_else(|e| {
            eprintln!("Invalid identity file: {}", e);
            std::process::exit(1);
        });

    println!("=== ZK-ACE Identity ===");
    println!("IDcom:    {}", identity["id_com"].as_str().unwrap_or("unknown"));
    println!("Chain ID: {}", identity["chain_id"]);
    println!("Nonce:    {}", identity["nonce"]);
    println!();
    println!("(REV hidden for security — see ~/.zkace/identity.json if needed)");
}

// ---------------------------------------------------------------------------
// Subcommand: prove
// ---------------------------------------------------------------------------

fn cmd_prove(args: &[String]) {
    let calldata_hex = parse_flag_str(args, "--calldata").unwrap_or_else(|| {
        eprintln!("Usage: cli prove --calldata <hex>");
        std::process::exit(1);
    });

    // Load identity
    let identity_path = home_dir().join(".zkace").join("identity.json");
    let data = std::fs::read_to_string(&identity_path)
        .unwrap_or_else(|_| {
            eprintln!("No identity found. Run: cli new-identity");
            std::process::exit(1);
        });
    let mut identity: serde_json::Value = serde_json::from_str(&data)
        .unwrap_or_else(|e| {
            eprintln!("Invalid identity file: {}", e);
            std::process::exit(1);
        });

    let rev = hex_to_fr(identity["rev"].as_str().unwrap());
    let salt = hex_to_fr(identity["salt"].as_str().unwrap());
    let chain_id = identity["chain_id"].as_u64().unwrap();
    let nonce_value = identity["nonce"].as_u64().unwrap();

    // Load proving key
    let artifacts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    let pk_path = artifacts_dir.join("pk.bin");

    println!("Loading proving key from {}...", pk_path.display());
    let pk_bytes = std::fs::read(&pk_path)
        .unwrap_or_else(|_| {
            eprintln!("Cannot read {}. Run setup first.", pk_path.display());
            std::process::exit(1);
        });
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .expect("Invalid pk.bin — run setup again");

    // Build witness
    let witness = ZkAceWitness {
        rev,
        salt,
        ctx: Ctx {
            alg_id: Fr::from(1u64),
            domain: Fr::from(chain_id),
            index: Fr::from(0u64),
        },
        nonce: Fr::from(nonce_value),
    };

    // Compute TxHash = keccak256(calldata) reduced to BN254 field
    let calldata_clean = calldata_hex.strip_prefix("0x").unwrap_or(&calldata_hex);
    let calldata_bytes = hex::decode(calldata_clean)
        .unwrap_or_else(|e| {
            eprintln!("Invalid calldata hex: {}", e);
            std::process::exit(1);
        });

    let mut hasher = Keccak256::new();
    hasher.update(&calldata_bytes);
    let hash_result = hasher.finalize();
    let mut tx_hash_bytes = [0u8; 32];
    tx_hash_bytes.copy_from_slice(&hash_result);
    let tx_hash = keccak_to_field_element(&tx_hash_bytes);

    // Compute public inputs
    let public_inputs = compute_public_inputs(&witness, tx_hash);

    // Generate Groth16 proof
    println!("Generating Groth16 proof...");
    let start = std::time::Instant::now();
    let mut prove_rng = ark_std::rand::rngs::OsRng;
    let proof = prove(&pk, witness, public_inputs.clone(), &mut prove_rng);
    let elapsed = start.elapsed();
    println!("Proof generated in {:?}", elapsed);

    // Serialize for EVM
    let proof_bytes = serialize_proof_for_evm(&proof);
    let pi_bytes = serialize_public_inputs_for_evm(&public_inputs);

    // ABI-encoded signature = proof (256 bytes) + public inputs (160 bytes)
    let mut signature = Vec::with_capacity(proof_bytes.len() + pi_bytes.len());
    signature.extend_from_slice(&proof_bytes);
    signature.extend_from_slice(&pi_bytes);

    let signature_hex = format!("0x{}", hex::encode(&signature));

    println!();
    println!("=== Proof Output ===");
    println!("TxHash:    {}", fr_to_hex(tx_hash));
    println!("IDcom:     {}", fr_to_hex(public_inputs.id_com));
    println!("Nonce:     {}", nonce_value);
    println!("Signature: {}", signature_hex);

    // Increment nonce in identity.json
    identity["nonce"] = serde_json::json!(nonce_value + 1);
    let json_str = serde_json::to_string_pretty(&identity).unwrap();
    std::fs::write(&identity_path, &json_str)
        .unwrap_or_else(|e| panic!("Failed to update {}: {}", identity_path.display(), e));

    println!();
    println!("Nonce incremented to {} in {}", nonce_value + 1, identity_path.display());
}

// ---------------------------------------------------------------------------
// Subcommand: info
// ---------------------------------------------------------------------------

fn cmd_info() {
    // Read constraint count from the circuit
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::r1cs::ConstraintSynthesizer;
    use zk_ace_circuit::circuit::ZkAceCircuit;

    let circuit = ZkAceCircuit::<Fr>::blank();
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).expect("constraint generation");
    let num_constraints = cs.num_constraints();

    // Read chain_id from identity if present
    let identity_path = home_dir().join(".zkace").join("identity.json");
    let chain_id = std::fs::read_to_string(&identity_path)
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .and_then(|v| v["chain_id"].as_u64())
        .unwrap_or(42161);

    println!("=== ZK-ACE System Info ===");
    println!();
    println!("Contracts (Arbitrum One):");
    println!("  STARK Verifier (PQ): 0xE1B8750ED6Fd835e7D27a1A4F08532BDbFb9F6d4");
    println!("  Groth16 Verifier:    0xfA56E270c36849072F41e8D44884fcae2CB9c70c");
    println!("  Account Factory:     0xf50Fa247F5C0FCB5524f7dcf3A709F3345dfeF0d");
    println!("  EntryPoint:          0x0000000071727De22E5E9d8BAf0edAc6f37da032");
    println!();
    println!("Circuit:");
    println!("  Constraints: {}", num_constraints);
    println!("  Curve:       BN254 (alt_bn128)");
    println!("  Hash:        Poseidon (t=3, r=2, alpha=17, RF=8, RP=57)");
    println!("  Proof:       Groth16");
    println!();
    println!("Chain ID:      {}", chain_id);
    println!("Artifacts:     crates/zk-ace-prover/artifacts/");

    // Check if artifacts exist
    let artifacts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    let pk_exists = artifacts_dir.join("pk.bin").exists();
    let vk_exists = artifacts_dir.join("vk.bin").exists();
    println!("  pk.bin:      {}", if pk_exists { "present" } else { "MISSING — run setup" });
    println!("  vk.bin:      {}", if vk_exists { "present" } else { "MISSING — run setup" });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn hex_to_fr(s: &str) -> Fr {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).expect("Invalid hex for field element");
    Fr::from_be_bytes_mod_order(&bytes)
}

fn parse_flag_u64(args: &[String], flag: &str) -> Option<u64> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
}

fn parse_flag_str(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
