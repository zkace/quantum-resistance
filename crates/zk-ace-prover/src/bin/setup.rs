use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("--help");

    match mode {
        "--production" => run_production_setup(),
        "--dev" => run_dev_setup(),
        _ => {
            eprintln!("Usage: setup --production | --dev");
            eprintln!("  --production  Use OS entropy (OsRng). Safe for real funds.");
            eprintln!("  --dev         Use deterministic seed. UNSAFE — for testing only.");
            std::process::exit(1);
        }
    }
}

fn run_production_setup() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  ZK-ACE PRODUCTION Trusted Setup                       ║");
    println!("║  Using OS entropy (OsRng / /dev/urandom)               ║");
    println!("║  Toxic waste exists ONLY in RAM during this process.    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // Use OsRng — pulls from the OS CSPRNG (/dev/urandom on macOS/Linux).
    // The random values used for the setup (tau, alpha, beta) exist only
    // in RAM and are dropped when this function returns.
    let mut rng = ark_std::rand::rngs::OsRng;

    println!("Generating circuit-specific parameters with OS entropy...");
    let (pk, vk) = zk_ace_prover::setup::trusted_setup(&mut rng);

    write_artifacts(&pk, &vk, "production");

    println!();
    println!("IMPORTANT: The toxic waste (tau, alpha, beta) existed only in RAM");
    println!("during this process and has now been dropped. If this machine's");
    println!("memory has not been compromised, the setup is secure.");
    println!();
    println!("For higher assurance, run this on an air-gapped machine and");
    println!("wipe/destroy the machine after extracting the artifacts.");
}

fn run_dev_setup() {
    println!("ZK-ACE DEV Trusted Setup");
    println!("WARNING: Deterministic seed — UNSAFE for real funds.");
    println!();

    let seed = 0xDEAD_BEEF_CAFE_BABEu64;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    println!("Generating circuit-specific parameters (deterministic)...");
    let (pk, vk) = zk_ace_prover::setup::trusted_setup(&mut rng);

    write_artifacts(&pk, &vk, "dev");
}

fn write_artifacts(
    pk: &ark_groth16::ProvingKey<ark_bn254::Bn254>,
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    mode: &str,
) {
    let artifacts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts");
    fs::create_dir_all(&artifacts_dir).unwrap();

    // Serialize proving key
    let pk_path = artifacts_dir.join("pk.bin");
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    fs::write(&pk_path, &pk_bytes).unwrap();
    println!("Proving key: {} ({} bytes)", pk_path.display(), pk_bytes.len());

    // Serialize verifying key
    let vk_path = artifacts_dir.join("vk.bin");
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    fs::write(&vk_path, &vk_bytes).unwrap();
    println!("Verifying key: {} ({} bytes)", vk_path.display(), vk_bytes.len());

    // Generate Solidity verifier
    let sol = zk_ace_prover::solidity::generate_solidity_verifier(vk);
    let sol_path = artifacts_dir.join("ZkAceVerifier.sol");
    fs::write(&sol_path, &sol).unwrap();
    println!("Solidity verifier: {}", sol_path.display());

    // Write metadata
    let meta = format!(
        "{{\"mode\":\"{}\",\"ic_points\":{},\"timestamp\":\"{}\"}}",
        mode,
        vk.gamma_abc_g1.len(),
        chrono_now(),
    );
    let meta_path = artifacts_dir.join("ceremony.json");
    fs::write(&meta_path, &meta).unwrap();
    println!("Metadata: {}", meta_path.display());
}

fn chrono_now() -> String {
    // Simple timestamp without adding a dependency
    use std::time::SystemTime;
    let d = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    format!("{}", d.as_secs())
}
