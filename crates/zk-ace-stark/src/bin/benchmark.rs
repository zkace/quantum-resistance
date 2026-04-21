//! Benchmark STARK proof generation, verification, and estimate on-chain gas costs.

use std::time::Instant;
use winterfell::math::fields::f64::BaseElement;
use winterfell::Prover;

use zk_ace_stark::prover::{compute_public_inputs, default_proof_options, ZkAceProver, ZkAceWitness};
use zk_ace_stark::serialization::estimate_gas_cost;
use zk_ace_stark::verifier::verify_proof;

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  ZK-ACE STARK (Post-Quantum) — Benchmark & Cost Report ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let witness = ZkAceWitness {
        rev: BaseElement::new(0xDEAD_BEEF_CAFE_BABEu64),
        salt: BaseElement::new(0x1234_5678_9ABC_DEF0u64),
        alg_id: BaseElement::new(1),
        ctx_domain: BaseElement::new(42161), // Arbitrum One
        ctx_index: BaseElement::new(0),
        nonce: BaseElement::new(0),
    };
    let tx_hash = [BaseElement::new(0xAAAAu64), BaseElement::new(0xBBBBu64), BaseElement::new(0xCCCCu64), BaseElement::new(0xDDDDu64)];
    let public_inputs = compute_public_inputs(&witness, tx_hash);
    let prover = ZkAceProver::new(default_proof_options());

    // --- Proof Generation ---
    let start = Instant::now();
    let trace = prover.build_trace(&witness, &public_inputs);
    let proof = prover.prove(trace).expect("Proof generation failed");
    let prove_time = start.elapsed();

    // --- Verification ---
    let start = Instant::now();
    let valid = verify_proof(&proof, &public_inputs);
    let verify_time = start.elapsed();
    assert!(valid, "Proof verification failed!");

    // --- Serialization ---
    let proof_bytes = proof.to_bytes();

    // --- Gas Estimation ---
    let gas = estimate_gas_cost(&proof_bytes);

    println!("━━━ Proof System ━━━");
    println!("  Type: STARK (FRI-based, hash-only)");
    println!("  Hash: Rescue-Prime 64/256 (Rp64_256)");
    println!("  Security: ~128-bit (32 queries, blowup 8)");
    println!("  Post-quantum: YES (no elliptic curves, no pairings)");
    println!("  Trusted setup: NONE (transparent)");
    println!();
    println!("━━━ Performance ━━━");
    println!("  Proof generation: {:?}", prove_time);
    println!("  Verification: {:?}", verify_time);
    println!();
    println!("━━━ Proof Size ━━━");
    println!("  {}", gas);
    println!();

    // --- Comparison with Groth16 ---
    println!("━━━ Comparison: STARK vs Groth16 ━━━");
    println!();
    println!("  {:30} {:>12} {:>12}", "", "Groth16", "STARK");
    println!("  {:30} {:>12} {:>12}", "─".repeat(30), "─".repeat(12), "─".repeat(12));
    println!("  {:30} {:>12} {:>10.1} KB",
        "Proof size",
        "256 B",
        proof_bytes.len() as f64 / 1024.0);
    println!("  {:30} {:>12} {:>12}",
        "Trusted setup",
        "REQUIRED",
        "NONE");
    println!("  {:30} {:>12} {:>12}",
        "Post-quantum secure",
        "NO",
        "YES");
    println!("  {:30} {:>10} ms {:>10} ms",
        "Prove time (single-thread)",
        "63",
        prove_time.as_millis());
    println!("  {:30} {:>10} μs {:>10} μs",
        "Verify time (native)",
        "651",
        verify_time.as_micros());
    println!();

    let groth16_gas: u64 = 270_000;
    let stark_gas = gas.total_gas;
    let arb_gas_price_gwei = 0.02f64;
    let eth_price = 1850.0f64;

    let groth16_cost = groth16_gas as f64 * arb_gas_price_gwei * 1e-9 * eth_price;
    let stark_cost = stark_gas as f64 * arb_gas_price_gwei * 1e-9 * eth_price;

    println!("━━━ Arbitrum One Costs (at {:.2} gwei, ETH=${}) ━━━", arb_gas_price_gwei, eth_price);
    println!();
    println!("  {:30} {:>12} {:>12}", "", "Groth16", "STARK");
    println!("  {:30} {:>12} {:>12}", "─".repeat(30), "─".repeat(12), "─".repeat(12));
    println!("  {:30} {:>10}k {:>10}k",
        "Verification gas",
        groth16_gas / 1000,
        stark_gas / 1000);
    println!("  {:30} {:>11.4}  {:>11.4} ",
        "Cost per tx (USD)",
        groth16_cost,
        stark_cost);
    println!("  {:30} {:>12} {:>11.1}x",
        "Cost ratio vs Groth16",
        "1.0x",
        stark_gas as f64 / groth16_gas as f64);
    println!();

    // Deployment costs
    // STARK verifier contract would be significantly larger than Groth16 (~20-50 KB bytecode)
    // But for initial estimate, let's size it based on FRI verification logic
    let verifier_bytecode_est = 30_000; // ~30 KB estimated for FRI verifier contract
    let deploy_gas_est: u64 = verifier_bytecode_est * 200 + 500_000; // bytecode + constructor
    let deploy_cost = deploy_gas_est as f64 * arb_gas_price_gwei * 1e-9 * eth_price;

    println!("━━━ Deployment Cost Estimate ━━━");
    println!("  STARK verifier contract: ~{} KB bytecode (estimated)", verifier_bytecode_est / 1000);
    println!("  Deployment gas: ~{}k", deploy_gas_est / 1000);
    println!("  Deployment cost: ${:.3}", deploy_cost);
    println!();

    println!("━━━ Key Takeaway ━━━");
    println!("  The STARK proof is {:.1} KB vs 256 bytes for Groth16.", proof_bytes.len() as f64 / 1024.0);
    println!("  On-chain verification is ~{:.1}x more expensive than Groth16.", stark_gas as f64 / groth16_gas as f64);
    println!("  But: NO trusted setup, NO elliptic curves, fully POST-QUANTUM.");
    println!("  On Arbitrum at current gas prices, each tx costs ~${:.4}.", stark_cost);
}
