//! Proof serialization and gas cost estimation for on-chain STARK verification.

use winterfell::Proof;

/// Serialize a STARK proof to bytes for on-chain submission.
pub fn serialize_proof(proof: &Proof) -> Vec<u8> {
    proof.to_bytes()
}

/// Estimate Arbitrum gas cost for on-chain STARK verification.
pub fn estimate_gas_cost(proof_bytes: &[u8]) -> GasCostEstimate {
    let proof_size = proof_bytes.len();

    // Arbitrum calldata costs:
    // - 4 gas per zero byte
    // - 16 gas per non-zero byte
    let zero_bytes = proof_bytes.iter().filter(|&&b| b == 0).count();
    let nonzero_bytes = proof_size - zero_bytes;
    let calldata_gas = (zero_bytes * 4 + nonzero_bytes * 16) as u64;

    // STARK verification computation gas:
    // FRI verification: ~200-400k gas (depends on number of queries and layers)
    // Merkle path verification: ~50-100k gas
    // Constraint evaluation: ~10-50k gas
    // Total computation: ~300-600k gas
    let num_queries = 32; // from default_proof_options
    let fri_layers = 4; // approximate for our trace size
    let merkle_gas = num_queries * fri_layers * 2000; // ~256k gas for Merkle paths
    let constraint_gas = 50_000; // linear constraint evaluation
    let fri_polynomial_gas = 100_000; // FRI polynomial evaluation
    let computation_gas = merkle_gas + constraint_gas + fri_polynomial_gas;

    let total_gas = calldata_gas + computation_gas;

    GasCostEstimate {
        proof_size_bytes: proof_size,
        calldata_gas,
        computation_gas,
        total_gas,
    }
}

#[derive(Debug)]
pub struct GasCostEstimate {
    pub proof_size_bytes: usize,
    pub calldata_gas: u64,
    pub computation_gas: u64,
    pub total_gas: u64,
}

impl std::fmt::Display for GasCostEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Proof size: {} bytes ({:.1} KB)\n\
             Calldata gas: {} ({:.1}k)\n\
             Computation gas: {} ({:.1}k)\n\
             Total estimated gas: {} ({:.1}k)\n\
             At 0.02 gwei (Arbitrum): {:.6} ETH\n\
             At ETH=$1850: ${:.4}",
            self.proof_size_bytes,
            self.proof_size_bytes as f64 / 1024.0,
            self.calldata_gas,
            self.calldata_gas as f64 / 1000.0,
            self.computation_gas,
            self.computation_gas as f64 / 1000.0,
            self.total_gas,
            self.total_gas as f64 / 1000.0,
            self.total_gas as f64 * 0.00000002, // 0.02 gwei in ETH
            self.total_gas as f64 * 0.00000002 * 1850.0,
        )
    }
}
