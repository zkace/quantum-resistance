use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::PrimeField;

/// Create Poseidon configuration matching the paper's reference implementation:
/// width t=3, rate r=2, S-box exponent alpha=17, 8 full rounds, 57 partial rounds.
///
/// Uses arkworks' `find_poseidon_ark_and_mds` for deterministic round constant
/// and MDS matrix generation over the BN254 scalar field.
pub fn poseidon_config<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 17u64;
    let rate = 2;
    let capacity = 1;

    // Generate round constants (ark) and MDS matrix deterministically.
    // Parameters: field bits, rate, full_rounds, partial_rounds, skip_matrices
    let (ark, mds) = ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0, // skip_matrices
    );

    PoseidonConfig {
        full_rounds: full_rounds as usize,
        partial_rounds: partial_rounds as usize,
        alpha,
        ark,
        mds,
        rate,
        capacity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;

    #[test]
    fn poseidon_config_creates_valid_params() {
        let config = poseidon_config::<Fr>();
        assert_eq!(config.full_rounds, 8);
        assert_eq!(config.partial_rounds, 57);
        assert_eq!(config.alpha, 17);
        assert_eq!(config.rate, 2);
        assert_eq!(config.capacity, 1);
        // Total rounds = 8 + 57 = 65, each with t=3 round constants
        assert_eq!(config.ark.len(), 65);
        assert_eq!(config.mds.len(), 3);
        assert_eq!(config.mds[0].len(), 3);
    }
}
