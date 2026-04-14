use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ff::PrimeField;

/// Compute identity commitment off-chain: ID_com = Poseidon(REV, salt, domain).
///
/// Uses the same Poseidon configuration as the ZK circuit to ensure
/// functional equivalence between off-chain and in-circuit computation.
pub fn compute_id_commitment<F: PrimeField + Absorb>(
    config: &PoseidonConfig<F>,
    rev: F,
    salt: F,
    domain: F,
) -> F {
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&rev);
    sponge.absorb(&salt);
    sponge.absorb(&domain);
    let output: Vec<F> = sponge.squeeze_field_elements(1);
    output[0]
}

/// Compute target binding off-chain: target = Poseidon(Poseidon(REV, AlgID, Domain, Index)).
///
/// Mirrors the circuit-native Derive function (C2).
pub fn compute_target<F: PrimeField + Absorb>(
    config: &PoseidonConfig<F>,
    rev: F,
    alg_id: F,
    domain: F,
    index: F,
) -> F {
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&rev);
    sponge.absorb(&alg_id);
    sponge.absorb(&domain);
    sponge.absorb(&index);
    let derived_key: Vec<F> = sponge.squeeze_field_elements(1);

    let mut sponge2 = PoseidonSponge::new(config);
    sponge2.absorb(&derived_key[0]);
    let target: Vec<F> = sponge2.squeeze_field_elements(1);
    target[0]
}

/// Compute replay-prevention commitment: rp_com = Poseidon(ID_com, nonce).
pub fn compute_rp_com<F: PrimeField + Absorb>(
    config: &PoseidonConfig<F>,
    id_com: F,
    nonce: F,
) -> F {
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&id_com);
    sponge.absorb(&nonce);
    let output: Vec<F> = sponge.squeeze_field_elements(1);
    output[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_config() -> PoseidonConfig<Fr> {
        let (ark, mds) =
            ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds::<Fr>(
                Fr::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0,
            );
        PoseidonConfig {
            full_rounds: 8,
            partial_rounds: 57,
            alpha: 17,
            ark,
            mds,
            rate: 2,
            capacity: 1,
        }
    }

    #[test]
    fn commitment_deterministic() {
        let config = test_config();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let rev = Fr::rand(&mut rng);
        let salt = Fr::rand(&mut rng);
        let domain = Fr::from(42161u64);

        let c1 = compute_id_commitment(&config, rev, salt, domain);
        let c2 = compute_id_commitment(&config, rev, salt, domain);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_salt_different_commitment() {
        let config = test_config();
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let rev = Fr::rand(&mut rng);
        let salt1 = Fr::rand(&mut rng);
        let salt2 = Fr::rand(&mut rng);
        let domain = Fr::from(42161u64);

        let c1 = compute_id_commitment(&config, rev, salt1, domain);
        let c2 = compute_id_commitment(&config, rev, salt2, domain);
        assert_ne!(c1, c2);
    }
}
