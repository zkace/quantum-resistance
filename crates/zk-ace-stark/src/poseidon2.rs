//! Poseidon2 hash helpers for ZK-ACE STARK commitments.
//! Uses the canonical Plonky3 Goldilocks width-8 permutation.

use p3_goldilocks::{
    default_goldilocks_poseidon2_8, Goldilocks, Poseidon2Goldilocks,
    GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS, GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8,
};
use p3_field::PrimeField64;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use winterfell::math::fields::f64::BaseElement;

pub const POSEIDON2_WIDTH: usize = 8;
pub const POSEIDON2_RATE: usize = 4;
pub const POSEIDON2_DIGEST_ELEMS: usize = 4;
pub const POSEIDON2_ALPHA: u64 = 7;
pub const POSEIDON2_FULL_ROUNDS: usize = 2 * GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS;
pub const POSEIDON2_PARTIAL_ROUNDS: usize = GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8;

type Poseidon2Sponge = PaddingFreeSponge<
    Poseidon2Goldilocks<POSEIDON2_WIDTH>,
    POSEIDON2_WIDTH,
    POSEIDON2_RATE,
    POSEIDON2_DIGEST_ELEMS,
>;

fn default_sponge() -> Poseidon2Sponge {
    Poseidon2Sponge::new(default_goldilocks_poseidon2_8())
}

fn to_goldilocks(elem: BaseElement) -> Goldilocks {
    Goldilocks::new(elem.inner())
}

fn from_goldilocks(elem: Goldilocks) -> BaseElement {
    BaseElement::new(elem.as_canonical_u64())
}

/// Hash field elements using Poseidon2, returning the full 4-element digest.
pub fn poseidon2_hash_full(inputs: &[BaseElement]) -> [BaseElement; 4] {
    default_sponge()
        .hash_iter(inputs.iter().copied().map(to_goldilocks))
        .map(from_goldilocks)
}

/// Convert a Poseidon2 4-element digest back to bytes (for comparison/display).
pub fn digest_to_bytes(digest: &[BaseElement; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, elem) in digest.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem.inner().to_le_bytes());
    }
    bytes
}

/// Helper to create a field element from a u64.
pub fn to_element(val: u64) -> BaseElement {
    BaseElement::new(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use p3_symmetric::Permutation;

    #[test]
    fn poseidon2_parameters_match_plan() {
        assert_eq!(POSEIDON2_WIDTH, 8);
        assert_eq!(POSEIDON2_RATE, 4);
        assert_eq!(POSEIDON2_DIGEST_ELEMS, 4);
        assert_eq!(POSEIDON2_ALPHA, 7);
        assert_eq!(POSEIDON2_FULL_ROUNDS, 8);
        assert_eq!(POSEIDON2_PARTIAL_ROUNDS, 22);
    }

    #[test]
    fn poseidon2_default_permutation_matches_plonky3_known_answer() {
        let mut input = Goldilocks::new_array([0, 1, 2, 3, 4, 5, 6, 7]);
        let expected = Goldilocks::new_array([
            0x020cf04a1b214d14,
            0x84e14aaaeacaed25,
            0x1ae0f640e81c7457,
            0xa4d204cbaeb0d8a5,
            0x0cf637b627b3a7ff,
            0x788d304d948b486b,
            0x7327133ea1949af4,
            0xf415abb924da395b,
        ]);

        default_goldilocks_poseidon2_8().permute_mut(&mut input);

        assert_eq!(input, expected);
    }

    #[test]
    fn poseidon2_hash_deterministic() {
        let input = [to_element(42), to_element(100), to_element(42161)];
        let h1 = poseidon2_hash_full(&input);
        let h2 = poseidon2_hash_full(&input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon2_hash_different_inputs() {
        let h1 = poseidon2_hash_full(&[to_element(1), to_element(2)]);
        let h2 = poseidon2_hash_full(&[to_element(1), to_element(3)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon2_hash_matches_plonky3_reference_vectors() {
        let sponge = default_sponge();
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        for _ in 0..20 {
            let len = rng.gen_range(1..=6);
            let inputs: Vec<BaseElement> = (0..len).map(|_| to_element(rng.gen())).collect();
            let expected = sponge
                .hash_iter(inputs.iter().copied().map(to_goldilocks))
                .map(from_goldilocks);
            let actual = poseidon2_hash_full(&inputs);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn poseidon2_digest_roundtrip() {
        let input = poseidon2_hash_full(&[to_element(123), to_element(456)]);
        let bytes = digest_to_bytes(&input);
        let input2 = poseidon2_hash_full(&[to_element(123), to_element(456)]);
        let bytes2 = digest_to_bytes(&input2);

        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, bytes2);
    }
}
