use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::CryptoRng;
use ark_std::rand::RngCore;

use zk_ace_circuit::circuit::ZkAceCircuit;

/// Perform Groth16 trusted setup for the ZK-ACE circuit.
/// Returns (ProvingKey, VerifyingKey).
pub fn trusted_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (
    ark_groth16::ProvingKey<Bn254>,
    ark_groth16::VerifyingKey<Bn254>,
) {
    let circuit = ZkAceCircuit::<Fr>::blank();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();
    (pk, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn setup_produces_valid_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD);
        let (pk, _vk) = trusted_setup(&mut rng);
        // Basic sanity: proving key should have non-zero elements
        assert!(!pk.vk.gamma_abc_g1.is_empty());
    }
}
