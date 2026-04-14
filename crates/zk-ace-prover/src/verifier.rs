use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_snark::SNARK;

use zk_ace_circuit::types::ZkAcePublicInputs;

use crate::prover::public_inputs_to_vec;

/// Prepare the verifying key for efficient repeated verification.
pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).unwrap()
}

/// Verify a Groth16 proof against public inputs.
pub fn verify(
    pvk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &ZkAcePublicInputs<Fr>,
) -> bool {
    let pi_vec = public_inputs_to_vec(public_inputs);
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &pi_vec, proof).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::prove;
    use crate::setup::trusted_setup;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use zk_ace_circuit::types::{Ctx, ZkAceWitness};
    use zk_ace_circuit::witness::compute_public_inputs;

    #[test]
    fn prove_and_verify_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF);

        // Setup
        let (pk, vk) = trusted_setup(&mut rng);
        let pvk = prepare_vk(&vk);

        // Create witness
        let witness = ZkAceWitness {
            rev: Fr::rand(&mut rng),
            salt: Fr::rand(&mut rng),
            ctx: Ctx {
                alg_id: Fr::from(1u64),
                domain: Fr::from(42161u64),
                index: Fr::from(0u64),
            },
            nonce: Fr::from(1u64),
        };
        let tx_hash = Fr::rand(&mut rng);
        let public_inputs = compute_public_inputs(&witness, tx_hash);

        // Prove
        let proof = prove(&pk, witness, public_inputs.clone(), &mut rng);

        // Verify
        assert!(verify(&pvk, &proof, &public_inputs), "Valid proof must verify");
    }

    #[test]
    fn mutated_public_input_fails() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xCAFE);

        let (pk, vk) = trusted_setup(&mut rng);
        let pvk = prepare_vk(&vk);

        let witness = ZkAceWitness {
            rev: Fr::rand(&mut rng),
            salt: Fr::rand(&mut rng),
            ctx: Ctx {
                alg_id: Fr::from(1u64),
                domain: Fr::from(42161u64),
                index: Fr::from(0u64),
            },
            nonce: Fr::from(1u64),
        };
        let tx_hash = Fr::rand(&mut rng);
        let public_inputs = compute_public_inputs(&witness, tx_hash);
        let proof = prove(&pk, witness, public_inputs.clone(), &mut rng);

        // Mutate tx_hash
        let mut bad_inputs = public_inputs;
        bad_inputs.tx_hash += Fr::from(1u64);
        assert!(!verify(&pvk, &proof, &bad_inputs), "Mutated tx_hash must fail verification");
    }
}
