//! ZK-ACE STARK Verifier (Rust native).

use winterfell::{verify, AcceptableOptions, Proof};
use crate::air::ZkAcePublicInputs;
use crate::prover::default_proof_options;

/// Verify a ZK-ACE STARK proof natively.
pub fn verify_proof(proof: &Proof, public_inputs: &ZkAcePublicInputs) -> bool {
    use crate::keccak_hasher::KeccakHash;
    let acceptable = AcceptableOptions::OptionSet(vec![default_proof_options()]);
    verify::<
        crate::air::ZkAceAir,
        KeccakHash,
        winterfell::crypto::DefaultRandomCoin<KeccakHash>,
        winterfell::crypto::MerkleTree<KeccakHash>,
    >(proof.clone(), public_inputs.clone(), &acceptable)
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{compute_public_inputs, default_proof_options, ZkAceProver, ZkAceWitness};
    use winterfell::math::fields::f64::BaseElement;
    use winterfell::Prover;

    #[test]
    fn prove_verify_round_trip() {
        let witness = ZkAceWitness {
            rev: BaseElement::new(0xDEAD_BEEF_CAFE_BABEu64),
            salt: BaseElement::new(0x1234_5678_9ABC_DEF0u64),
            alg_id: BaseElement::new(1),
            ctx_domain: BaseElement::new(42161),
            ctx_index: BaseElement::new(0),
            nonce: BaseElement::new(0),
        };
        let tx_hash = [
            BaseElement::new(0xAAAAu64), BaseElement::new(0xBBBBu64),
            BaseElement::new(0xCCCCu64), BaseElement::new(0xDDDDu64),
        ];
        let public_inputs = compute_public_inputs(&witness, tx_hash);
        let prover = ZkAceProver::new(default_proof_options());
        let trace = prover.build_trace(&witness, &public_inputs);
        let proof = prover.prove(trace).expect("Proof generation failed");
        assert!(verify_proof(&proof, &public_inputs), "STARK proof must verify");
    }

    #[test]
    fn wrong_public_inputs_fail() {
        let witness = ZkAceWitness {
            rev: BaseElement::new(0xDEAD_BEEF_CAFE_BABEu64),
            salt: BaseElement::new(0x1234_5678_9ABC_DEF0u64),
            alg_id: BaseElement::new(1),
            ctx_domain: BaseElement::new(42161),
            ctx_index: BaseElement::new(0),
            nonce: BaseElement::new(0),
        };
        let tx_hash = [
            BaseElement::new(0xAAAAu64), BaseElement::new(0xBBBBu64),
            BaseElement::new(0xCCCCu64), BaseElement::new(0xDDDDu64),
        ];
        let public_inputs = compute_public_inputs(&witness, tx_hash);
        let prover = ZkAceProver::new(default_proof_options());
        let trace = prover.build_trace(&witness, &public_inputs);
        let proof = prover.prove(trace).expect("Proof generation failed");

        let mut bad_inputs = public_inputs;
        bad_inputs.id_com[0] = BaseElement::new(999);
        assert!(!verify_proof(&proof, &bad_inputs), "Wrong public inputs must fail");
    }
}
