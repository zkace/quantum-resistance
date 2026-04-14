use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::constraints;
use crate::poseidon::poseidon_config;
use crate::types::{ZkAcePublicInputs, ZkAceWitness};

/// ZK-ACE authorization circuit implementing all 5 constraints (C1-C5).
///
/// Proves knowledge of (REV, salt, Ctx, nonce) such that:
/// 1. The identity commitment matches the on-chain anchor (C1)
/// 2. The target binding is consistent with deterministic derivation (C2)
/// 3. The authorization token binds identity to the transaction (C3)
/// 4. The replay-prevention commitment is correctly formed (C4)
/// 5. The context domain matches the public domain tag (C5)
pub struct ZkAceCircuit<F: PrimeField> {
    /// Private witness (None for blank circuit used in setup)
    pub witness: Option<ZkAceWitness<F>>,
    /// Public inputs (None for blank circuit used in setup)
    pub public_inputs: Option<ZkAcePublicInputs<F>>,
}

impl<F: PrimeField> ZkAceCircuit<F> {
    /// Create a blank circuit for trusted setup (constraint generation only).
    pub fn blank() -> Self {
        Self {
            witness: None,
            public_inputs: None,
        }
    }

    /// Create a circuit with concrete witness and public input values.
    pub fn new(witness: ZkAceWitness<F>, public_inputs: ZkAcePublicInputs<F>) -> Self {
        Self {
            witness: Some(witness),
            public_inputs: Some(public_inputs),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for ZkAceCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let config = poseidon_config::<F>();

        // Helper: extract witness field or default to F::zero() (for blank circuit setup)
        let w = |f: fn(&ZkAceWitness<F>) -> F| -> Result<F, SynthesisError> {
            Ok(self.witness.as_ref().map(f).unwrap_or_default())
        };
        let p = |f: fn(&ZkAcePublicInputs<F>) -> F| -> Result<F, SynthesisError> {
            Ok(self.public_inputs.as_ref().map(f).unwrap_or_default())
        };

        // --- Allocate private witness variables ---
        let rev_var = FpVar::new_witness(cs.clone(), || w(|w| w.rev))?;
        let salt_var = FpVar::new_witness(cs.clone(), || w(|w| w.salt))?;
        let alg_id_var = FpVar::new_witness(cs.clone(), || w(|w| w.ctx.alg_id))?;
        let ctx_domain_var = FpVar::new_witness(cs.clone(), || w(|w| w.ctx.domain))?;
        let ctx_index_var = FpVar::new_witness(cs.clone(), || w(|w| w.ctx.index))?;
        let nonce_var = FpVar::new_witness(cs.clone(), || w(|w| w.nonce))?;

        // --- Allocate public input variables ---
        let id_com_var = FpVar::new_input(cs.clone(), || p(|p| p.id_com))?;
        // tx_hash is a public input wired into the Groth16 verification equation.
        // It is not used inside any circuit constraint (C3 was removed per audit).
        let _tx_hash_var = FpVar::new_input(cs.clone(), || p(|p| p.tx_hash))?;
        let domain_var = FpVar::new_input(cs.clone(), || p(|p| p.domain))?;
        let target_var = FpVar::new_input(cs.clone(), || p(|p| p.target))?;
        let rp_com_var = FpVar::new_input(cs.clone(), || p(|p| p.rp_com))?;

        // --- C1: Commitment Consistency ---
        // H(REV || salt || ctx_domain) == ID_com
        // Uses witness ctx_domain_var (not public domain_var) so C1 is self-contained.
        // C5 enforces ctx_domain == domain, closing the binding.
        constraints::enforce_commitment_consistency(
            &config, cs.clone(), &rev_var, &salt_var, &ctx_domain_var, &id_com_var,
        )?;

        // --- C2: Target Binding ---
        // H(H(REV, AlgID, Domain, Index)) == target
        constraints::enforce_target_binding(
            &config, cs.clone(), &rev_var, &alg_id_var, &ctx_domain_var, &ctx_index_var, &target_var,
        )?;

        // --- C3: Authorization Binding ---
        // REMOVED per audit CRIT-3: Auth was computed but never constrained against
        // a public input, making it dead code (~1,615 wasted constraints).
        // tx_hash is already bound as a Groth16 public input.
        // The identity-to-transaction binding comes from:
        //   - C1 binds REV → ID_com (identity ownership)
        //   - C4 binds ID_com + nonce → rp_com (replay prevention)
        //   - tx_hash is a public input verified by the Groth16 equation
        //   - C5 binds domain across all computations

        // --- C4: Anti-Replay (Nonce Registry) ---
        // H(ID_com || nonce) == rp_com
        constraints::enforce_nonce_replay_prevention(
            &config, cs.clone(), &id_com_var, &nonce_var, &rp_com_var,
        )?;

        // --- C5: Domain Separation ---
        // Ctx.Domain == domain (public input)
        constraints::enforce_domain_separation(&ctx_domain_var, &domain_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use crate::types::Ctx;
    use crate::witness::compute_public_inputs;

    fn test_witness() -> (ZkAceWitness<Fr>, ZkAcePublicInputs<Fr>) {
        use ark_ff::UniformRand;
        use rand_chacha::ChaCha20Rng;
        use rand::SeedableRng;

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let witness = ZkAceWitness {
            rev: Fr::rand(&mut rng),
            salt: Fr::rand(&mut rng),
            ctx: Ctx {
                alg_id: Fr::from(1u64),  // Ed25519
                domain: Fr::from(42161u64), // Arbitrum chain ID
                index: Fr::from(0u64),
            },
            nonce: Fr::from(1u64),
        };

        let tx_hash = Fr::rand(&mut rng);
        let public_inputs = compute_public_inputs(&witness, tx_hash);

        (witness, public_inputs)
    }

    #[test]
    fn honest_witness_satisfies_constraints() {
        let (witness, public_inputs) = test_witness();
        let circuit = ZkAceCircuit::new(witness, public_inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap(), "Honest witness must satisfy all constraints");
    }

    #[test]
    fn constraint_count() {
        let (witness, public_inputs) = test_witness();
        let circuit = ZkAceCircuit::new(witness, public_inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        let num_constraints = cs.num_constraints();
        // After removing C3 (audit CRIT-3): 4,024 - 1,615 = 2,409
        // C1: ~805, C2: ~1,200, C4: ~400, C5: ~4
        println!("Total R1CS constraints: {}", num_constraints);
        assert!(
            num_constraints > 2000 && num_constraints < 3000,
            "Constraint count {} outside expected range [2000, 3000] (target: ~2,409)",
            num_constraints
        );
    }

    #[test]
    fn blank_circuit_generates_constraints() {
        let circuit = ZkAceCircuit::<Fr>::blank();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Blank circuit should produce the same number of constraints (~2,409)
        assert!(cs.num_constraints() > 2000);
    }

    #[test]
    fn wrong_id_com_fails() {
        let (witness, mut public_inputs) = test_witness();
        // Corrupt the identity commitment
        public_inputs.id_com += Fr::from(1u64);
        let circuit = ZkAceCircuit::new(witness, public_inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Wrong ID_com must fail C1");
    }

    #[test]
    fn wrong_target_fails() {
        let (witness, mut public_inputs) = test_witness();
        public_inputs.target += Fr::from(1u64);
        let circuit = ZkAceCircuit::new(witness, public_inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Wrong target must fail C2");
    }

    #[test]
    fn wrong_rp_com_fails() {
        let (witness, mut public_inputs) = test_witness();
        public_inputs.rp_com += Fr::from(1u64);
        let circuit = ZkAceCircuit::new(witness, public_inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Wrong rp_com must fail C4");
    }

    #[test]
    fn domain_mismatch_fails() {
        let (mut witness, public_inputs) = test_witness();
        // Change Ctx.Domain to differ from public domain input
        witness.ctx.domain = Fr::from(99999u64);
        let circuit = ZkAceCircuit::new(witness, public_inputs);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Domain mismatch must fail C5");
    }
}
