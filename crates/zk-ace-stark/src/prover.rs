//! ZK-ACE STARK Prover — 128-bit post-quantum via 4-element commitments.

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::air::{ZkAceAir, ZkAcePublicInputs, TRACE_LENGTH, TRACE_WIDTH};
use crate::poseidon2::poseidon2_hash_full;
use crate::rescue::rescue_hash_full;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashChoice {
    RescuePrime,
    Poseidon2,
}

impl Default for HashChoice {
    fn default() -> Self {
        Self::Poseidon2
    }
}

impl HashChoice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RescuePrime => "rescue",
            Self::Poseidon2 => "poseidon2",
        }
    }
}

fn hash_full(hash_choice: HashChoice, inputs: &[BaseElement]) -> [BaseElement; 4] {
    match hash_choice {
        HashChoice::RescuePrime => rescue_hash_full(inputs),
        HashChoice::Poseidon2 => poseidon2_hash_full(inputs),
    }
}

/// Private witness for ZK-ACE STARK proof.
/// Private witness — no Clone/Debug to prevent REV leakage.
pub struct ZkAceWitness {
    pub rev: BaseElement,
    pub salt: BaseElement,
    pub alg_id: BaseElement,
    pub ctx_domain: BaseElement,
    pub ctx_index: BaseElement,
    pub nonce: BaseElement,
    pub hash_choice: HashChoice,
}

fn derive_commitments(
    witness: &ZkAceWitness,
) -> ([BaseElement; 4], [BaseElement; 4], [BaseElement; 4]) {
    let id_com = hash_full(
        witness.hash_choice,
        &[witness.rev, witness.salt, witness.ctx_domain],
    );

    let derived_key = hash_full(
        witness.hash_choice,
        &[witness.rev, witness.alg_id, witness.ctx_domain, witness.ctx_index],
    );
    let target = hash_full(witness.hash_choice, &derived_key);

    let rp_com = hash_full(
        witness.hash_choice,
        &[id_com[0], id_com[1], id_com[2], id_com[3], witness.nonce],
    );

    (id_com, target, rp_com)
}

/// Compute public inputs from witness using the selected 4-element hash.
pub fn compute_public_inputs(
    witness: &ZkAceWitness,
    tx_hash: [BaseElement; 4],
) -> ZkAcePublicInputs {
    let (id_com, target, rp_com) = derive_commitments(witness);

    ZkAcePublicInputs {
        id_com,
        target,
        rp_com,
        domain: witness.ctx_domain,
        tx_hash,
    }
}

// ---------- Prover ----------

pub struct ZkAceProver {
    options: ProofOptions,
}

impl ZkAceProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(
        &self,
        witness: &ZkAceWitness,
        public_inputs: &ZkAcePublicInputs,
    ) -> TraceTable<BaseElement> {
        let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);

        let (id_com, target, rp_com) = derive_commitments(witness);

        trace.fill(
            |state| {
                // cols 0-3: id_com (4 elements)
                state[0] = id_com[0];
                state[1] = id_com[1];
                state[2] = id_com[2];
                state[3] = id_com[3];
                // cols 4-7: target (4 elements)
                state[4] = target[0];
                state[5] = target[1];
                state[6] = target[2];
                state[7] = target[3];
                // cols 8-11: rp_com (4 elements)
                state[8] = rp_com[0];
                state[9] = rp_com[1];
                state[10] = rp_com[2];
                state[11] = rp_com[3];
                // col 12: ctx_domain
                state[12] = witness.ctx_domain;
                // cols 13-16: tx_hash (4 elements)
                state[13] = public_inputs.tx_hash[0];
                state[14] = public_inputs.tx_hash[1];
                state[15] = public_inputs.tx_hash[2];
                state[16] = public_inputs.tx_hash[3];
                // col 17: step counter
                state[17] = BaseElement::ZERO;
            },
            |_, state| {
                state[17] += BaseElement::ONE;
            },
        );

        trace
    }
}

impl Prover for ZkAceProver {
    type BaseField = BaseElement;
    type Air = ZkAceAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = crate::keccak_hasher::KeccakHash;
    type VC = winterfell::crypto::MerkleTree<Self::HashFn>;
    type RandomCoin = winterfell::crypto::DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> ZkAcePublicInputs {
        ZkAcePublicInputs {
            id_com: [trace.get(0, 0), trace.get(1, 0), trace.get(2, 0), trace.get(3, 0)],
            target: [trace.get(4, 0), trace.get(5, 0), trace.get(6, 0), trace.get(7, 0)],
            rp_com: [trace.get(8, 0), trace.get(9, 0), trace.get(10, 0), trace.get(11, 0)],
            domain: trace.get(12, 0),
            tx_hash: [trace.get(13, 0), trace.get(14, 0), trace.get(15, 0), trace.get(16, 0)],
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self, trace_info: &TraceInfo, main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>, partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self, composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>, partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace, num_constraint_composition_columns, domain, partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self, air: &'a Self::Air, aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Proof options: 128-bit post-quantum security.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        44,  // queries: ceil(128/3) = 43, +1 for margin
        8,   // blowup factor
        20,  // grinding factor (20-bit PoW)
        winterfell::FieldExtension::Quadratic,
        8,   // FRI folding factor
        31,  // FRI max remainder polynomial degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::Trace as _;

    fn test_witness(hash_choice: HashChoice) -> (ZkAceWitness, ZkAcePublicInputs) {
        let witness = ZkAceWitness {
            rev: BaseElement::new(0xDEAD_BEEF_CAFE_BABEu64),
            salt: BaseElement::new(0x1234_5678_9ABC_DEF0u64),
            alg_id: BaseElement::new(1),
            ctx_domain: BaseElement::new(42161),
            ctx_index: BaseElement::new(0),
            nonce: BaseElement::new(0),
            hash_choice,
        };
        // tx_hash: keccak256 split into 4 Goldilocks elements
        let tx_hash = [
            BaseElement::new(0xAAAA_BBBB_CCCC_DDDDu64),
            BaseElement::new(0x1111_2222_3333_4444u64),
            BaseElement::new(0x5555_6666_7777_8888u64),
            BaseElement::new(0x9999_0000_AAAA_BBBBu64),
        ];
        let public_inputs = compute_public_inputs(&witness, tx_hash);
        (witness, public_inputs)
    }

    #[test]
    fn build_trace_succeeds() {
        for hash_choice in [HashChoice::RescuePrime, HashChoice::Poseidon2] {
            let (witness, public_inputs) = test_witness(hash_choice);
            let prover = ZkAceProver::new(default_proof_options());
            let trace = prover.build_trace(&witness, &public_inputs);
            assert_eq!(trace.width(), TRACE_WIDTH);
            assert_eq!(trace.length(), TRACE_LENGTH);
        }
    }

    #[test]
    fn prove_and_get_proof_size() {
        for hash_choice in [HashChoice::RescuePrime, HashChoice::Poseidon2] {
            let (witness, public_inputs) = test_witness(hash_choice);
            let prover = ZkAceProver::new(default_proof_options());
            let trace = prover.build_trace(&witness, &public_inputs);
            let proof = prover.prove(trace).expect("Proof generation failed");
            let proof_bytes = proof.to_bytes();
            println!(
                "STARK proof size for {} commitments: {} bytes ({:.1} KB)",
                hash_choice.as_str(),
                proof_bytes.len(),
                proof_bytes.len() as f64 / 1024.0
            );
            assert!(proof_bytes.len() < 300_000, "Proof should be under 300 KB");
        }
    }

    #[test]
    fn public_inputs_change_with_hash_choice() {
        let (_, rescue_public_inputs) = test_witness(HashChoice::RescuePrime);
        let (_, poseidon2_public_inputs) = test_witness(HashChoice::Poseidon2);

        assert_ne!(rescue_public_inputs.id_com, poseidon2_public_inputs.id_com);
        assert_ne!(rescue_public_inputs.target, poseidon2_public_inputs.target);
        assert_ne!(rescue_public_inputs.rp_com, poseidon2_public_inputs.rp_com);
    }
}
