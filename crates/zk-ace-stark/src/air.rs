//! ZK-ACE STARK AIR — 128-bit post-quantum security via 4-element commitments.
//!
//! All security-critical values (id_com, target, rp_com, tx_hash) use the
//! FULL 4-element (256-bit) Rescue-Prime digest. This provides 128-bit
//! post-quantum preimage resistance (Grover halves 256 to 128).
//!
//! Trace layout (18 columns × 8 rows):
//!   cols  0-3:  id_com[0..4]    — identity commitment (full 256-bit)
//!   cols  4-7:  target[0..4]    — derivation target (full 256-bit)
//!   cols  8-11: rp_com[0..4]    — replay prevention commitment (full 256-bit)
//!   col  12:    ctx_domain      — chain/application domain
//!   cols 13-16: tx_hash[0..4]   — transaction hash (keccak256 split into 4 Goldilocks)
//!   col  17:    step_counter    — 0,1,2,...,7 (ensures non-trivial trace polynomial)
//!
//! Transition constraints (18 total):
//!   cols 0-16: next[i] == current[i]  (constancy)
//!   col 17:    next[17] == current[17] + 1  (step counter)
//!
//! Boundary assertions (18 total, all at row 0):
//!   id_com[0..4] == public_inputs[0..4]
//!   target[0..4] == public_inputs[4..8]
//!   rp_com[0..4] == public_inputs[8..12]
//!   ctx_domain   == public_inputs[12]
//!   tx_hash[0..4] == public_inputs[13..17]
//!   step_counter == 0

use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// ---------- Public Inputs ----------

/// Public inputs for ZK-ACE STARK proof (256-bit commitments).
#[derive(Clone, Debug)]
pub struct ZkAcePublicInputs {
    /// Identity commitment — 4 Goldilocks elements = 256-bit Rescue digest
    pub id_com: [BaseElement; 4],
    /// Derivation target — 4 elements
    pub target: [BaseElement; 4],
    /// Replay prevention commitment — 4 elements
    pub rp_com: [BaseElement; 4],
    /// Chain/application domain — 1 element
    pub domain: BaseElement,
    /// Transaction hash — 4 elements (keccak256 split into Goldilocks)
    pub tx_hash: [BaseElement; 4],
}

impl ToElements<BaseElement> for ZkAcePublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(17);
        v.extend_from_slice(&self.id_com);
        v.extend_from_slice(&self.target);
        v.extend_from_slice(&self.rp_com);
        v.push(self.domain);
        v.extend_from_slice(&self.tx_hash);
        v
    }
}

pub const TRACE_WIDTH: usize = 18;
pub const TRACE_LENGTH: usize = 8;
pub const NUM_PUB_INPUTS: usize = 17;

// ---------- AIR ----------

pub struct ZkAceAir {
    context: AirContext<BaseElement>,
    public_inputs: ZkAcePublicInputs,
}

impl Air for ZkAceAir {
    type BaseField = BaseElement;
    type PublicInputs = ZkAcePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // 18 transition constraints (all degree 1)
        let degrees = vec![TransitionConstraintDegree::new(1); TRACE_WIDTH];
        // 18 boundary assertions
        let num_assertions = TRACE_WIDTH;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        Self {
            context,
            public_inputs: pub_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Constancy for cols 0..17
        for i in 0..17 {
            result[i] = next[i] - current[i];
        }
        // Step counter: next[17] == current[17] + 1
        result[17] = next[17] - current[17] - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let pi = &self.public_inputs;
        let mut assertions = Vec::with_capacity(TRACE_WIDTH);

        // id_com[0..4] at row 0
        for i in 0..4 {
            assertions.push(Assertion::single(i, 0, pi.id_com[i]));
        }
        // target[0..4] at row 0
        for i in 0..4 {
            assertions.push(Assertion::single(4 + i, 0, pi.target[i]));
        }
        // rp_com[0..4] at row 0
        for i in 0..4 {
            assertions.push(Assertion::single(8 + i, 0, pi.rp_com[i]));
        }
        // ctx_domain at row 0
        assertions.push(Assertion::single(12, 0, pi.domain));
        // tx_hash[0..4] at row 0
        for i in 0..4 {
            assertions.push(Assertion::single(13 + i, 0, pi.tx_hash[i]));
        }
        // step_counter at row 0 = 0
        assertions.push(Assertion::single(17, 0, BaseElement::ZERO));

        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}
