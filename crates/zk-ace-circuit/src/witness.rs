use ark_crypto_primitives::sponge::{
    poseidon::PoseidonSponge, Absorb, CryptographicSponge,
};
use ark_ff::PrimeField;

use crate::poseidon::poseidon_config;
use crate::types::{ZkAcePublicInputs, ZkAceWitness};

/// Compute all public inputs from a witness (off-chain, native computation).
/// Uses the same Poseidon parameterization as the circuit for functional equivalence.
pub fn compute_public_inputs<F: PrimeField + Absorb>(
    witness: &ZkAceWitness<F>,
    tx_hash: F,
) -> ZkAcePublicInputs<F> {
    let config = poseidon_config::<F>();

    // ID_com = Poseidon(REV, salt, domain)
    let id_com = native_poseidon_hash(&config, &[witness.rev, witness.salt, witness.ctx.domain]);

    // target = Poseidon(Poseidon(REV, AlgID, Domain, Index))
    let derived_key = native_poseidon_hash(
        &config,
        &[witness.rev, witness.ctx.alg_id, witness.ctx.domain, witness.ctx.index],
    );
    let target = native_poseidon_hash(&config, &[derived_key]);

    // rp_com = Poseidon(ID_com, nonce)
    let rp_com = native_poseidon_hash(&config, &[id_com, witness.nonce]);

    ZkAcePublicInputs {
        id_com,
        tx_hash,
        domain: witness.ctx.domain,
        target,
        rp_com,
    }
}

/// Native (off-chain) Poseidon hash using the same config as the circuit.
pub fn native_poseidon_hash<F: PrimeField + Absorb>(
    config: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F>,
    inputs: &[F],
) -> F {
    let mut sponge = PoseidonSponge::new(config);
    for input in inputs {
        sponge.absorb(input);
    }
    let output: Vec<F> = sponge.squeeze_field_elements(1);
    output[0]
}
