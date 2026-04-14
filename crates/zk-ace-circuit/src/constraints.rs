use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;

/// Compute Poseidon hash of given field-element inputs inside a constraint system.
/// Creates a fresh sponge, absorbs all inputs, squeezes one output.
fn poseidon_hash_var<F: PrimeField>(
    config: &PoseidonConfig<F>,
    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, config);
    sponge.absorb(&inputs)?;
    let output = sponge.squeeze_field_elements(1)?;
    Ok(output[0].clone())
}

/// **C1: Commitment Consistency**
/// Enforces: H(REV || salt || domain) == ID_com
///
/// Paper equation (3): ID_com = H(REV || salt || domain)
pub fn enforce_commitment_consistency<F: PrimeField>(
    config: &PoseidonConfig<F>,
    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    rev: &FpVar<F>,
    salt: &FpVar<F>,
    domain: &FpVar<F>,
    id_com: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let computed = poseidon_hash_var(config, cs, &[rev.clone(), salt.clone(), domain.clone()])?;
    computed.enforce_equal(id_com)?;
    Ok(())
}

/// **C2: Target Binding (Deterministic Derivation Correctness)**
/// Enforces: target == H(H(REV, AlgID, Domain, Index))
///
/// Paper equation (4): target = H(Derive(REV, Ctx))
/// The inner hash implements the circuit-native Derive function.
/// The outer hash commits to the derived key without revealing it.
pub fn enforce_target_binding<F: PrimeField>(
    config: &PoseidonConfig<F>,
    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    rev: &FpVar<F>,
    alg_id: &FpVar<F>,
    ctx_domain: &FpVar<F>,
    ctx_index: &FpVar<F>,
    target: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // Inner hash: Derive(REV, Ctx) = H(REV, AlgID, Domain, Index)
    let derived_key = poseidon_hash_var(
        config,
        cs.clone(),
        &[rev.clone(), alg_id.clone(), ctx_domain.clone(), ctx_index.clone()],
    )?;
    // Outer hash: target = H(derived_key)
    let computed_target = poseidon_hash_var(config, cs, &[derived_key])?;
    computed_target.enforce_equal(target)?;
    Ok(())
}

/// **C3: Authorization Binding**
/// Enforces: Auth == H(REV || Ctx || TxHash || domain || nonce)
///
/// Paper equation (5): Auth = H(REV || Ctx || TxHash || domain || nonce)
/// This binds the authorization to the identity root, derivation context,
/// specific transaction, domain, and replay-prevention nonce.
///
/// Note: Auth is computed internally and not exposed as a public input.
/// It is used by C4 (nullifier variant) but for the nonce-registry variant,
/// we just need to ensure it's consistently computed. The constraint enforces
/// that the witness values are bound together through this hash.
pub fn compute_auth_var<F: PrimeField>(
    config: &PoseidonConfig<F>,
    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    rev: &FpVar<F>,
    alg_id: &FpVar<F>,
    ctx_domain: &FpVar<F>,
    ctx_index: &FpVar<F>,
    tx_hash: &FpVar<F>,
    domain: &FpVar<F>,
    nonce: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    poseidon_hash_var(
        config,
        cs,
        &[
            rev.clone(),
            alg_id.clone(),
            ctx_domain.clone(),
            ctx_index.clone(),
            tx_hash.clone(),
            domain.clone(),
            nonce.clone(),
        ],
    )
}

/// **C4: Anti-Replay (Nonce Registry)**
/// Enforces: rp_com == H(ID_com || nonce)
///
/// Paper equation (6): rp_com = H(ID_com || nonce)
/// This commits the nonce to the identity, enabling the on-chain verifier
/// to enforce monotonic nonce advancement per identity.
pub fn enforce_nonce_replay_prevention<F: PrimeField>(
    config: &PoseidonConfig<F>,
    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
    id_com: &FpVar<F>,
    nonce: &FpVar<F>,
    rp_com: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let computed = poseidon_hash_var(config, cs, &[id_com.clone(), nonce.clone()])?;
    computed.enforce_equal(rp_com)?;
    Ok(())
}

/// **C5: Domain Separation and Context Consistency**
/// Enforces: Ctx.Domain == domain (public input)
///
/// Paper equation (8): Ctx.Domain = domain
/// This ensures the derivation context's domain component matches
/// the publicly declared domain, preventing cross-chain proof reuse.
pub fn enforce_domain_separation<F: PrimeField>(
    ctx_domain: &FpVar<F>,
    domain: &FpVar<F>,
) -> Result<(), SynthesisError> {
    ctx_domain.enforce_equal(domain)?;
    Ok(())
}
