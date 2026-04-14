use ark_ff::PrimeField;

/// Derivation context tuple: (AlgID, Domain, Index)
/// Used by the DIDP to derive context-specific keys from REV.
#[derive(Clone)]
pub struct Ctx<F: PrimeField> {
    pub alg_id: F,
    pub domain: F,
    pub index: F,
}

/// Private witness for ZK-ACE authorization proof.
/// Contains REV (the identity root secret) — zeroized on drop.
///
/// SECURITY: Do not derive Debug or Clone. REV must not be logged
/// or duplicated in memory. Use this struct ephemerally.
pub struct ZkAceWitness<F: PrimeField> {
    /// 256-bit Root Entropy Value (identity root)
    pub rev: F,
    /// Commitment salt (random, identity-specific)
    pub salt: F,
    /// Derivation context tuple
    pub ctx: Ctx<F>,
    /// Replay-prevention nonce
    pub nonce: F,
}

impl<F: PrimeField> Drop for ZkAceWitness<F> {
    fn drop(&mut self) {
        // Zeroize REV and salt by overwriting with zero bytes.
        // PrimeField elements are stored as fixed-size limb arrays;
        // writing zeros over them is the best we can do without
        // unsafe access to the internal representation.
        self.rev = F::zero();
        self.salt = F::zero();
    }
}

/// Public inputs for ZK-ACE authorization proof.
#[derive(Clone)]
pub struct ZkAcePublicInputs<F: PrimeField> {
    /// On-chain identity commitment: H(REV || salt || domain)
    pub id_com: F,
    /// Transaction hash to authorize
    pub tx_hash: F,
    /// Chain/application domain tag
    pub domain: F,
    /// Target binding: H(Derive(REV, Ctx))
    pub target: F,
    /// Replay-prevention commitment: H(ID_com || nonce)
    pub rp_com: F,
}
