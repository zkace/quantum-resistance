use zeroize::Zeroize;

/// Root Entropy Value — the 256-bit identity root.
/// Zeroized on drop to prevent memory leakage.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Rev(pub [u8; 32]);

/// Derivation context tuple for the DIDP.
#[derive(Clone, Debug)]
pub struct DeriveCtx {
    /// Algorithm identifier (e.g., 1 = Ed25519, 2 = Secp256k1)
    pub alg_id: u32,
    /// Application domain (e.g., chain ID as bytes)
    pub domain: Vec<u8>,
    /// Derivation index
    pub index: u32,
}
