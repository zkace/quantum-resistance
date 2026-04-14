use hkdf::Hkdf;
use sha2::Sha256;

use crate::types::{DeriveCtx, Rev};

const HKDF_SALT: &[u8] = b"ZK-ACE-DIDP-v1";

/// Derive a context-specific key from REV using HKDF-SHA256 (RFC 5869).
///
/// This is the off-chain DIDP implementation. For the ZK circuit,
/// derivation uses Poseidon (circuit-native). This HKDF function is
/// used for the general identity pipeline (key derivation for signing, etc.).
pub fn derive_key(rev: &Rev, ctx: &DeriveCtx) -> [u8; 32] {
    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM=REV)
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &rev.0);

    // Build info string: AlgID (4 bytes) || Domain (length-prefixed) || Index (4 bytes)
    let mut info = Vec::new();
    info.extend_from_slice(&ctx.alg_id.to_be_bytes());
    info.extend_from_slice(&(ctx.domain.len() as u32).to_be_bytes());
    info.extend_from_slice(&ctx.domain);
    info.extend_from_slice(&ctx.index.to_be_bytes());

    // HKDF-Expand: OKM = HKDF-Expand(PRK, info, 32)
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("HKDF-Expand should not fail with 32-byte output");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let rev = Rev([0x42u8; 32]);
        let ctx = DeriveCtx {
            alg_id: 1,
            domain: b"ethereum".to_vec(),
            index: 0,
        };

        let key1 = derive_key(&rev, &ctx);
        let key2 = derive_key(&rev, &ctx);
        assert_eq!(key1, key2, "Same inputs must produce same key");
    }

    #[test]
    fn context_isolation() {
        let rev = Rev([0x42u8; 32]);
        let ctx1 = DeriveCtx {
            alg_id: 1,
            domain: b"ethereum".to_vec(),
            index: 0,
        };
        let ctx2 = DeriveCtx {
            alg_id: 2,
            domain: b"ethereum".to_vec(),
            index: 0,
        };

        let key1 = derive_key(&rev, &ctx1);
        let key2 = derive_key(&rev, &ctx2);
        assert_ne!(key1, key2, "Different AlgID must produce different keys");
    }

    #[test]
    fn domain_isolation() {
        let rev = Rev([0x42u8; 32]);
        let ctx1 = DeriveCtx {
            alg_id: 1,
            domain: b"arbitrum".to_vec(),
            index: 0,
        };
        let ctx2 = DeriveCtx {
            alg_id: 1,
            domain: b"base".to_vec(),
            index: 0,
        };

        let key1 = derive_key(&rev, &ctx1);
        let key2 = derive_key(&rev, &ctx2);
        assert_ne!(key1, key2, "Different domains must produce different keys");
    }
}
