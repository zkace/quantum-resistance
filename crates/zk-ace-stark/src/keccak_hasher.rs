//! Keccak256 hasher for Winterfell STARK proofs.
//!
//! Uses the original Keccak-256 (NOT NIST SHA-3) to match the EVM's
//! `keccak256` opcode exactly. This means Merkle verification and
//! Fiat-Shamir transcript reconstruction in Solidity costs only 30 gas
//! per hash call (native EVM opcode).
//!
//! Post-quantum security: Keccak-256 is a symmetric primitive. Its
//! security against quantum adversaries is 128 bits (Grover's algorithm
//! halves the security level of symmetric primitives).

use core::fmt;
use tiny_keccak::{Hasher as KeccakTrait, Keccak};
use winterfell::crypto::{Digest, ElementHasher, Hasher};
use winterfell::math::{fields::f64::BaseElement, FieldElement, StarkField};
use winter_utils::{ByteWriter, ByteReader, Deserializable, DeserializationError, Serializable};

// ============================================================
// Digest type
// ============================================================

/// 32-byte digest matching Keccak-256 output.
#[derive(Copy, Clone, Eq, PartialEq, Default)]
pub struct KeccakDigest([u8; 32]);

impl fmt::Debug for KeccakDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeccakDigest(0x{})", hex::encode(self.0))
    }
}

impl Digest for KeccakDigest {
    fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Serializable for KeccakDigest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_bytes(&self.0);
    }
}

impl Deserializable for KeccakDigest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let bytes = source.read_array::<32>()?;
        Ok(KeccakDigest(bytes))
    }
}

// ============================================================
// Helper: raw keccak256
// ============================================================

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn digests_as_bytes(digests: &[KeccakDigest]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(digests.len() * 32);
    for d in digests {
        bytes.extend_from_slice(&d.0);
    }
    bytes
}

// ============================================================
// Hasher implementation
// ============================================================

/// Keccak-256 hasher for Winterfell STARK proofs.
/// Matches the EVM's `keccak256` opcode exactly.
pub struct KeccakHash;

impl Hasher for KeccakHash {
    type Digest = KeccakDigest;

    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: &[u8]) -> Self::Digest {
        KeccakDigest(keccak256(bytes))
    }

    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&values[0].0);
        data[32..].copy_from_slice(&values[1].0);
        KeccakDigest(keccak256(&data))
    }

    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        KeccakDigest(keccak256(&digests_as_bytes(values)))
    }

    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&seed.0);
        data[32..].copy_from_slice(&value.to_le_bytes());
        KeccakDigest(keccak256(&data))
    }
}

impl ElementHasher for KeccakHash {
    type BaseField = BaseElement;

    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        // BaseElement (Goldilocks f64) has IS_CANONICAL = false, so we need to
        // serialize elements to their canonical byte representation before hashing.
        let mut bytes = Vec::with_capacity(elements.len() * 8);
        for elem in elements {
            // Serialize as canonical little-endian 8 bytes
            elem.write_into(&mut bytes);
        }
        KeccakDigest(keccak256(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_hash_matches_evm() {
        // Known test vector: keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let empty_hash = keccak256(b"");
        assert_eq!(
            hex::encode(empty_hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn keccak_hash_nonempty() {
        // keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        let hello_hash = keccak256(b"hello");
        assert_eq!(
            hex::encode(hello_hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn merge_deterministic() {
        let a = KeccakDigest([1u8; 32]);
        let b = KeccakDigest([2u8; 32]);
        let h1 = KeccakHash::merge(&[a, b]);
        let h2 = KeccakHash::merge(&[a, b]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn merge_with_int_deterministic() {
        let seed = KeccakDigest([0xAB; 32]);
        let h1 = KeccakHash::merge_with_int(seed, 42);
        let h2 = KeccakHash::merge_with_int(seed, 42);
        assert_eq!(h1, h2);
    }

    #[test]
    fn merge_with_int_different_values() {
        let seed = KeccakDigest([0xAB; 32]);
        let h1 = KeccakHash::merge_with_int(seed, 1);
        let h2 = KeccakHash::merge_with_int(seed, 2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_elements_deterministic() {
        let elems = vec![BaseElement::new(42), BaseElement::new(100)];
        let h1 = KeccakHash::hash_elements(&elems);
        let h2 = KeccakHash::hash_elements(&elems);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_elements_different_inputs() {
        let h1 = KeccakHash::hash_elements(&[BaseElement::new(1)]);
        let h2 = KeccakHash::hash_elements(&[BaseElement::new(2)]);
        assert_ne!(h1, h2);
    }
}
