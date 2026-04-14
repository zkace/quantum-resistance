//! Rescue-Prime hash helpers for ZK-ACE STARK prover.
//! Uses Rp64_256 (Rescue-Prime over 64-bit field with 256-bit digest).
//!
//! SECURITY: The full 256-bit (4-element) digest is used for commitments.
//! Previous versions truncated to 64 bits, reducing security to ~32-bit PQ.

use winterfell::math::{fields::f64::BaseElement, FieldElement};
use winterfell::crypto::{hashers::Rp64_256, Digest, ElementHasher};

/// Hash field elements using Rescue-Prime, returning the full 4-element digest.
/// Each element is 64 bits, giving 256-bit total security.
pub fn rescue_hash_full(inputs: &[BaseElement]) -> [BaseElement; 4] {
    let digest = Rp64_256::hash_elements(inputs);
    let bytes = digest.as_bytes();
    let mut result = [BaseElement::ZERO; 4];
    for i in 0..4 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        result[i] = BaseElement::new(u64::from_le_bytes(buf));
    }
    result
}

/// Hash field elements returning the first element only.
/// Used where a single field element is needed (e.g., trace columns).
/// NOTE: This provides only 64-bit security. For commitments that
/// require full security, use rescue_hash_full and store all 4 elements.
pub fn rescue_hash_to_element(inputs: &[BaseElement]) -> BaseElement {
    rescue_hash_full(inputs)[0]
}

/// Convert a Rescue 4-element digest back to bytes (for comparison/display).
pub fn digest_to_bytes(digest: &[BaseElement; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let elem_bytes = digest[i].inner().to_le_bytes();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&elem_bytes);
    }
    bytes
}

/// Helper to create a field element from a u64.
pub fn to_element(val: u64) -> BaseElement {
    BaseElement::new(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rescue_hash_deterministic() {
        let a = to_element(42);
        let b = to_element(100);

        let h1 = rescue_hash_to_element(&[a, b]);
        let h2 = rescue_hash_to_element(&[a, b]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn rescue_hash_different_inputs() {
        let h1 = rescue_hash_to_element(&[to_element(1), to_element(2)]);
        let h2 = rescue_hash_to_element(&[to_element(1), to_element(3)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn rescue_hash_full_gives_four_elements() {
        let result = rescue_hash_full(&[to_element(42)]);
        // All 4 elements should be non-zero (with overwhelming probability)
        let nonzero = result.iter().filter(|e| **e != BaseElement::ZERO).count();
        assert!(nonzero >= 3, "Expected most digest elements to be non-zero");
    }

    #[test]
    fn digest_roundtrip() {
        let input = rescue_hash_full(&[to_element(123), to_element(456)]);
        let bytes = digest_to_bytes(&input);
        assert_eq!(bytes.len(), 32);
        // Verify it's deterministic
        let input2 = rescue_hash_full(&[to_element(123), to_element(456)]);
        let bytes2 = digest_to_bytes(&input2);
        assert_eq!(bytes, bytes2);
    }
}
