use proptest::prelude::*;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

const P: u64 = 18446744069414584321; // 2^64 - 2^32 + 1

proptest! {
    #[test]
    fn test_goldilocks_addition_commutative(a in 0..P, b in 0..P) {
        let x = BaseElement::new(a);
        let y = BaseElement::new(b);
        assert_eq!(x + y, y + x);
    }
    
    #[test]
    fn test_goldilocks_addition_associative(a in 0..P, b in 0..P, c in 0..P) {
        let x = BaseElement::new(a);
        let y = BaseElement::new(b);
        let z = BaseElement::new(c);
        assert_eq!((x + y) + z, x + (y + z));
    }

    #[test]
    fn test_goldilocks_multiplication_commutative(a in 0..P, b in 0..P) {
        let x = BaseElement::new(a);
        let y = BaseElement::new(b);
        assert_eq!(x * y, y * x);
    }

    #[test]
    fn test_goldilocks_multiplication_associative(a in 0..P, b in 0..P, c in 0..P) {
        let x = BaseElement::new(a);
        let y = BaseElement::new(b);
        let z = BaseElement::new(c);
        assert_eq!((x * y) * z, x * (y * z));
    }

    #[test]
    fn test_goldilocks_distributive(a in 0..P, b in 0..P, c in 0..P) {
        let x = BaseElement::new(a);
        let y = BaseElement::new(b);
        let z = BaseElement::new(c);
        assert_eq!(x * (y + z), (x * y) + (x * z));
    }

    #[test]
    fn test_goldilocks_inverses(a in 1..P) { // Can't invert 0
        let x = BaseElement::new(a);
        let inv = x.inv();
        assert_eq!(x * inv, BaseElement::ONE);
    }
    
    #[test]
    fn test_goldilocks_negation(a in 0..P) {
        let x = BaseElement::new(a);
        let neg_x = -x;
        assert_eq!(x + neg_x, BaseElement::ZERO);
    }
}
