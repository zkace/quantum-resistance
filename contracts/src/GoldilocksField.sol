// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Goldilocks Field Arithmetic
/// @notice Library for arithmetic in the Goldilocks field (p = 2^64 - 2^32 + 1).
///         This is the native field used by the STARK prover (Winterfell/Miden).
/// @dev All operations use EVM's addmod/mulmod for gas-efficient modular arithmetic.
///      Elements are stored as uint256 but must be < P.
library Goldilocks {
    /// @notice The Goldilocks prime: p = 2^64 - 2^32 + 1 = 18446744069414584321
    uint256 internal constant P = 18446744069414584321;

    /// @notice A generator of the multiplicative group of order p-1.
    ///         g = 7 is a primitive root mod p.
    uint256 internal constant GENERATOR = 7;

    /// @notice Modular addition: (a + b) mod p
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, P);
    }

    /// @notice Modular subtraction: (a - b) mod p
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, P - (b % P), P);
    }

    /// @notice Modular multiplication: (a * b) mod p
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }

    /// @notice Modular exponentiation: base^e mod p
    /// @dev Square-and-multiply using mulmod. Gas cost is O(log e).
    function exp(uint256 base, uint256 e) internal pure returns (uint256 result) {
        result = 1;
        base = base % P;
        while (e > 0) {
            if (e & 1 == 1) {
                result = mulmod(result, base, P);
            }
            e >>= 1;
            base = mulmod(base, base, P);
        }
    }

    /// @notice Modular inverse: a^(-1) mod p via Fermat's little theorem.
    /// @dev Returns a^(p-2) mod p. Reverts if a == 0.
    function inv(uint256 a) internal pure returns (uint256) {
        require(a % P != 0, "Goldilocks: zero has no inverse");
        return exp(a, P - 2);
    }

    /// @notice Reduce a uint256 into the Goldilocks field.
    function reduce(uint256 a) internal pure returns (uint256) {
        return a % P;
    }

    /// @notice Check whether a value is a valid field element (< P).
    function isValid(uint256 a) internal pure returns (bool) {
        return a < P;
    }

    // ================================================================
    // Quadratic Extension: elements are (a0, a1) where t^2 - t + 2 = 0
    // i.e. t^2 = t - 2, so (a0+a1*t)(b0+b1*t) = a0b0-2*a1b1 + (a0b1+a1b0+a1b1)*t
    // ================================================================

    /// @notice Multiply two quadratic extension elements.
    /// @param a0 Real part of first element
    /// @param a1 Extension part of first element
    /// @param b0 Real part of second element
    /// @param b1 Extension part of second element
    /// @return r0 Real part of product
    /// @return r1 Extension part of product
    function mulExt(uint256 a0, uint256 a1, uint256 b0, uint256 b1)
        internal pure returns (uint256 r0, uint256 r1)
    {
        uint256 a0b0 = mulmod(a0, b0, P);
        uint256 a1b1 = mulmod(a1, b1, P);
        // r0 = a0*b0 - 2*a1*b1
        r0 = addmod(a0b0, P - mulmod(2, a1b1, P), P);
        // r1 = (a0+a1)*(b0+b1) - a0*b0 = a0b1 + a1b0 + a1b1
        uint256 sumA = addmod(a0, a1, P);
        uint256 sumB = addmod(b0, b1, P);
        r1 = addmod(mulmod(sumA, sumB, P), P - a0b0, P);
    }

    /// @notice Add two quadratic extension elements.
    function addExt(uint256 a0, uint256 a1, uint256 b0, uint256 b1)
        internal pure returns (uint256 r0, uint256 r1)
    {
        r0 = addmod(a0, b0, P);
        r1 = addmod(a1, b1, P);
    }

    /// @notice Subtract two quadratic extension elements.
    function subExt(uint256 a0, uint256 a1, uint256 b0, uint256 b1)
        internal pure returns (uint256 r0, uint256 r1)
    {
        r0 = addmod(a0, P - (b0 % P), P);
        r1 = addmod(a1, P - (b1 % P), P);
    }

    /// @notice Multiply extension element by base field element.
    function mulExtBase(uint256 a0, uint256 a1, uint256 b)
        internal pure returns (uint256 r0, uint256 r1)
    {
        r0 = mulmod(a0, b, P);
        r1 = mulmod(a1, b, P);
    }

    /// @notice Invert a quadratic extension element via the norm.
    /// inv(a0+a1*t) = conjugate / norm where:
    ///   conjugate = frobenius(a) = (a0+a1, -a1) [from Winterfell code]
    ///   norm = a * conj(a) (base field element)
    function invExt(uint256 a0, uint256 a1)
        internal pure returns (uint256 r0, uint256 r1)
    {
        require(a0 % P != 0 || a1 % P != 0, "Goldilocks: zero ext element has no inverse");
        // norm = a0^2 + a0*a1 - 2*a1^2 (computed from a * frobenius(a))
        // frobenius(a0,a1) = (a0+a1, P-a1)
        // a * frob(a) = (a0+a1*t)(a0+a1 - a1*t)
        // = a0(a0+a1) - a1*a0*t + a1*t*(a0+a1) - a1^2*t^2
        // = a0^2 + a0*a1 + a1*t*(a0+a1-a0) - a1^2*(t-2)
        // = a0^2 + a0*a1 + a1^2*t - a1^2*t + 2*a1^2
        // = a0^2 + a0*a1 + 2*a1^2
        uint256 a0sq = mulmod(a0, a0, P);
        uint256 a0a1 = mulmod(a0, a1, P);
        uint256 a1sq = mulmod(a1, a1, P);
        uint256 norm = addmod(addmod(a0sq, a0a1, P), mulmod(2, a1sq, P), P);
        uint256 normInv = exp(norm, P - 2);
        // inv = frobenius(a) / norm = ((a0+a1)*normInv, (P-a1)*normInv)
        r0 = mulmod(addmod(a0, a1, P), normInv, P);
        r1 = mulmod(P - (a1 % P), normInv, P);
    }
}
