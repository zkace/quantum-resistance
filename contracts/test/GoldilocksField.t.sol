// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/GoldilocksField.sol";

contract GoldilocksFieldTest is Test {
    using Goldilocks for uint256;

    uint256 constant P = 18446744069414584321;

    // ===== Addition =====

    function test_addZero() public pure {
        assertEq(Goldilocks.add(0, 0), 0);
        assertEq(Goldilocks.add(42, 0), 42);
        assertEq(Goldilocks.add(0, 42), 42);
    }

    function test_addBasic() public pure {
        assertEq(Goldilocks.add(1, 1), 2);
        assertEq(Goldilocks.add(100, 200), 300);
    }

    function test_addWraps() public pure {
        // (P-1) + 1 = 0 mod P
        assertEq(Goldilocks.add(P - 1, 1), 0);
        // (P-1) + 2 = 1 mod P
        assertEq(Goldilocks.add(P - 1, 2), 1);
        // (P-1) + (P-1) = 2P - 2 mod P = P - 2
        assertEq(Goldilocks.add(P - 1, P - 1), P - 2);
    }

    function test_addCommutative() public pure {
        uint256 a = 123456789;
        uint256 b = 987654321;
        assertEq(Goldilocks.add(a, b), Goldilocks.add(b, a));
    }

    // ===== Subtraction =====

    function test_subZero() public pure {
        assertEq(Goldilocks.sub(42, 0), 42);
        assertEq(Goldilocks.sub(0, 0), 0);
    }

    function test_subBasic() public pure {
        assertEq(Goldilocks.sub(10, 3), 7);
        assertEq(Goldilocks.sub(1000, 1), 999);
    }

    function test_subWraps() public pure {
        // 0 - 1 = P - 1 mod P
        assertEq(Goldilocks.sub(0, 1), P - 1);
        // 1 - 2 = P - 1 mod P
        assertEq(Goldilocks.sub(1, 2), P - 1);
        // 0 - (P-1) = 1 mod P
        assertEq(Goldilocks.sub(0, P - 1), 1);
    }

    function test_addSubInverse() public pure {
        uint256 a = 7777777;
        uint256 b = 3333333;
        // (a + b) - b == a
        assertEq(Goldilocks.sub(Goldilocks.add(a, b), b), a);
    }

    // ===== Multiplication =====

    function test_mulZero() public pure {
        assertEq(Goldilocks.mul(0, 0), 0);
        assertEq(Goldilocks.mul(42, 0), 0);
        assertEq(Goldilocks.mul(0, 42), 0);
    }

    function test_mulOne() public pure {
        assertEq(Goldilocks.mul(42, 1), 42);
        assertEq(Goldilocks.mul(1, 42), 42);
        assertEq(Goldilocks.mul(P - 1, 1), P - 1);
    }

    function test_mulBasic() public pure {
        assertEq(Goldilocks.mul(3, 7), 21);
        assertEq(Goldilocks.mul(100, 100), 10000);
    }

    function test_mulLargeValues() public pure {
        // (P-1) * (P-1) = 1 mod P (because (-1)*(-1) = 1)
        assertEq(Goldilocks.mul(P - 1, P - 1), 1);
        // (P-1) * 2 = P - 2 mod P (because (-1)*2 = -2)
        assertEq(Goldilocks.mul(P - 1, 2), P - 2);
    }

    function test_mulCommutative() public pure {
        uint256 a = 123456789;
        uint256 b = 987654321;
        assertEq(Goldilocks.mul(a, b), Goldilocks.mul(b, a));
    }

    function test_mulDistributive() public pure {
        uint256 a = 111;
        uint256 b = 222;
        uint256 c = 333;
        // a * (b + c) == a*b + a*c
        uint256 lhs = Goldilocks.mul(a, Goldilocks.add(b, c));
        uint256 rhs = Goldilocks.add(Goldilocks.mul(a, b), Goldilocks.mul(a, c));
        assertEq(lhs, rhs);
    }

    // ===== Exponentiation =====

    function test_expZero() public pure {
        // a^0 = 1 for all a != 0
        assertEq(Goldilocks.exp(42, 0), 1);
        assertEq(Goldilocks.exp(P - 1, 0), 1);
        // 0^0 = 1 (convention)
        assertEq(Goldilocks.exp(0, 0), 1);
    }

    function test_expOne() public pure {
        assertEq(Goldilocks.exp(42, 1), 42);
        assertEq(Goldilocks.exp(P - 1, 1), P - 1);
    }

    function test_expSmall() public pure {
        // 2^10 = 1024
        assertEq(Goldilocks.exp(2, 10), 1024);
        // 3^5 = 243
        assertEq(Goldilocks.exp(3, 5), 243);
    }

    function test_expFermatLittleTheorem() public pure {
        // a^(P-1) == 1 mod P for a != 0 (Fermat's little theorem)
        assertEq(Goldilocks.exp(2, P - 1), 1);
        assertEq(Goldilocks.exp(7, P - 1), 1);
        assertEq(Goldilocks.exp(123456789, P - 1), 1);
        assertEq(Goldilocks.exp(P - 1, P - 1), 1);
    }

    function test_expGeneratorOrder() public pure {
        // g = 7 is a primitive root, so g^(P-1) = 1 and g^((P-1)/2) = P-1 (Euler criterion)
        uint256 g = Goldilocks.GENERATOR;
        assertEq(Goldilocks.exp(g, P - 1), 1);
        // g^((P-1)/2) should be P-1 (i.e., -1) since 7 is a quadratic non-residue
        assertEq(Goldilocks.exp(g, (P - 1) / 2), P - 1);
    }

    // ===== Inverse =====

    function test_invBasic() public pure {
        // inv(1) = 1
        assertEq(Goldilocks.inv(1), 1);
        // inv(P-1) = P-1 (because (-1)^(-1) = -1)
        assertEq(Goldilocks.inv(P - 1), P - 1);
    }

    function test_invMulIdentity() public pure {
        // a * inv(a) == 1 for various a
        uint256[5] memory testValues = [uint256(2), 3, 7, 123456789, P - 2];
        for (uint256 i = 0; i < testValues.length; i++) {
            uint256 a = testValues[i];
            uint256 aInv = Goldilocks.inv(a);
            assertEq(Goldilocks.mul(a, aInv), 1, "a * inv(a) should be 1");
        }
    }

    function test_invOfTwo() public pure {
        // inv(2) should satisfy 2 * inv(2) = 1 mod P
        uint256 inv2 = Goldilocks.inv(2);
        assertEq(Goldilocks.mul(2, inv2), 1);
        // inv(2) = (P + 1) / 2 for odd prime P
        assertEq(inv2, (P + 1) / 2);
    }

    function test_invRevertsOnZero() public {
        // Library internal calls with via_ir don't work with vm.expectRevert
        // Test via an external call instead
        try this.callInv(0) returns (uint256) {
            fail("Should have reverted");
        } catch {}
    }

    function test_invRevertsOnP() public {
        try this.callInv(P) returns (uint256) {
            fail("Should have reverted");
        } catch {}
    }

    // Helper for testing reverts on library calls
    function callInv(uint256 a) external pure returns (uint256) {
        return Goldilocks.inv(a);
    }

    // ===== Reduce =====

    function test_reduceSmall() public pure {
        assertEq(Goldilocks.reduce(0), 0);
        assertEq(Goldilocks.reduce(42), 42);
        assertEq(Goldilocks.reduce(P - 1), P - 1);
    }

    function test_reduceP() public pure {
        assertEq(Goldilocks.reduce(P), 0);
        assertEq(Goldilocks.reduce(P + 1), 1);
        assertEq(Goldilocks.reduce(2 * P), 0);
        assertEq(Goldilocks.reduce(2 * P + 7), 7);
    }

    function test_reduceLargeValue() public pure {
        // A 256-bit value reduces correctly
        uint256 large = type(uint256).max;
        uint256 reduced = Goldilocks.reduce(large);
        assertTrue(reduced < P);
    }

    // ===== IsValid =====

    function test_isValid() public pure {
        assertTrue(Goldilocks.isValid(0));
        assertTrue(Goldilocks.isValid(1));
        assertTrue(Goldilocks.isValid(P - 1));
        assertFalse(Goldilocks.isValid(P));
        assertFalse(Goldilocks.isValid(P + 1));
        assertFalse(Goldilocks.isValid(type(uint256).max));
    }

    // ===== Fuzz Tests =====

    function testFuzz_addCommutative(uint64 a, uint64 b) public pure {
        uint256 x = uint256(a);
        uint256 y = uint256(b);
        assertEq(Goldilocks.add(x, y), Goldilocks.add(y, x));
    }

    function testFuzz_mulCommutative(uint64 a, uint64 b) public pure {
        uint256 x = uint256(a);
        uint256 y = uint256(b);
        assertEq(Goldilocks.mul(x, y), Goldilocks.mul(y, x));
    }

    function testFuzz_addSubCancel(uint64 a, uint64 b) public pure {
        uint256 x = uint256(a) % P;
        uint256 y = uint256(b) % P;
        assertEq(Goldilocks.sub(Goldilocks.add(x, y), y), x);
    }

    function testFuzz_mulInvCancel(uint64 a) public pure {
        vm.assume(a > 0);
        uint256 x = (uint256(a) % (P - 1)) + 1; // ensure 1 <= x < P
        uint256 xInv = Goldilocks.inv(x);
        assertEq(Goldilocks.mul(x, xInv), 1);
    }

    function testFuzz_fermat(uint64 a) public pure {
        vm.assume(a > 0);
        uint256 x = (uint256(a) % (P - 1)) + 1; // ensure 1 <= x < P
        assertEq(Goldilocks.exp(x, P - 1), 1);
    }
}
