use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;

/// Generate a Solidity verifier contract from a Groth16 verifying key.
/// The contract uses BN254 precompiles for pairing checks.
pub fn generate_solidity_verifier(vk: &VerifyingKey<Bn254>) -> String {
    let alpha_g1 = format_g1(&vk.alpha_g1);
    let beta_g2 = format_g2(&vk.beta_g2);
    let gamma_g2 = format_g2(&vk.gamma_g2);
    let delta_g2 = format_g2(&vk.delta_g2);

    let mut ic_entries = String::new();
    for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
        let (x, y) = g1_coords(ic);
        ic_entries.push_str(&format!(
            "        vk.IC[{i}] = Pairing.G1Point({x}, {y});\n"
        ));
    }

    format!(
        r#"// SPDX-License-Identifier: MIT
// Auto-generated Groth16 verifier for ZK-ACE circuit
pragma solidity ^0.8.28;

library Pairing {{
    struct G1Point {{
        uint256 X;
        uint256 Y;
    }}
    struct G2Point {{
        uint256[2] X;
        uint256[2] Y;
    }}

    function negate(G1Point memory p) internal pure returns (G1Point memory) {{
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }}

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }}
        require(success, "ec-add-failed");
    }}

    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {{
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x60)
        }}
        require(success, "ec-mul-failed");
    }}

    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {{
        require(p1.length == p2.length, "pairing-lengths-fail");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {{
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }}
        uint256[1] memory out;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }}
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }}

    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {{
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1; p2[0] = a2;
        p1[1] = b1; p2[1] = b2;
        p1[2] = c1; p2[2] = c2;
        p1[3] = d1; p2[3] = d2;
        return pairing(p1, p2);
    }}
}}

contract ZkAceVerifier {{
    using Pairing for *;

    struct VerifyingKey {{
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }}

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {{
        vk.alpha1 = Pairing.G1Point({alpha_g1});
        vk.beta2 = Pairing.G2Point({beta_g2});
        vk.gamma2 = Pairing.G2Point({gamma_g2});
        vk.delta2 = Pairing.G2Point({delta_g2});
        vk.IC = new Pairing.G1Point[]({ic_len});
{ic_entries}    }}

    /// @dev BN254 scalar field modulus. Public inputs must be less than this.
    uint256 internal constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function verify(uint256[5] memory input, uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) public view returns (bool) {{
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        // Validate all public inputs are valid field elements (HIGH-4 fix)
        for (uint256 i = 0; i < input.length; i++) {{
            require(input[i] < SNARK_SCALAR_FIELD, "verifier-input-gte-snark-scalar-field");
        }}

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint256 i = 0; i < input.length; i++) {{
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }}
        vk_x = Pairing.addition(vk_x, vk.IC[0]);

        return Pairing.pairingProd4(
            Pairing.negate(Pairing.G1Point(a[0], a[1])),
            Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]),
            vk.alpha1, vk.beta2,
            vk_x, vk.gamma2,
            Pairing.G1Point(c[0], c[1]), vk.delta2
        );
    }}

    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[5] memory input
    ) public view returns (bool r) {{
        return verify(input, a, b, c);
    }}
}}
"#,
        alpha_g1 = alpha_g1,
        beta_g2 = beta_g2,
        gamma_g2 = gamma_g2,
        delta_g2 = delta_g2,
        ic_len = vk.gamma_abc_g1.len(),
        ic_entries = ic_entries,
    )
}

fn g1_coords(p: &G1Affine) -> (String, String) {
    let x = fq_to_decimal(p.x().unwrap());
    let y = fq_to_decimal(p.y().unwrap());
    (x, y)
}

fn format_g1(p: &G1Affine) -> String {
    let (x, y) = g1_coords(p);
    format!("{x}, {y}")
}

fn format_g2(p: &G2Affine) -> String {
    let x: &Fq2 = p.x().unwrap();
    let y: &Fq2 = p.y().unwrap();
    // EVM expects (imaginary, real) ordering for Fq2
    format!(
        "[{}, {}], [{}, {}]",
        fq_to_decimal(&x.c1), // x_im
        fq_to_decimal(&x.c0), // x_re
        fq_to_decimal(&y.c1), // y_im
        fq_to_decimal(&y.c0), // y_re
    )
}

fn fq_to_decimal(f: &Fq) -> String {
    let bigint = f.into_bigint();
    // Convert to decimal string
    let bytes = bigint.to_bytes_be();
    // Use a simple big-endian to decimal conversion
    num_to_decimal(&bytes)
}

/// Convert big-endian bytes to decimal string.
fn num_to_decimal(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return "0".to_string();
    }
    // Work with the big integer as a sequence of bytes
    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes {
        // Multiply existing number by 256
        let mut carry = 0u16;
        for d in digits.iter_mut() {
            let val = (*d as u16) * 256 + carry;
            *d = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
        // Add the new byte
        let mut carry = byte as u16;
        for d in digits.iter_mut() {
            let val = (*d as u16) + carry;
            *d = (val % 10) as u8;
            carry = val / 10;
            if carry == 0 {
                break;
            }
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.reverse();
    digits.iter().map(|d| (b'0' + d) as char).collect()
}
