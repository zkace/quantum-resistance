// SPDX-License-Identifier: MIT
// Auto-generated Groth16 verifier for ZK-ACE circuit
pragma solidity ^0.8.28;

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }
        require(success, "ec-add-failed");
    }

    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x60)
        }
        require(success, "ec-mul-failed");
    }

    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length, "pairing-lengths-fail");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }

    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1; p2[0] = a2;
        p1[1] = b1; p2[1] = b2;
        p1[2] = c1; p2[2] = c2;
        p1[3] = d1; p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract ZkAceVerifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha1 = Pairing.G1Point(15005716679757134904169710821774707008849646766364378811567958699427532929338, 11717043397454311921512517477229756877182037272151846169866906253917360379330);
        vk.beta2 = Pairing.G2Point([11931311314739818496228038909040133910828408858075151350578150521857946825505, 15656382663971804316293044388033530850430526642920628387541653573055132746885], [19506524040411510692522724622187527593607412778995583069524828205597493265720, 21851633273041437361683227591866736654608875128182087882873739109099944799336]);
        vk.gamma2 = Pairing.G2Point([13269181758806463206707986230606330432717060296185385448565426281853680527409, 2708918087474828163810368742833658856497258997053145286216651357094553931462], [14918431804512353258226076332652082841182586990183547294948306811822031531777, 20339934193524690977081984655287159241437519696348316421925858449440758246252]);
        vk.delta2 = Pairing.G2Point([18616805009664152326593732340318341662227542026533170680775623833212639874427, 396429641745665791786160004193354178073292451808192663501657661534169274225], [532834431728289532344237622708862906308877466862077763922833663212215390808, 8772616540789766117503465863620076369098616446495621409146338162437759548888]);
        vk.IC = new Pairing.G1Point[](6);
        vk.IC[0] = Pairing.G1Point(6589150873506804837016600098597869375507863741623336853003438612463402006045, 1193162114900086691294871182573074600175792049253219416503713930709554570821);
        vk.IC[1] = Pairing.G1Point(3283239891016709977586367179142568813086198055905571759820802125639193391079, 4709956271148998906022578067677630403293292230288580575049351083084533160897);
        vk.IC[2] = Pairing.G1Point(1132433931191225179307189639582654670597349093535150793603522601661000504943, 1632012474904901156564337879787975813699389748904855257718135910996992314140);
        vk.IC[3] = Pairing.G1Point(5450693594243051351129872403892998363618877435135630930995562514314025870016, 101014835295343078039378411365907176996810996752856745813805154300040440029);
        vk.IC[4] = Pairing.G1Point(6995938477517038393026313748068177590843617116881365488838486346390696532766, 732609859975205607563376398935468933942657485497379599455402482704881753589);
        vk.IC[5] = Pairing.G1Point(5704534825222232746162993578130113164915383148888475986155277455867973188359, 14805223843908417853011008495423380534298453419002178892560463463039042242584);
    }

    /// @dev BN254 scalar field modulus. Public inputs must be less than this.
    uint256 internal constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function verify(uint256[5] memory input, uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) public view returns (bool) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        // Validate all public inputs are valid field elements (HIGH-4 fix)
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < SNARK_SCALAR_FIELD, "verifier-input-gte-snark-scalar-field");
        }

        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint256 i = 0; i < input.length; i++) {
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.IC[0]);

        return Pairing.pairingProd4(
            Pairing.negate(Pairing.G1Point(a[0], a[1])),
            Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]),
            vk.alpha1, vk.beta2,
            vk_x, vk.gamma2,
            Pairing.G1Point(c[0], c[1]), vk.delta2
        );
    }

    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[5] memory input
    ) public view returns (bool r) {
        return verify(input, a, b, c);
    }
}
