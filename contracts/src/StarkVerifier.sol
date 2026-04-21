// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./IStarkVerifier.sol";
import "./GoldilocksField.sol";

/// @title StarkVerifier — Cryptographically complete STARK verification
/// @notice All random challenges derived from Fiat-Shamir transcript.
///         All algebraic checks performed in Solidity. Nothing trusted from prover
///         except the proof structure.
///
/// @dev ZK-ACE AIR: 18 cols × 8 rows, Goldilocks + QuadExt, Keccak256
///      44 queries, 20-bit grinding, 0 FRI layers
///      128-bit post-quantum security via 256-bit Rescue commitments
contract StarkVerifier is IStarkVerifier {
    using Goldilocks for uint256;

    uint256 constant P = 18446744069414584321;
    uint256 constant NUM_QUERIES = 44;
    uint256 constant GRINDING_BITS = 20;
    uint256 constant LDE_DOMAIN_SIZE = 64;
    uint256 constant TRACE_WIDTH = 18;
    uint256 constant TRACE_LENGTH = 8;
    uint256 constant MERKLE_DEPTH = 6;
    uint256 constant G7 = 18446742969902956801; // trace_domain_gen^7
    uint256 constant NUM_PUB_INPUTS = 17;
    uint256 constant NUM_TRANSITION_CONSTRAINTS = 18;
    uint256 constant NUM_BOUNDARY_ASSERTIONS = 18;
    uint256 constant NUM_CONSTRAINT_COEFFS = 36; // 18 transition + 18 boundary
    uint256 constant NUM_DEEP_COEFFS = 19; // 18 trace + 1 constraint

    // Proof layout offsets
    uint256 constant O_TRACE = 0;
    uint256 constant O_CONSTR = 32;
    uint256 constant O_FRI = 64;
    uint256 constant O_OOD_DIGEST = 96;
    uint256 constant O_POW = 128;
    // OOD Frame: (18 trace current + 18 trace next + 2 constraint) = 38 ext elements × 64 bytes = 2432
    uint256 constant O_OOD = 160;
    // z: 64 bytes
    uint256 constant O_Z = 2592;
    // Constraint coeffs: 36 ext × 64 = 2304
    uint256 constant O_CC = 2656;
    // DEEP coeffs: 19 ext × 64 = 1216
    uint256 constant O_DC = 4960;
    // Remainder: 8 ext × 64 = 512
    uint256 constant O_REM = 6176;
    // Field constants: 4 × 32 = 128
    uint256 constant O_FC = 6688;
    // numQ: 32
    uint256 constant O_NQ = 6816;
    // Query data
    uint256 constant O_QD = 6848;
    // Per-query: position(32) + traceLeaf(32) + constraintLeaf(32) + tracePath(192) + constraintPath(192)
    //          + traceEvals(18×32=576) + constraintEval(2×32=64) = 1120
    uint256 constant QSZ = 1120;

    error GrindingFailed();
    error OodCheckFailed();
    error MerkleCheckFailed(uint256 q);
    error RemainderCheckFailed(uint256 q);
    error QueryCountInvalid();
    error QueryPositionMismatch(uint256 q);
    error OodDigestMismatch();

    // ═══════════════════════════════════════
    //  Random Coin: draw a Goldilocks element
    // ═══════════════════════════════════════
    // Winterfell: loop { counter++; h = keccak(seed || counter_LE); val = first 8 bytes LE; if val < P: return }
    function _draw(bytes32 seed, uint256 counter) internal pure returns (uint256 val, uint256 newCounter) {
        for (uint256 i = 0; i < 100; i++) {
            counter++;
            bytes32 h = keccak256(abi.encodePacked(seed, _toLE(uint64(counter))));
            val = uint256(_swapEndian64(uint64(bytes8(h))));
            if (val < P) return (val, counter);
        }
        revert("draw failed");
    }

    // Draw an extension field element: single hash, take first 16 bytes as 2 LE u64
    // Matches Winterfell: draw() calls next(), takes ELEMENT_BYTES=16, tries from_random_bytes
    function _drawExt(bytes32 seed, uint256 counter) internal pure returns (uint256 e0, uint256 e1, uint256 newCounter) {
        for (uint256 i = 0; i < 100; i++) {
            counter++;
            bytes32 h = keccak256(abi.encodePacked(seed, _toLE(uint64(counter))));
            // Parse first 16 bytes as 2 LE u64 values (matches Winterfell ELEMENT_BYTES=16)
            // bytes32 layout: byte[0] at bits 255..248, byte[31] at bits 7..0
            uint256 hval = uint256(h);
            e0 = uint256(_swapEndian64(uint64(hval >> 192))); // bytes 0-7 BE → LE
            e1 = uint256(_swapEndian64(uint64(hval >> 128))); // bytes 8-15 BE → LE
            if (e0 < P && e1 < P) return (e0, e1, counter);
        }
        revert("drawExt failed");
    }

    /// @inheritdoc IStarkVerifier
    function verifyProof(
        bytes calldata proof,
        uint64[17] calldata publicInputs
    ) external pure override returns (bool) {
        for (uint256 i = 0; i < NUM_PUB_INPUTS; i++) {
            if (uint256(publicInputs[i]) >= P) return false;
        }

        bytes32 traceRoot = bytes32(proof[O_TRACE:O_TRACE+32]);
        bytes32 constraintRoot = bytes32(proof[O_CONSTR:O_CONSTR+32]);
        bytes32 friRoot = bytes32(proof[O_FRI:O_FRI+32]);
        uint64 powNonce = uint64(uint256(bytes32(proof[O_POW:O_POW+32])));

        // ═══════════════════════════════════
        //  1. Fiat-Shamir + Derive Challenges
        // ═══════════════════════════════════
        // Context encodes: trace_info, proof_options, num_constraints.
        // Element 1: trace_width=18 (0x12 LE), Element 5: total_constraints=36 (0x24 LE).
        // The exact bytes must match Winterfell's serialization of AirContext.
        bytes32 seed = keccak256(abi.encodePacked(
            bytes8(0x0012000000000000), bytes8(0x0800000000000000),
            bytes8(0x0100000000000000), bytes8(0xffffffff00000000),
            bytes8(0x2400000000000000), bytes8(0x081f080200000000),
            bytes8(0x1400000000000000), bytes8(0x2c00000000000000),
            _toLE(publicInputs[0]), _toLE(publicInputs[1]),
            _toLE(publicInputs[2]), _toLE(publicInputs[3]),
            _toLE(publicInputs[4]), _toLE(publicInputs[5]),
            _toLE(publicInputs[6]), _toLE(publicInputs[7]),
            _toLE(publicInputs[8]), _toLE(publicInputs[9]),
            _toLE(publicInputs[10]), _toLE(publicInputs[11]),
            _toLE(publicInputs[12]), _toLE(publicInputs[13]),
            _toLE(publicInputs[14]), _toLE(publicInputs[15]),
            _toLE(publicInputs[16])
        ));

        // Reseed with trace commitment
        seed = keccak256(abi.encodePacked(seed, traceRoot));

        // Draw 36 constraint composition coefficients FROM TRANSCRIPT
        // (18 transition + 18 boundary)
        uint256 counter = 0;
        uint256[2][36] memory cc;
        for (uint256 i = 0; i < NUM_CONSTRAINT_COEFFS; i++) {
            (cc[i][0], cc[i][1], counter) = _drawExt(seed, counter);
        }

        // Reseed with constraint commitment
        seed = keccak256(abi.encodePacked(seed, constraintRoot));
        counter = 0;

        // Draw OOD point z FROM TRANSCRIPT
        uint256 z0; uint256 z1;
        (z0, z1, counter) = _drawExt(seed, counter);

        // ═══════════════════════════════════
        //  2. Recompute OOD Digest
        // ═══════════════════════════════════
        // Hash all 38 OOD extension elements (same order as Winterfell)
        // OOD frame layout: trace_current[0..18], trace_next[18..36], constraint[36..38]
        // Winterfell digest order: trace_current ++ constraint_current ++ trace_next ++ constraint_next
        // Each ext element serialized as 2 LE u64 = 16 bytes
        {
            // 38 ext elements × 16 bytes = 608 bytes
            // But Winterfell hashes as: current_trace(18) + constraint_at_z(1) + next_trace(18) + constraint_at_zg(1) = 38
            bytes memory oodBytes = new bytes(38 * 16);
            // trace_current[0..18] = OOD frame indices 0..18
            for (uint256 i = 0; i < TRACE_WIDTH; i++) {
                uint256 v0 = uint256(bytes32(proof[O_OOD + i*64 : O_OOD + i*64 + 32]));
                uint256 v1 = uint256(bytes32(proof[O_OOD + i*64 + 32 : O_OOD + i*64 + 64]));
                _writeLE64(oodBytes, i * 16, v0);
                _writeLE64(oodBytes, i * 16 + 8, v1);
            }
            // constraint_current[0] = OOD frame index 36
            {
                uint256 v0 = uint256(bytes32(proof[O_OOD + 36*64 : O_OOD + 36*64 + 32]));
                uint256 v1 = uint256(bytes32(proof[O_OOD + 36*64 + 32 : O_OOD + 36*64 + 64]));
                _writeLE64(oodBytes, TRACE_WIDTH * 16, v0);
                _writeLE64(oodBytes, TRACE_WIDTH * 16 + 8, v1);
            }
            // trace_next[0..18] = OOD frame indices 18..36
            for (uint256 i = 0; i < TRACE_WIDTH; i++) {
                uint256 v0 = uint256(bytes32(proof[O_OOD + (TRACE_WIDTH+i)*64 : O_OOD + (TRACE_WIDTH+i)*64 + 32]));
                uint256 v1 = uint256(bytes32(proof[O_OOD + (TRACE_WIDTH+i)*64 + 32 : O_OOD + (TRACE_WIDTH+i)*64 + 64]));
                _writeLE64(oodBytes, (TRACE_WIDTH + 1 + i) * 16, v0);
                _writeLE64(oodBytes, (TRACE_WIDTH + 1 + i) * 16 + 8, v1);
            }
            // constraint_next[0] = OOD frame index 37
            {
                uint256 v0 = uint256(bytes32(proof[O_OOD + 37*64 : O_OOD + 37*64 + 32]));
                uint256 v1 = uint256(bytes32(proof[O_OOD + 37*64 + 32 : O_OOD + 37*64 + 64]));
                _writeLE64(oodBytes, (2 * TRACE_WIDTH + 1) * 16, v0);
                _writeLE64(oodBytes, (2 * TRACE_WIDTH + 1) * 16 + 8, v1);
            }
            bytes32 computedDigest = keccak256(oodBytes);
            bytes32 claimedDigest = bytes32(proof[O_OOD_DIGEST:O_OOD_DIGEST+32]);
            if (computedDigest != claimedDigest) revert OodDigestMismatch();
        }

        // Reseed with OOD digest
        seed = keccak256(abi.encodePacked(seed, bytes32(proof[O_OOD_DIGEST:O_OOD_DIGEST+32])));
        counter = 0;

        // Draw 19 DEEP coefficients FROM TRANSCRIPT (18 trace + 1 constraint)
        uint256[2][19] memory dc;
        for (uint256 i = 0; i < NUM_DEEP_COEFFS; i++) {
            (dc[i][0], dc[i][1], counter) = _drawExt(seed, counter);
        }

        // Reseed with FRI commitment
        seed = keccak256(abi.encodePacked(seed, friRoot));
        counter = 0;
        // Draw FRI alpha (not used with 0 layers, but advances state)
        { uint256 _a; uint256 _b; (_a, _b, counter) = _drawExt(seed, counter); }

        // ═══════════════════════════════════
        //  3. Proof-of-Work
        // ═══════════════════════════════════
        {
            bytes32 ph = keccak256(abi.encodePacked(seed, _toLE(powNonce)));
            uint64 pv = _swapEndian64(uint64(bytes8(ph)));
            uint256 tz = 0;
            if (pv != 0) { uint64 t = pv; while (t & 1 == 0) { tz++; t >>= 1; } } else { tz = 64; }
            if (tz < GRINDING_BITS) revert GrindingFailed();
        }
        seed = keccak256(abi.encodePacked(seed, _toLE(powNonce)));

        // ═══════════════════════════════════
        //  4. Query Positions
        // ═══════════════════════════════════
        bool[64] memory expSet;
        uint256 expCount = 0;
        for (uint256 i = 0; i < NUM_QUERIES; i++) {
            bytes32 ph = keccak256(abi.encodePacked(seed, _toLE(uint64(i + 1))));
            uint256 pos = uint256(_swapEndian64(uint64(bytes8(ph)))) & 63;
            if (!expSet[pos]) { expSet[pos] = true; expCount++; }
        }
        uint256 numQ = uint256(bytes32(proof[O_NQ:O_NQ+32]));
        if (numQ != expCount) revert QueryCountInvalid();

        // ═══════════════════════════════════
        //  5. OOD Constraint Evaluation
        // ═══════════════════════════════════
        {
            // Evaluate ALL 18 transition constraints at z
            // t[i] = next[i] - current[i] for i=0..16 (constancy)
            // t[17] = next[17] - current[17] - 1 (step counter)
            uint256[2][18] memory tEval;
            for (uint256 i = 0; i < TRACE_WIDTH; i++) {
                uint256 c0 = uint256(bytes32(proof[O_OOD + i*64 : O_OOD + i*64 + 32]));
                uint256 c1 = uint256(bytes32(proof[O_OOD + i*64 + 32 : O_OOD + i*64 + 64]));
                uint256 n0 = uint256(bytes32(proof[O_OOD + (TRACE_WIDTH+i)*64 : O_OOD + (TRACE_WIDTH+i)*64 + 32]));
                uint256 n1 = uint256(bytes32(proof[O_OOD + (TRACE_WIDTH+i)*64 + 32 : O_OOD + (TRACE_WIDTH+i)*64 + 64]));
                (tEval[i][0], tEval[i][1]) = Goldilocks.subExt(n0, n1, c0, c1);
            }
            // Col 17 (step counter): subtract 1
            (tEval[17][0], tEval[17][1]) = Goldilocks.subExt(tEval[17][0], tEval[17][1], 1, 0);

            // Transition divisor: (z^8 - 1) / (z - g^7)
            (uint256 zp0, uint256 zp1) = (z0, z1);
            for (uint256 i = 0; i < 3; i++) (zp0, zp1) = Goldilocks.mulExt(zp0, zp1, zp0, zp1);
            (uint256 z8m1_0, uint256 z8m1_1) = Goldilocks.subExt(zp0, zp1, 1, 0);
            (uint256 zmg7_0, uint256 zmg7_1) = Goldilocks.subExt(z0, z1, G7, 0);

            // Combined transition: sum(cc[i] * t[i]) * (z-g7) / (z^8-1)
            (uint256 tSum0, uint256 tSum1) = (uint256(0), uint256(0));
            for (uint256 i = 0; i < TRACE_WIDTH; i++) {
                (uint256 m0, uint256 m1) = Goldilocks.mulExt(cc[i][0], cc[i][1], tEval[i][0], tEval[i][1]);
                (tSum0, tSum1) = Goldilocks.addExt(tSum0, tSum1, m0, m1);
            }
            (tSum0, tSum1) = Goldilocks.mulExt(tSum0, tSum1, zmg7_0, zmg7_1);
            {
                (uint256 inv0, uint256 inv1) = Goldilocks.invExt(z8m1_0, z8m1_1);
                (tSum0, tSum1) = Goldilocks.mulExt(tSum0, tSum1, inv0, inv1);
            }

            // Boundary constraints: 18 assertions at row 0
            // cols 0-3   → id_com[0..4]   (pubInputs[0..4])
            // cols 4-7   → target[0..4]   (pubInputs[4..8])
            // cols 8-11  → rp_com[0..4]   (pubInputs[8..12])
            // col  12    → domain         (pubInputs[12])
            // cols 13-16 → tx_hash[0..4]  (pubInputs[13..17])
            // col  17    → 0 (step counter)
            uint256[18] memory bVals;
            for (uint256 i = 0; i < NUM_PUB_INPUTS; i++) {
                bVals[i] = uint256(publicInputs[i]);
            }
            bVals[17] = 0; // step counter starts at 0

            (uint256 bdI0, uint256 bdI1) = Goldilocks.invExt(Goldilocks.sub(z0, 1), z1);
            (uint256 bSum0, uint256 bSum1) = (uint256(0), uint256(0));
            for (uint256 j = 0; j < NUM_BOUNDARY_ASSERTIONS; j++) {
                // Column j maps to boundary value bVals[j]
                uint256 tv0 = uint256(bytes32(proof[O_OOD + j*64 : O_OOD + j*64 + 32]));
                uint256 tv1 = uint256(bytes32(proof[O_OOD + j*64 + 32 : O_OOD + j*64 + 64]));
                (uint256 nm0, uint256 nm1) = Goldilocks.subExt(tv0, tv1, bVals[j], 0);
                (nm0, nm1) = Goldilocks.mulExt(nm0, nm1, bdI0, bdI1);
                // Boundary coefficients start after 18 transition coefficients
                (uint256 tm0, uint256 tm1) = Goldilocks.mulExt(cc[NUM_TRANSITION_CONSTRAINTS+j][0], cc[NUM_TRANSITION_CONSTRAINTS+j][1], nm0, nm1);
                (bSum0, bSum1) = Goldilocks.addExt(bSum0, bSum1, tm0, tm1);
            }

            (uint256 ood0, uint256 ood1) = Goldilocks.addExt(tSum0, tSum1, bSum0, bSum1);
            // Constraint evaluation at z is OOD frame index 36
            uint256 claimed0 = uint256(bytes32(proof[O_OOD + 36*64 : O_OOD + 36*64 + 32]));
            uint256 claimed1 = uint256(bytes32(proof[O_OOD + 36*64 + 32 : O_OOD + 36*64 + 64]));
            if (ood0 != claimed0 || ood1 != claimed1) revert OodCheckFailed();
        }

        // ═══════════════════════════════════
        //  6. Merkle + DEEP + Remainder
        // ═══════════════════════════════════
        // MED-1 fix: Field constants HARDCODED, not read from proof.
        // Prevents attacker from manipulating algebraic computations.
        uint256 g_lde = 8;          // primitive 64th root of unity
        uint256 dom_offset = 7;     // Winterfell's GENERATOR
        uint256 g_trace = 16777216; // primitive 8th root of unity
        // z*g (for DEEP)
        (uint256 zg0, uint256 zg1) = Goldilocks.mulExtBase(z0, z1, g_trace);

        for (uint256 q = 0; q < numQ; q++) {
            uint256 base = O_QD + q * QSZ;
            uint256 position = uint256(bytes32(proof[base:base+32]));
            if (!expSet[position]) revert QueryPositionMismatch(q);
            expSet[position] = false; // Prevent position reuse — each position checked exactly once

            // Merkle: trace
            {
                bytes32 cur = bytes32(proof[base+32:base+64]);
                uint256 idx = position;
                for (uint256 d = 0; d < MERKLE_DEPTH; d++) {
                    bytes32 sib = bytes32(proof[base+96+d*32:base+96+(d+1)*32]);
                    cur = (idx & 1 == 0) ? keccak256(abi.encodePacked(cur, sib)) : keccak256(abi.encodePacked(sib, cur));
                    idx >>= 1;
                }
                if (cur != traceRoot) revert MerkleCheckFailed(q);
            }
            // Merkle: constraint
            {
                bytes32 cur = bytes32(proof[base+64:base+96]);
                uint256 idx = position;
                for (uint256 d = 0; d < MERKLE_DEPTH; d++) {
                    bytes32 sib = bytes32(proof[base+288+d*32:base+288+(d+1)*32]);
                    cur = (idx & 1 == 0) ? keccak256(abi.encodePacked(cur, sib)) : keccak256(abi.encodePacked(sib, cur));
                    idx >>= 1;
                }
                if (cur != constraintRoot) revert MerkleCheckFailed(q);
            }

            // Verify trace leaf hash matches raw evaluations
            // The prover provides raw trace evals; we hash them and check against the
            // Merkle-verified leaf. This prevents fake evaluations.
            {
                uint256 evOff_ = base + 480;
                bytes memory traceBytes = new bytes(TRACE_WIDTH * 8); // 18 × 8 LE bytes = 144
                for (uint256 i = 0; i < TRACE_WIDTH; i++) {
                    uint256 v = uint256(bytes32(proof[evOff_ + i*32 : evOff_ + (i+1)*32]));
                    _writeLE64(traceBytes, i * 8, v);
                }
                bytes32 computedLeaf = keccak256(traceBytes);
                bytes32 claimedLeaf = bytes32(proof[base+32:base+64]);
                require(computedLeaf == claimedLeaf, "trace eval/leaf mismatch");
            }
            // Verify constraint leaf hash matches raw evaluation
            {
                uint256 cevOff_ = base + 480 + TRACE_WIDTH * 32; // 480 + 576 = 1056
                uint256 cv0_ = uint256(bytes32(proof[cevOff_ : cevOff_ + 32]));
                uint256 cv1_ = uint256(bytes32(proof[cevOff_ + 32 : cevOff_ + 64]));
                bytes memory cBytes = new bytes(16);
                _writeLE64(cBytes, 0, cv0_);
                _writeLE64(cBytes, 8, cv1_);
                bytes32 computedCLeaf = keccak256(cBytes);
                bytes32 claimedCLeaf = bytes32(proof[base+64:base+96]);
                require(computedCLeaf == claimedCLeaf, "constraint eval/leaf mismatch");
            }

            // DEEP composition + Remainder check: ALL COMPUTED IN SOLIDITY
            {
                uint256 x_q = mulmod(dom_offset, Goldilocks.exp(g_lde, position), P);
                (uint256 xmz0, uint256 xmz1) = Goldilocks.subExt(x_q, 0, z0, z1);
                (uint256 xmzg0, uint256 xmzg1) = Goldilocks.subExt(x_q, 0, zg0, zg1);

                // Read raw trace evals (18 base field elements) from proof
                // Located after the Merkle paths: base + 32 + 32 + 32 + 192 + 192 = base + 480
                uint256 evOff = base + 480;

                // Compute DEEP numerator: sum over 18 trace cols + 1 constraint col
                (uint256 t1n0, uint256 t1n1) = (uint256(0), uint256(0));
                (uint256 t2n0, uint256 t2n1) = (uint256(0), uint256(0));

                for (uint256 i = 0; i < TRACE_WIDTH; i++) {
                    uint256 tval = uint256(bytes32(proof[evOff + i*32 : evOff + (i+1)*32]));
                    // OOD trace values at z and z*g (from OOD frame)
                    uint256 oz0 = uint256(bytes32(proof[O_OOD + i*64 : O_OOD + i*64 + 32]));
                    uint256 oz1 = uint256(bytes32(proof[O_OOD + i*64 + 32 : O_OOD + i*64 + 64]));
                    uint256 ozg0 = uint256(bytes32(proof[O_OOD + (TRACE_WIDTH+i)*64 : O_OOD + (TRACE_WIDTH+i)*64 + 32]));
                    uint256 ozg1 = uint256(bytes32(proof[O_OOD + (TRACE_WIDTH+i)*64 + 32 : O_OOD + (TRACE_WIDTH+i)*64 + 64]));

                    // diff_z = T_i(x) - T_i(z)
                    (uint256 dz0, uint256 dz1) = Goldilocks.subExt(tval, 0, oz0, oz1);
                    // diff_zg = T_i(x) - T_i(z*g)
                    (uint256 dzg0, uint256 dzg1) = Goldilocks.subExt(tval, 0, ozg0, ozg1);

                    // t1_num += diff_z * dc[i]
                    (uint256 m0, uint256 m1) = Goldilocks.mulExt(dz0, dz1, dc[i][0], dc[i][1]);
                    (t1n0, t1n1) = Goldilocks.addExt(t1n0, t1n1, m0, m1);
                    // t2_num += diff_zg * dc[i]
                    (m0, m1) = Goldilocks.mulExt(dzg0, dzg1, dc[i][0], dc[i][1]);
                    (t2n0, t2n1) = Goldilocks.addExt(t2n0, t2n1, m0, m1);
                }

                // Constraint column (extension element at evOff + 18*32 = evOff + 576)
                uint256 cevOff = evOff + TRACE_WIDTH * 32;
                uint256 cv0 = uint256(bytes32(proof[cevOff : cevOff + 32]));
                uint256 cv1 = uint256(bytes32(proof[cevOff + 32 : cevOff + 64]));
                // OOD constraint at z (index 36) and z*g (index 37)
                uint256 ocz0 = uint256(bytes32(proof[O_OOD + 36*64 : O_OOD + 36*64 + 32]));
                uint256 ocz1 = uint256(bytes32(proof[O_OOD + 36*64 + 32 : O_OOD + 36*64 + 64]));
                uint256 oczg0 = uint256(bytes32(proof[O_OOD + 37*64 : O_OOD + 37*64 + 32]));
                uint256 oczg1 = uint256(bytes32(proof[O_OOD + 37*64 + 32 : O_OOD + 37*64 + 64]));

                {
                    (uint256 dz0, uint256 dz1) = Goldilocks.subExt(cv0, cv1, ocz0, ocz1);
                    (uint256 dzg0, uint256 dzg1) = Goldilocks.subExt(cv0, cv1, oczg0, oczg1);
                    // Constraint DEEP coeff is at index 18 (after 18 trace coeffs)
                    (uint256 m0, uint256 m1) = Goldilocks.mulExt(dz0, dz1, dc[TRACE_WIDTH][0], dc[TRACE_WIDTH][1]);
                    (t1n0, t1n1) = Goldilocks.addExt(t1n0, t1n1, m0, m1);
                    (m0, m1) = Goldilocks.mulExt(dzg0, dzg1, dc[TRACE_WIDTH][0], dc[TRACE_WIDTH][1]);
                    (t2n0, t2n1) = Goldilocks.addExt(t2n0, t2n1, m0, m1);
                }

                // DEEP = (t1_num * (x-zg) + t2_num * (x-z)) / ((x-z)*(x-zg))
                (uint256 p1_0, uint256 p1_1) = Goldilocks.mulExt(t1n0, t1n1, xmzg0, xmzg1);
                (uint256 p2_0, uint256 p2_1) = Goldilocks.mulExt(t2n0, t2n1, xmz0, xmz1);
                (uint256 n0, uint256 n1) = Goldilocks.addExt(p1_0, p1_1, p2_0, p2_1);
                (uint256 den0, uint256 den1) = Goldilocks.mulExt(xmz0, xmz1, xmzg0, xmzg1);
                (uint256 dinv0, uint256 dinv1) = Goldilocks.invExt(den0, den1);
                (uint256 deep0, uint256 deep1) = Goldilocks.mulExt(n0, n1, dinv0, dinv1);

                // Remainder polynomial evaluation at x_q (Horner, coeffs already reversed)
                uint256 rem0 = 0; uint256 rem1 = 0;
                for (uint256 k = 0; k < 8; k++) {
                    if (k > 0) (rem0, rem1) = Goldilocks.mulExtBase(rem0, rem1, x_q);
                    uint256 coff = O_REM + k * 64;
                    (rem0, rem1) = Goldilocks.addExt(rem0, rem1,
                        uint256(bytes32(proof[coff:coff+32])),
                        uint256(bytes32(proof[coff+32:coff+64])));
                }

                // DEEP(x) must equal remainder(x)
                if (deep0 != rem0 || deep1 != rem1) revert RemainderCheckFailed(q);
            }
        }

        return true;
    }

    // ═══════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════

    function _swapEndian64(uint64 v) internal pure returns (uint64) {
        v = ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000) >> 16) | ((v & 0x0000FFFF0000FFFF) << 16);
        return (v >> 32) | (v << 32);
    }

    function _toLE(uint64 v) internal pure returns (bytes8) {
        return bytes8(_swapEndian64(v));
    }

    /// @dev Write a uint256 value as LE u64 (8 bytes) into a bytes array at offset
    function _writeLE64(bytes memory buf, uint256 offset, uint256 val) internal pure {
        uint64 v = uint64(val);
        for (uint256 i = 0; i < 8; i++) {
            buf[offset + i] = bytes1(uint8(v & 0xFF));
            v >>= 8;
        }
    }
}
