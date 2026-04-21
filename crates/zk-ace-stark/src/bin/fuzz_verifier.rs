//! Generate an ABI-encoded STARK proof for the Solidity StarkVerifier.
//! Outputs mutated proofs for differential fuzzing.
//!
//! Proof layout (18-column AIR, all values ABI-encoded as uint256 = 32-byte BE):
//!
//! O_TRACE   =    0   traceRoot              (32 bytes)
//! O_CONSTR  =   32   constraintRoot         (32 bytes)
//! O_FRI     =   64   friRoot                (32 bytes)
//! O_OOD_DIG =   96   oodDigest              (32 bytes)
//! O_POW     =  128   powNonce (u64 as u256) (32 bytes)
//! O_OOD     =  160   OOD frame: 38 ext × 64 = 2432 bytes
//!              (18 trace_current + 18 trace_next + 1 constr_current + 1 constr_next)
//! O_Z       = 2592   z point: 1 ext × 64 = 64 bytes
//! O_CC      = 2656   constraint coeffs: 36 ext × 64 = 2304 bytes
//! O_DC      = 4960   DEEP coeffs: 19 ext × 64 = 1216 bytes
//! O_REM     = 6176   remainder: 8 ext × 64 = 512 bytes
//! O_FC      = 6688   field constants: 4 × 32 = 128 bytes
//! O_NQ      = 6816   numQueries: 1 × 32 bytes
//! O_QD      = 6848   per-query data starts
//! QSZ       = 1120   per query:
//!              pos(32) + traceLeaf(32) + constLeaf(32)
//!            + tracePath(6×32=192) + constPath(6×32=192)
//!            + traceEvals(18×32=576) + constEval(2×32=64)

use winterfell::crypto::{
    BatchMerkleProof, DefaultRandomCoin, Digest, ElementHasher, MerkleTree, RandomCoin,
};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, StarkField, ToElements};
use winterfell::Prover;

use zk_ace_stark::keccak_hasher::{KeccakDigest, KeccakHash};
use zk_ace_stark::prover::{
    compute_public_inputs, default_proof_options, ZkAceProver, ZkAceWitness,
};
use zk_ace_stark::verifier::verify_proof;

type B = BaseElement;
type E = winterfell::math::fields::QuadExtension<B>;

// ── Layout constants (must match StarkVerifier.sol) ──────────────────────

const TRACE_WIDTH: usize = 18;
const NUM_CONSTRAINT_COEFFS: usize = 36; // 18 transition + 18 boundary
const NUM_DEEP_COEFFS: usize = 19; // 18 trace + 1 constraint
const MERKLE_DEPTH: usize = 6;
const QSZ: usize = 1120;

// Expected byte offsets (for assertions)
const O_TRACE: usize = 0;
const O_CONSTR: usize = 32;
const O_FRI: usize = 64;
const O_OOD_DIGEST: usize = 96;
const O_POW: usize = 128;
const O_OOD: usize = 160;
const O_Z: usize = 2592;
const O_CC: usize = 2656;
const O_DC: usize = 4960;
const O_REM: usize = 6176;
const O_FC: usize = 6688;
const O_NQ: usize = 6816;
const O_QD: usize = 6848;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Decompose a QuadExtension<BaseElement> into its two base field components.
fn quad_ext_to_base_pair(e: E) -> (B, B) {
    let bases = e.to_base_elements();
    (bases[0], bases[1])
}

/// Encode an extension field element as two consecutive ABI uint256 words (64 bytes).
/// Each u64 component is zero-padded to 32 bytes, big-endian.
fn encode_ext_element(abi: &mut Vec<u8>, e: E) {
    let (b0, b1) = quad_ext_to_base_pair(e);
    abi.extend_from_slice(&[0u8; 24]);
    abi.extend_from_slice(&b0.as_int().to_be_bytes());
    abi.extend_from_slice(&[0u8; 24]);
    abi.extend_from_slice(&b1.as_int().to_be_bytes());
}

/// Encode a u64 as a 32-byte ABI uint256 word.
fn encode_u64(abi: &mut Vec<u8>, val: u64) {
    abi.extend_from_slice(&[0u8; 24]);
    abi.extend_from_slice(&val.to_be_bytes());
}

// ─────────────────────────────────────────────────────────────────────────

fn main() {
    // =====================================================================
    // 1. Generate proof with 4-element tx_hash
    // =====================================================================
    let (tx_hash, nonce_val) = ([B::new(0xAAAAu64), B::new(0xBBBBu64), B::new(0xCCCCu64), B::new(0xDDDDu64)], 0u64);

    let witness = ZkAceWitness {
        rev: B::new(0xDEAD_BEEF_CAFE_BABEu64),
        salt: B::new(0x1234_5678_9ABC_DEF0u64),
        alg_id: B::new(1),
        ctx_domain: B::new(42161),
        ctx_index: B::new(0),
        nonce: B::new(nonce_val),
    };
    let public_inputs = compute_public_inputs(&witness, tx_hash);
    let options = default_proof_options();
    let prover = ZkAceProver::new(options.clone());
    let trace = prover.build_trace(&witness, &public_inputs);
    let proof = prover.prove(trace).expect("proof generation failed");

    // =====================================================================
    // 2. Verify natively
    // =====================================================================
    assert!(verify_proof(&proof, &public_inputs), "native verify failed");
    eprintln!("Native verification: PASSED");

    // =====================================================================
    // 3. Extract proof components
    // =====================================================================
    let trace_info = proof.trace_info();
    let trace_width = trace_info.width();
    assert_eq!(trace_width, TRACE_WIDTH, "trace width mismatch");
    let trace_length = trace_info.length();
    let lde_domain_size = proof.lde_domain_size();
    let fri_options = options.to_fri_options();
    let num_fri_layers = fri_options.num_fri_layers(lde_domain_size);
    let num_trace_segments = trace_info.num_segments();

    // Commitments
    let (trace_coms, constraint_com, fri_coms) = proof
        .commitments
        .clone()
        .parse::<KeccakHash>(num_trace_segments, num_fri_layers)
        .expect("parse commitments");

    // OOD frame
    let (trace_ood, constraint_ood) = proof
        .ood_frame
        .clone()
        .parse::<E>(trace_width, 0, 1)
        .expect("parse OOD frame");

    let ood_trace_current: Vec<E> = trace_ood.current_row().to_vec();
    let ood_trace_next: Vec<E> = trace_ood.next_row().to_vec();
    let ood_constraint_current: Vec<E> = constraint_ood.current_row().to_vec();
    let ood_constraint_next: Vec<E> = constraint_ood.next_row().to_vec();

    assert_eq!(ood_trace_current.len(), TRACE_WIDTH);
    assert_eq!(ood_trace_next.len(), TRACE_WIDTH);
    assert_eq!(ood_constraint_current.len(), 1);
    assert_eq!(ood_constraint_next.len(), 1);

    // OOD digest (Winterfell order: trace_current, constraint_current, trace_next, constraint_next)
    let mut ood_elems: Vec<E> = Vec::new();
    ood_elems.extend_from_slice(&ood_trace_current);
    ood_elems.extend_from_slice(&ood_constraint_current);
    ood_elems.extend_from_slice(&ood_trace_next);
    ood_elems.extend_from_slice(&ood_constraint_next);
    let ood_digest = KeccakHash::hash_elements(&ood_elems);

    // PoW nonce + unique query count
    let pow_nonce = proof.pow_nonce;
    let num_queries = proof.num_unique_queries as usize;

    // =====================================================================
    // 4. Replay Fiat-Shamir transcript
    // =====================================================================
    let context_elems: Vec<B> = proof.context.to_elements();
    let mut coin_seed: Vec<B> = context_elems;
    coin_seed.append(&mut public_inputs.to_elements());
    let mut coin = DefaultRandomCoin::<KeccakHash>::new(&coin_seed);

    // Reseed with trace commitment → draw 36 constraint composition coefficients
    coin.reseed(trace_coms[0]);
    let mut constraint_coeffs: Vec<E> = Vec::new();
    for _ in 0..NUM_CONSTRAINT_COEFFS {
        constraint_coeffs.push(coin.draw::<E>().unwrap());
    }
    assert_eq!(constraint_coeffs.len(), NUM_CONSTRAINT_COEFFS);

    // Reseed with constraint commitment → draw OOD point z
    coin.reseed(constraint_com);
    let z: E = coin.draw().unwrap();

    // Reseed with OOD digest → draw 19 DEEP coefficients
    coin.reseed(ood_digest);
    let mut deep_coeffs: Vec<E> = Vec::new();
    for _ in 0..NUM_DEEP_COEFFS {
        deep_coeffs.push(coin.draw::<E>().unwrap());
    }
    assert_eq!(deep_coeffs.len(), NUM_DEEP_COEFFS);

    // FRI commit phase (reseed + draw alpha for each commitment)
    for fc in &fri_coms {
        coin.reseed(*fc);
        let _: E = coin.draw().unwrap();
    }

    // Query positions
    let positions =
        coin.draw_integers(options.num_queries(), lde_domain_size, pow_nonce)
            .unwrap();
    let mut unique_pos = positions.clone();
    unique_pos.sort_unstable();
    unique_pos.dedup();
    assert_eq!(unique_pos.len(), num_queries, "unique query count mismatch");

    // =====================================================================
    // 5. Parse query data (trace evals, constraint evals, Merkle paths)
    // =====================================================================
    let (trace_batch, trace_states): (BatchMerkleProof<KeccakHash>, _) = proof.trace_queries[0]
        .clone()
        .parse::<B, KeccakHash, MerkleTree<KeccakHash>>(lde_domain_size, num_queries, trace_width)
        .unwrap();

    let (constraint_batch, constraint_evals): (BatchMerkleProof<KeccakHash>, _) = proof
        .constraint_queries
        .clone()
        .parse::<E, KeccakHash, MerkleTree<KeccakHash>>(lde_domain_size, num_queries, 1)
        .unwrap();

    let trace_leaves: Vec<KeccakDigest> = trace_states
        .rows()
        .map(|r| KeccakHash::hash_elements(r))
        .collect();
    let constraint_leaves: Vec<KeccakDigest> = constraint_evals
        .rows()
        .map(|r| KeccakHash::hash_elements(r))
        .collect();

    let trace_openings = trace_batch
        .into_openings(&trace_leaves, &unique_pos)
        .unwrap();
    let constraint_openings = constraint_batch
        .into_openings(&constraint_leaves, &unique_pos)
        .unwrap();

    // FRI remainder polynomial
    let fri_remainder: Vec<E> = proof.fri_proof.clone().parse_remainder().unwrap();
    assert_eq!(fri_remainder.len(), 8, "expected 8 remainder coefficients");

    // Domain info
    let trace_domain_gen = B::get_root_of_unity(trace_length.ilog2());
    let lde_domain_gen = B::get_root_of_unity(lde_domain_size.ilog2());
    let domain_offset = B::GENERATOR;
    let g7 = trace_domain_gen.exp(7u64);

    // =====================================================================
    // 6. Build ABI-encoded proof bytes
    // =====================================================================
    let mut abi: Vec<u8> = Vec::with_capacity(O_QD + unique_pos.len() * QSZ);

    // ── Header commitments (4 × 32 = 128 bytes) ─────────────────────────
    abi.extend_from_slice(&trace_coms[0].as_bytes()); // O_TRACE   =   0
    abi.extend_from_slice(&constraint_com.as_bytes()); // O_CONSTR  =  32
    abi.extend_from_slice(&fri_coms[0].as_bytes());    // O_FRI     =  64
    abi.extend_from_slice(&ood_digest.as_bytes());     // O_OOD_DIG =  96
    assert_eq!(abi.len(), O_POW);

    // ── powNonce (32 bytes) ──────────────────────────────────────────────
    encode_u64(&mut abi, pow_nonce); // O_POW = 128
    assert_eq!(abi.len(), O_OOD);

    // ── OOD frame (38 ext × 64 = 2432 bytes) ────────────────────────────
    for e in &ood_trace_current { encode_ext_element(&mut abi, *e); }
    for e in &ood_trace_next { encode_ext_element(&mut abi, *e); }
    for e in &ood_constraint_current { encode_ext_element(&mut abi, *e); }
    for e in &ood_constraint_next { encode_ext_element(&mut abi, *e); }
    assert_eq!(abi.len(), O_Z, "OOD frame should end at O_Z={}", O_Z);

    // ── z point (1 ext × 64 = 64 bytes) ─────────────────────────────────
    encode_ext_element(&mut abi, z);
    assert_eq!(abi.len(), O_CC, "z should end at O_CC={}", O_CC);

    // ── Constraint composition coefficients (36 ext × 64 = 2304 bytes) ──
    for e in &constraint_coeffs { encode_ext_element(&mut abi, *e); }
    assert_eq!(abi.len(), O_DC, "CC should end at O_DC={}", O_DC);

    // ── DEEP coefficients (19 ext × 64 = 1216 bytes) ────────────────────
    for e in &deep_coeffs { encode_ext_element(&mut abi, *e); }
    assert_eq!(abi.len(), O_REM, "DC should end at O_REM={}", O_REM);

    // ── Remainder polynomial (8 ext × 64 = 512 bytes) ───────────────────
    for e in &fri_remainder { encode_ext_element(&mut abi, *e); }
    assert_eq!(abi.len(), O_FC, "REM should end at O_FC={}", O_FC);

    // ── Field constants (4 × 32 = 128 bytes) ────────────────────────────
    encode_u64(&mut abi, trace_domain_gen.as_int()); // g_trace
    encode_u64(&mut abi, lde_domain_gen.as_int());   // g_lde
    encode_u64(&mut abi, domain_offset.as_int());    // offset
    encode_u64(&mut abi, g7.as_int());               // g^7
    assert_eq!(abi.len(), O_NQ, "FC should end at O_NQ={}", O_NQ);

    // ── numQueries (32 bytes) ────────────────────────────────────────────
    encode_u64(&mut abi, unique_pos.len() as u64);
    assert_eq!(abi.len(), O_QD, "header should end at O_QD={}", O_QD);

    // ── Per-query data (QSZ = 1120 bytes each) ──────────────────────────
    for (qi, &pos) in unique_pos.iter().enumerate() {
        let q_start = abi.len();

        encode_u64(&mut abi, pos as u64);
        abi.extend_from_slice(&trace_leaves[qi].as_bytes());
        abi.extend_from_slice(&constraint_leaves[qi].as_bytes());

        let tp = &trace_openings[qi].1;
        for node in tp.iter() { abi.extend_from_slice(&node.as_bytes()); }
        for _ in tp.len()..MERKLE_DEPTH { abi.extend_from_slice(&[0u8; 32]); }

        let cp = &constraint_openings[qi].1;
        for node in cp.iter() { abi.extend_from_slice(&node.as_bytes()); }
        for _ in cp.len()..MERKLE_DEPTH { abi.extend_from_slice(&[0u8; 32]); }

        let trace_row = trace_states.get_row(qi);
        for &val in trace_row.iter() { encode_u64(&mut abi, val.as_int()); }

        let cval = constraint_evals.get_row(qi)[0];
        encode_ext_element(&mut abi, cval);

        assert_eq!(abi.len() - q_start, QSZ);
    }

    // =====================================================================
    // 7. Output Mutated Proofs
    // =====================================================================
    use std::fs;
    use std::path::PathBuf;

    let out_dir = PathBuf::from("contracts/test/fixtures/fuzz");
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).unwrap();
    }
    fs::create_dir_all(&out_dir).unwrap();

    let valid_path = out_dir.join("proof_valid.hex");
    fs::write(valid_path, hex::encode(&abi)).unwrap();

    let mut tampered_proofs = Vec::new();

    // Mutator 1: Tamper with trace commitment (offset 0..32)
    let mut p1 = abi.clone();
    p1[0] ^= 0xFF;
    tampered_proofs.push(("trace_comm", p1));

    // Mutator 2: Tamper with constraint commitment (offset 32..64)
    let mut p2 = abi.clone();
    p2[32] ^= 0xAA;
    tampered_proofs.push(("constr_comm", p2));

    // Mutator 3: Tamper with FRI commitment (offset 64..96)
    let mut p3 = abi.clone();
    p3[64] ^= 0x55;
    tampered_proofs.push(("fri_comm", p3));

    // Mutator 4: Tamper with OOD Digest (offset 96..128)
    let mut p4 = abi.clone();
    p4[96] ^= 0x01;
    tampered_proofs.push(("ood_digest", p4));

    // Mutator 5: Tamper with PoW nonce (offset 128..160)
    let mut p5 = abi.clone();
    p5[159] ^= 0x01;
    tampered_proofs.push(("pow_nonce", p5));

    for (name, bytes) in tampered_proofs {
        let path = out_dir.join(format!("proof_{}.hex", name));
        fs::write(path, hex::encode(&bytes)).unwrap();
    }

    let pi_vec: Vec<u64> = {
        let mut v = Vec::with_capacity(17);
        for e in &public_inputs.id_com { v.push(e.as_int()); }
        for e in &public_inputs.target { v.push(e.as_int()); }
        for e in &public_inputs.rp_com { v.push(e.as_int()); }
        v.push(public_inputs.domain.as_int());
        for e in &public_inputs.tx_hash { v.push(e.as_int()); }
        v
    };

    let inputs_path = out_dir.join("pub_inputs.hex");
    let mut inputs_bytes = Vec::new();
    for val in pi_vec {
        inputs_bytes.extend_from_slice(&val.to_be_bytes());
    }
    fs::write(inputs_path, hex::encode(&inputs_bytes)).unwrap();

    println!("Saved valid proof and tampered proofs to contracts/test/fixtures/fuzz");
}
