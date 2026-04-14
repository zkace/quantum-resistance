# STARK path cryptographic review (ZK-ACE / Stark vault)

**Date:** 2026-04-02  
**Scope:** verifier-centered review of the Winterfell-based STARK (Rust), WASM prover surface, Solidity `StarkVerifier`, and the proof-consumption boundary in `StarkZkAceAccount`. Excludes Groth16 / BN254 path and does **not** attempt a fresh numerical derivation of the STARK soundness bound.

---

## Executive summary

- **The AIR is cryptographically minimal:** transition constraints only enforce column constancy (cols 0–16) and a row counter (col 17); boundary assertions pin the 17 public inputs at row 0. The STARK does **not** re-express Rescue-Prime inside constraints. Identity / derivation / replay digests are **computed off-chain** and treated as public inputs; soundness of “knows a preimage for `id_com`” is **Rescue hardness + on-chain `idCom` equality**, not the STARK statement itself.
- **On-chain verifier alignment is intentionally brittle:** `StarkVerifier` hard-codes Winterfell `AirContext` / proof-option bytes in the Fiat-Shamir seed. Any Winterfell version or `ProofOptions` change without updating those constants will yield **verification failure or unintended transcript drift**. This is a **maintenance and deployment risk**, not a per-proof attack under a fixed deployment.
- **Interface assumption at the account/verifier boundary:** the witness `nonce` is **not** a STARK public input. Solidity cannot recompute Rescue; `StarkZkAceAccount` increments `zkNonce` after success but does **not** require `rp_com == f(id_com, zkNonce)` for the current nonce. Replay semantics therefore lean on **ERC-4337 account nonce**, calldata/`tx_hash` binding, and correct prover/SDK behavior—worth treating as an explicit **assumption** in threat models rather than a pure verifier property.
- **Encoding parity (tx hash, field elements):** `StarkZkAceAccount` and `gen_sol_proof` reduce each 64-bit keccak limb with `% P`; WASM uses `BaseElement::new(u64::from_be_bytes(...))`, which **silently reduces mod P** (winter-math 0.13.1). For canonical limb values this matches. **Mismatches would appear** if any component ever passed **non-canonical** `uint64` values `≥ P` into Solidity without reduction while Rust used canonical form—current verifier rejects `publicInputs[i] >= P`.

**Assumption box:** This review assumes Winterfell soundness in the chosen parameter regime (44 queries, blowup 8, 20-bit grinding), Keccak as the Fiat-Shamir random oracle / Merkle hash, Rescue as the intended off-chain commitment function, honest prover/wallet use of the current account `zkNonce`, and ERC-4337 nonce enforcement plus calldata binding at the account interface.

---

## AIR / statement adequacy

**Layout and constraints** (from `crates/zk-ace-stark/src/air.rs`):

- Trace: 18 columns × 8 rows. Cols 0–11 hold 4-word Rescue digests (`id_com`, `target`, `rp_com`); col 12 `domain`; cols 13–16 `tx_hash`; col 17 step counter 0…7.
- Transitions: for `i ∈ [0,16]`, `next[i] = current[i]`; `next[17] = current[17] + 1`.
- Boundaries: at row 0, columns 0–16 match the **17 public-input field elements** (`id_com`, `target`, `rp_com`, `domain`, `tx_hash`), and column 17 has a **separate** boundary assertion `step_counter = 0`.

**What this proves:** existence of a trace whose low-degree extension is consistent with Merkle/FRI checks and the above linear constraints. Because all non-counter columns are **constant over time**, the trace row is **fully determined** by the public inputs (plus the counter column). The proof is therefore chiefly a **proof of correct Winterfell execution** for those public inputs, not a circuit tying private `rev`, `salt`, `alg_id`, or `ctx_index` into the statement.

**Off-chain binding** (from `crates/zk-ace-stark/src/prover.rs`): `id_com`, `target`, and `rp_com` are derived with `rescue_hash_full` over witness field elements. Any party verifying only the STARK + public inputs learns that those digests are **mutually consistent with a trivial trace**, not that they equal Rescue of specific secrets—**unless** `id_com` is checked against a prior commitment (`StarkZkAceAccount.idCom`).

**Documentation nit:** `prover.rs` comments around `rp_com` mention “first element” binding; implementation hashes **four** `id_com` limbs plus `nonce` (`rescue_hash_full(&[id_com[0], …, id_com[3], witness.nonce])`), which matches the security intent better than a 64-bit truncation.

---

## Transcript and Fiat-Shamir review

**Hash function:** Rust prover/verifier use `KeccakHash` (`crates/zk-ace-stark/src/keccak_hasher.rs`): Keccak-256 (not SHA-3), `merge` over two 32-byte digests, `merge_with_int` with **little-endian** `u64`, and `hash_elements` via Winterfell `Serializable::write_into` per element (canonical **LE** 8-byte limbs). This matches the stated goal of EVM opcode alignment.

**Solidity transcript** (`contracts/src/StarkVerifier.sol`):

- Initial `seed = keccak256(abi.encodePacked(...))` concatenates **eight fixed `bytes8` chunks** (interpreted as little-endian `u64` in the Rust/Winterfell sense via `_toLE`) plus `_toLE(publicInputs[0..16])`. This must byte-match Winterfell’s `AirContext` + public-input serialization for the deployed options—**there is no runtime self-check**; mismatch breaks soundness of the intended relation.
- Subsequent reseeds: trace root → draw 36 extension coefficients → constraint root → draw `z` → OOD digest check → draw 19 DEEP coeffs → FRI root → draw FRI α (unused when there are zero FRI layers but still advances RNG) → PoW → query positions.
- **OOD digest:** Solidity rebuilds 38×16 bytes with an order consistent with the comment (trace current, constraint at `z`, trace next, constraint at `z·g`) and compares to `proof[O_OOD_DIGEST]`. Failure reverts with `OodDigestMismatch`.
- **PoW:** 20 trailing zero bits on a word derived from `keccak256(seed || powNonce_LE)`; aligns with `default_proof_options()` grinding factor 20.
- **Queries:** positions derived from `keccak256(seed || (i+1)_LE)`, masked to LDE size 64; `numQ` must equal count of **distinct** positions—covers the “numQ = 0” bypass class when implemented as tested.

**Risks / ambiguities:**

- **Version fragility:** hard-coded context words (e.g. `0x0012000000000000` for width 18, `0x2400000000000000` for 36 constraints, `0x2c00000000000000` for 44 queries) are correct only for the pinned Winterfell + `ProofOptions` pairing. Treat as **release-critical** when bumping `winterfell` or changing blowup, extension degree, batching, FRI params, or trace shape.
- **`_draw` / `_drawExt` rejection sampling:** loops cap at 100 iterations; astronomically unlikely to fail for random hashes, but it is a **theoretical revert** path if ever mis-seeded.
- **Soundness budget is parameter-bound:** the intended error budget comes from the Winterfell-style combination of `NUM_QUERIES = 44`, blowup factor `8`, quadratic extension, and `GRINDING_BITS = 20`; this note does **not** re-derive the exact bound, but the code-level parameter alignment is visible in Rust and Solidity.

---

## Field / arithmetic and encoding review

**Goldilocks base field** (`contracts/src/GoldilocksField.sol`): `P = 2^64 - 2^32 + 1`; `add`/`mul`/`exp`/`inv` via `addmod`/`mulmod`; quadratic extension uses `t^2 = t - 2` per comments, with `mulExt` / `invExt` consistent with Winterfell’s extension tests (see `StarkVerifierV2.t.sol` vectors).

**Verifier geometry:** `LDE_DOMAIN_SIZE = 64`, `TRACE_LENGTH = 8`, blowup 8, `g_lde = 8`, `dom_offset = 7`, `g_trace` hard-coded; transition divisor uses `(z^8 - 1)/(z - g^7)` with `G7 = trace_domain_gen^7`, matching an 8-row cyclic domain with last-row exception for the counter column.

**Leaf hashing:** trace leaves hash **18 × 8-byte LE** base-field evaluations; constraint leaves hash **16-byte LE** extension evaluation—consistent with `KeccakHash::hash_elements` on base vs extension serialization in Rust **if** Winterfell commits leaves the same way (E2E fixture tests are the regression guard).

**Public input bounds:** Solidity returns `false` if any `publicInputs[i] ≥ P`; prevents non-canonical encodings at the boundary.

**tx_hash split:** `StarkZkAceAccount` uses `keccak256(userOp.callData)` and reduces each 64-bit limb with `% P`, matching `gen_sol_proof`’s calldata path. WASM splits 32 bytes as big-endian `u64` then `BaseElement::new`, which applies modular reduction—**aligned** with the above for honest encoders.

---

## Rust / WASM / Solidity parity review

| Area | Rust (Winterfell) | WASM | Solidity |
|------|-------------------|------|----------|
| STARK hash | `KeccakHash` | Same crate stack via `zk_ace_stark` | `keccak256` |
| FS public inputs | `ZkAcePublicInputs::to_elements` order | `pub_inputs_to_u64_vec` same order | `_toLE` on `uint64[17]` same order |
| Proof bytes | `proof.to_bytes()` | Hex wraps same bytes | `verifyProof` fixed layout offsets |
| Rescue digests | `Rp64_256::hash_elements` → LE u64 limbs | `compute_id_commitment` / prover share `rescue_hash_full` | Not computed on-chain |

**WASM-specific notes** (`crates/zk-ace-stark-wasm/src/lib.rs`):

- `rev` / `salt` hex: interpreted as **big-endian**, up to 8 bytes—must match how signers define those secrets vs Rust CLI/tests (which often use `BaseElement::new(0x…u64)` = **little-endian** numeric constant if fed as integer). This is an **integration convention** risk, not a verifier bug.
- JSON `pub_inputs` exposes `inner()` Montgomery-backed `u64`; consumers must treat them as **field integers in `[0,P)`**, not opaque “wire” words, when cross-checking hex packings.

**Rust `serialization.rs`:** gas-estimate comments still mention 32 queries and FRI layers that do not match `default_proof_options()` (44 queries); **documentation drift only**.

---

## Concrete audit conclusions / likely findings

1. **Statement / AIR (informational → design):** STARK proves consistency of a **degenerate trace** with public digests; **cryptographic identity binding is Rescue + `idCom`**, not algebraic constraints inside the AIR.
2. **Fiat-Shamir (high severity if misconfigured):** correctness hinges on exact `AirContext`/options byte encoding in `StarkVerifier`’s initial seed; require **locked dependency versions** and a **regression test** that fails if Winterfell serialization changes.
3. **Interface / nonce semantics (medium, assumptions):** no on-chain check that witness `nonce` matches `zkNonce` before proof acceptance; `rp_com` is not recomputed in Solidity. Document reliance on **4337 nonce**, calldata binding, and wallet always using current `zkNonce` when proving.
   The Solidity NatSpec around Step 9 reads stronger than the actual EVM checks: it describes `rp_com` verification and says it changes each transaction, but the contract does not compare `rp_com` against recomputed or prior state.
4. **Encoding integration (low → medium):** WASM BE hex parsing for `rev`/`salt` vs other tools’ conventions; ensure end-to-end vectors define endianness explicitly.
5. **Verifier completeness:** Solidity reimplements DEEP + remainder + OOD checks and rejects tampered roots/digests; field constants are **hard-coded** (good for removing proof malleability via `O_FC`).
6. **Verifier regression environment:** Foundry E2E tests expect `contracts/test/fixtures/stark_proof.hex`; environments with restricted `fs` permissions may skip real-proof verification, so CI and release validation should preserve fixture-read capability.

---

## References (primary)

- `crates/zk-ace-stark/src/air.rs`, `prover.rs`, `verifier.rs`, `rescue.rs`, `keccak_hasher.rs`, `serialization.rs`
- `crates/zk-ace-stark-wasm/src/lib.rs`
- `contracts/src/StarkVerifier.sol`, `GoldilocksField.sol`, `StarkZkAceAccount.sol`
- `contracts/test/StarkE2E.t.sol`, `StarkVerifierV2.t.sol`
- `crates/zk-ace-stark/src/bin/gen_sol_proof.rs` (fixture / calldata `tx_hash` encoding)
