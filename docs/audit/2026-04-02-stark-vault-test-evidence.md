# STARK vault audit — runtime test evidence (2026-04-02)

This document records **fresh runtime evidence** collected for the STARK vault audit: commands executed, pass/fail outcomes, and how each run relates to security-relevant claims. It is intentionally narrow: it describes what ran and what succeeded, not a full threat model or formal assurance.

## Commands run

| Command | Result | What it evidences |
|--------|--------|-------------------|
| `cargo test -p zk-ace-stark` | **PASS** | Rust STARK stack: 15 unit tests and 7 property tests passed (prover round-trip, verifier round-trip, wrong public inputs rejected, keccak and rescue coverage). Compiler noted: unused import `StarkField` in `crates/zk-ace-stark/src/keccak_hasher.rs`; dead-code warnings in `src/bin/fuzz_verifier.rs`. |
| `cargo test -p zk-ace-stark-wasm` | **PASS** | WASM bindings: 4 tests passed (`compute_id_commitment`, deterministic commitment, `get_proof_public_inputs`, `generate_stark_proof`). |
| `forge test --match-path contracts/test/StarkE2E.t.sol` (cwd: repo root) | **PASS** | On-chain E2E with real fixture: 6 tests; `test_realStarkProofVerifies` and `test_realStarkProofGas` (~5.6M gas); tampered proof and wrong public inputs rejected; `numQ=0` and excessive `numQ` rejected. |
| `forge test --match-path contracts/test/StarkVerifierV2.t.sol` (cwd: repo root) | **PASS** | Verifier-focused suite: 13 tests; extension-field vectors; valid proof accepted; invalid public input, wrong OOD digest, wrong PoW nonce, field overflow rejected; gas ~5.6M on measured case. |
| `forge test --match-path contracts/test/GoldilocksField.t.sol` (cwd: repo root) | **PASS** | Field arithmetic: 33 tests including fuzz (commutativity, distributivity, inverses, Fermat) and explicit reduce/add/sub/mul/exp/inv cases. |
| `forge test --match-path contracts/test/StarkZkAceAccount.invariant.t.sol` (cwd: repo root) | **PASS** | Account invariants: 2 tests; `invariant_nonce_never_decreases` and `invariant_timelock_respected` over 256 runs / 128000 calls. |
| `forge test --match-path test/StarkE2E.t.sol` (cwd: `contracts/`) | **FAIL** | All 6 tests failed: `vm.readFile` denied for fixture path (see below). Does **not** indicate verifier logic failure when fixtures load correctly. |
| `forge test --match-path test/StarkVerifierV2.t.sol` (cwd: `contracts/`) | **FAIL** | Suite failed overall: 7 tests passed; 6 fixture-backed tests failed with the same `vm.readFile` permission error. |

## Forge: root-cause of repo-root vs `contracts/` divergence

STARK suites that load proofs via `vm.readFile` **pass when Forge’s working directory and config match the allowlisted path**, and **fail when run from `contracts/`** with the observed error:

`vm.readFile: the path contracts/test/fixtures/stark_proof.hex is not allowed to be accessed for read operations`

**Observed configuration and usage:**

- The **repository root** `foundry.toml` includes `fs_permissions = [{ access = "read", path = "./contracts/test/fixtures" }]`.
- `contracts/test/StarkE2E.t.sol` reads `contracts/test/fixtures/stark_proof.hex`.
- `contracts/test/StarkVerifierV2.t.sol` reads the same fixture path.

From the **repo root**, that relative path aligns with the configured allowlist, so reads succeed and tests complete. From **`contracts/`** as the project root, the nested `contracts/foundry.toml` allowlists **`./test/fixtures`**, but the tests still request **`contracts/test/fixtures/stark_proof.hex`**. That hardcoded path no longer matches the active allowlist, so `vm.readFile` is denied. **This is a tooling/configuration and invocation mismatch, not by itself proof of a cryptographic bug.**

Anyone reproducing these results should run fixture-backed Forge tests from the repository root (or adjust `fs_permissions`/paths consistently for their chosen cwd).

## What this evidence does and does not prove

**Does support (within the scope of the tests run):**

- Consistency of the Rust STARK implementation and WASM surface under the exercised unit/property cases.
- That the Solidity verifier and E2E paths **accept a known-good fixture** and **reject several malformed or inconsistent inputs** as modeled in the tests (tampering, wrong public inputs, bad `numQ`, OOD/PoW/overflow cases where covered).
- That Goldilocks field operations in contract code match the tested algebraic properties over the fuzzed/unittest ranges.
- That the invariant harness did not find counterexamples for nonce monotonicity and timelock behavior under its configured fuzz parameters.

**Does not establish:**

- Security against all adversarial proofs or a complete proof system soundness proof.
- Correctness on all chains, all compiler versions, or all deployment configurations.
- Absence of implementation bugs outside covered branches, or economic / MEV / account-abstraction integration risks not exercised here.
- That running from `contracts/` without aligned `fs_permissions` means the on-chain code is wrong — only that **those runs could not load fixtures**.

---

*Evidence captured for audit Task 6: baseline and adversarial tests tied to major security claims, with explicit limits on interpretation.*
