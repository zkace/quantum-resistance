# STARK Vault Audit — Scope Freeze (2026-04-02)

**Status:** Baseline record for a firm-grade security review.  
**Branch:** `audit/stark-vault-current`  
**Git baseline:** **No commit exists** (unborn repository). The audit artifact is the **current working tree** on this branch at the time this document was prepared. There is **no** reproducible `git rev-parse` identifier tying the review to an immutable object.

---

## 1. Audit target definition

**Primary target:** The **ZK-ACE STARK vault stack** — browser/client proof generation (Winterfell-based STARK over the ZK-ACE AIR), on-chain STARK verification in Solidity (Goldilocks + Keccak256), and ERC-4337 account logic that binds proofs to `UserOperation` context (`callData` hash, chain domain, identity commitment, nonce semantics).  

**Non-target for this scope:** The **Groth16 / BN254** wallet path (`ZkAceAccount`, `ZkAceVerifier`, Poseidon circuit crates, Groth16 prover artifacts, and the TypeScript `sdk/` package, which does not reference the STARK path).

---

## 2. Primary in-scope components (file paths)

### On-chain (Solidity)

| Role | Path |
|------|------|
| STARK verifier | `contracts/src/StarkVerifier.sol` |
| Verifier interface | `contracts/src/IStarkVerifier.sol` |
| Goldilocks / extension arithmetic (verifier dependency) | `contracts/src/GoldilocksField.sol` |
| ERC-4337 STARK account | `contracts/src/StarkZkAceAccount.sol` |
| CREATE2 factory | `contracts/src/StarkZkAceAccountFactory.sol` |
| STARK-focused tests / harnesses | `contracts/test/StarkE2E.t.sol`, `contracts/test/StarkVerifierV2.t.sol`, `contracts/test/StarkVerifier.sym.t.sol`, `contracts/test/StarkVerifierDifferential.t.sol`, `contracts/test/StarkZkAceAccount.invariant.t.sol`, `contracts/test/GoldilocksField.t.sol`, `contracts/test/ZkAceHandler.sol` |

**STARK on-chain test fixtures (hex blobs read by Foundry tests):**

| Fixture path | Consumed by |
|--------------|-------------|
| `contracts/test/fixtures/stark_proof.hex` | `StarkE2E.t.sol`, `StarkVerifierV2.t.sol` (`vm.readFile` with repo-relative path) |
| `contracts/test/fixtures/fuzz/pub_inputs.hex` | `StarkVerifierDifferential.t.sol` |
| `contracts/test/fixtures/fuzz/proof_valid.hex` | `StarkVerifierDifferential.t.sol` |
| `contracts/test/fixtures/fuzz/proof_trace_comm.hex` | `StarkVerifierDifferential.t.sol` |
| `contracts/test/fixtures/fuzz/proof_constr_comm.hex` | `StarkVerifierDifferential.t.sol` |
| `contracts/test/fixtures/fuzz/proof_fri_comm.hex` | `StarkVerifierDifferential.t.sol` |
| `contracts/test/fixtures/fuzz/proof_ood_digest.hex` | `StarkVerifierDifferential.t.sol` |
| `contracts/test/fixtures/fuzz/proof_pow_nonce.hex` | `StarkVerifierDifferential.t.sol` |

`StarkVerifierDifferential.t.sol` loads the fuzz fixtures via `string.concat(vm.projectRoot(), "/test/fixtures/fuzz/…")`; that resolves to the paths above when Forge’s project root is the `contracts/` directory (as in `contracts/foundry.toml`).

**Normative test invocation for STARK differential suites:** run them from `contracts/` (for example, `cd contracts && forge test --match-contract StarkVerifierDifferentialTest`). With the **repository-root** `foundry.toml`, `vm.projectRoot()` resolves differently and `readFile` can fall outside the configured `fs_permissions`, so repo-root Forge execution is **not** the frozen baseline for these tests.

**Forge invocation matrix (to avoid false-negative repros):**

| Suite family | Canonical cwd | Reason |
|--------------|---------------|--------|
| `contracts/test/StarkE2E.t.sol`, `contracts/test/StarkVerifierV2.t.sol` | repository root | Tests read `contracts/test/fixtures/...`, which matches root `foundry.toml` `fs_permissions = ./contracts/test/fixtures` |
| `contracts/test/StarkVerifierDifferential.t.sol` | `contracts/` | Test uses `vm.projectRoot() + "/test/fixtures/fuzz/..."`, which aligns with `contracts/foundry.toml` and `./test/fixtures` |
| `contracts/test/StarkZkAceAccount.invariant.t.sol`, `contracts/test/GoldilocksField.t.sol` | repository root | No external proof fixture dependency observed in this freeze; repo-root invocation matches the main evidence runbook |

The tampered `proof_*.hex` set under `contracts/test/fixtures/fuzz/` is produced by the Rust helper `crates/zk-ace-stark/src/bin/fuzz_verifier.rs` (output directory `contracts/test/fixtures/fuzz`).

`StarkVerifier.sym.t.sol` and `StarkZkAceAccount.invariant.t.sol` do **not** read external proof fixtures (synthetic / handler-driven state only).

*Note:* `contracts/script/Deploy.s.sol` deploys the **STARK verifier bytecode** alongside the **Groth16 account stack**, but it does **not** deploy `StarkZkAceAccountFactory`. Treat it as **context only** unless the engagement explicitly expands to deployment-path review.

### Prover / AIR (Rust — Winterfell)

| Role | Path |
|------|------|
| Crate root | `crates/zk-ace-stark/Cargo.toml`, `crates/zk-ace-stark/src/lib.rs` |
| AIR / public inputs | `crates/zk-ace-stark/src/air.rs` |
| Prover / witness / public input derivation | `crates/zk-ace-stark/src/prover.rs` |
| Rescue-Prime | `crates/zk-ace-stark/src/rescue.rs` |
| Transcript / hashing alignment | `crates/zk-ace-stark/src/keccak_hasher.rs` |
| Proof (de)serialization | `crates/zk-ace-stark/src/serialization.rs` |
| Rust verifier (differential / testing) | `crates/zk-ace-stark/src/verifier.rs` |
| Bins / tests (supporting evidence) | `crates/zk-ace-stark/src/bin/benchmark.rs`, `crates/zk-ace-stark/src/bin/fuzz_verifier.rs`, `crates/zk-ace-stark/src/bin/gen_sol_proof.rs`, `crates/zk-ace-stark/tests/proptest.rs` |

### Browser WASM bridge

| Role | Path |
|------|------|
| WASM crate | `crates/zk-ace-stark-wasm/Cargo.toml`, `crates/zk-ace-stark-wasm/src/lib.rs` |

### Vault client (production-shaped app)

| Role | Path |
|------|------|
| Application shell and build inputs | `vault-app/index.html`, `vault-app/package.json`, `vault-app/vite.config.ts`, `vault-app/src/main.ts` |
| Browser prover payload present in the working tree (gitignored by `vault-app/public/wasm/.gitignore`) | `vault-app/public/wasm/package.json`, `vault-app/public/wasm/zk_ace_stark_wasm.js`, `vault-app/public/wasm/zk_ace_stark_wasm.d.ts`, `vault-app/public/wasm/zk_ace_stark_wasm_bg.wasm`, `vault-app/public/wasm/zk_ace_stark_wasm_bg.wasm.d.ts`, `vault-app/public/wasm/.gitignore` |
| Built client artifacts present in-repo at freeze time | `vault-app/dist/index.html`, `vault-app/dist/assets/index-BvlRPxek.js`, `vault-app/dist/assets/ccip-B_FchW0P.js`, `vault-app/dist/wasm/package.json`, `vault-app/dist/wasm/zk_ace_stark_wasm.js`, `vault-app/dist/wasm/zk_ace_stark_wasm.d.ts`, `vault-app/dist/wasm/zk_ace_stark_wasm_bg.wasm`, `vault-app/dist/wasm/zk_ace_stark_wasm_bg.wasm.d.ts`, `vault-app/dist/wasm/.gitignore` |

**Minimal provenance note for browser prover assets:** the normative source crate is `crates/zk-ace-stark-wasm/src/lib.rs`; `vault-app/vite.config.ts` builds the web app into `vault-app/dist`, while `vault-app/public/wasm/package.json` identifies the browser prover payload as `zk-ace-stark-wasm` version `0.1.0`. Exact reproduction commands and toolchain versions are deferred to the dedicated reproducibility phase.

### Normative security narrative (read-only inputs to align claims)

- `docs/audit/threat_model.md` — invariants and trust boundaries used to derive the **claim set** below.

---

## 3. Primary out-of-scope items

- **Groth16 path:** `contracts/src/ZkAceAccount.sol`, `contracts/src/ZkAceVerifier.sol`, `contracts/src/ZkAceAccountFactory.sol`, `contracts/src/IZkAceVerifier.sol`, `crates/zk-ace-circuit/`, `crates/zk-ace-prover/` (SNARK setup / fixtures), and Groth16-centric tests.
- **TypeScript SDK:** `sdk/` (no STARK references; separate authorization stack).
- **Explicitly out-of-scope in `docs/audit/threat_model.md` §1.2:** compromised mnemonic/REV; **L1 consensus failure** (including 51% attacks, **Arbitrum sequencer censorship**, and **Ethereum mainnet reorganization**); **compiler/EVM bugs** (e.g. `solc`, EVM Keccak256 / static-call behavior).
- **Out-of-scope for this STARK vault freeze (not stated in `threat_model.md`):** ERC-4337 **`EntryPoint`** implementation, **bundler / paymaster** logic (e.g. Pimlico), and **JSON-RPC provider** correctness — treated as environmental assumptions unless the engagement explicitly expands.
- **Operational / marketing surfaces:** `website/`, the separate `wallet/` tree, hosting/CDN compromise models beyond noting supply-chain risk, and any go-to-market collateral not needed to validate technical claims.
- **Vendor libraries and protocol dependencies:** `contracts/lib/`, Winterfell internals outside `crates/zk-ace-stark` call sites, and third-party ERC-4337/bundler infrastructure are treated as dependency context unless the engagement explicitly expands into dependency audit.
- **Unused or adjacent identity stacks:** `crates/zk-ace-didp/` is excluded from the primary STARK vault freeze; the normative client derivation path for this engagement is the one exercised by `vault-app/src/main.ts` and `crates/zk-ace-stark-wasm/src/lib.rs`.
- **Bytecode–source equality:** Proving deployed Arbitrum contracts match this tree **without** explicit bytecode diff or verified build reproducibility is **not** asserted here.

---

## 4. Deployed references and chain assumptions

**Assumed primary deployment environment (from `vault-app/src/main.ts` and project collateral):**

| Item | Value |
|------|--------|
| **Chain** | **Arbitrum One** (Ethereum L2) |
| **Chain ID** | `42161` (as coded in `vault-app/src/main.ts`) |
| **EntryPoint (v0.7)** | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| **StarkVerifier** | `0xE1B8750ED6Fd835e7D27a1A4F08532BDbFb9F6d4` |
| **StarkZkAceAccountFactory** | `0x5c7D026978Fa2D159dCC0Bb87F25DbaBfE872614` |

**Collateral reference (example transaction cited in `ZK-ACE-Acquisition-Memo.md`):**  
`0x275451c9160e2f7fe72f6652e352bdd1e47e0853514a8278f7fefbe3e35e4491` on Arbiscan — useful as a **public behavioral sample**, not as a substitute for bytecode verification.

**Hosted client (marketing / ops reference):** `https://zkace-vault.vercel.app` — **not** cryptographically bound to this repository snapshot without independent artifact hashing and deployment provenance review.

**Assumption:** Reviewers treat **Arbitrum One** as the authoritative deployment for this freeze unless the engagement explicitly adds other chains. Grant and strategy documents mention multi-chain narratives; those are **out of scope** unless separately frozen.

---

## 5. Claim set under audit

### A. Implementation / cryptographic claims (core audit obligations)

These are claims the **code + stated parameters** are expected to substantiate (subject to explicit assumptions in `docs/audit/threat_model.md`):

1. **STARK soundness interface:** For the fixed AIR parameters encoded in `StarkVerifier` and `zk-ace-stark` (trace size, LDE domain, query count, grinding, Fiat-Shamir wiring, Merkle/FRI layout), acceptance of a proof implies the Winterfell-generated statement about the trace satisfying the ZK-ACE constraints for the given **17** Goldilocks public inputs — modulo standard STARK/hash assumptions.
2. **Public input hygiene:** All Goldilocks limbs in `publicInputs` are enforced `< p` where `p = 2^64 - 2^32 + 1` (prevents modular aliasing per threat model).
3. **Account binding:** `StarkZkAceAccount` does not treat prover-supplied `tx_hash` limbs as authoritative; it recomputes binding from `userOp.callData` and compares to decoded public inputs.
4. **Domain separation:** Authorization is bound to the expected chain domain (per account / deployment model) so trivial cross-chain replay of the same proof against another chain’s deployment is ruled out by design intent.
5. **Replay control:** `zkNonce` advances only after successful validation; proofs are tied to a replay-prevention commitment that includes nonce material as specified in the AIR / public input layout (`rp_com`).
6. **Identity rotation:** Two-step rotation with delay (`ROTATION_DELAY`) and enforced `confirm` timing; nonce not reset across rotation (per `docs/audit/threat_model.md`).
7. **Pause semantics:** When paused, user execution paths are blocked while unpause via proof remains coherent with the documented “no deadlock” intent.
8. **Prover–verifier alignment:** Rust prover + WASM wrapper produce proofs and public-input encodings consistent with the Solidity verifier’s parsing and Fiat-Shamir transcript (including Keccak256 usage and endianness conventions).

### B. Marketing / public claims (not proven by code alone)

These appear in `ZK-ACE-Guide.md`, `ZK-ACE-Acquisition-Memo.md`, and similar collateral. Auditors should **label** them separately; confirmation requires **operational** evidence (chain analytics, economics, competitive market survey), not only Solidity/Rust review:

- Uniqueness or “first/only” post-quantum wallet on EVM.
- Absolute statements such as “no ECDSA anywhere” in the **end-to-end product** (depends on bundler, paymaster, and any auxiliary flows).
- Concrete **$/tx**, gas totals (e.g. ~5.6M), latency, WASM size — environment-dependent.
- “All components live and processed real transactions” — deployment and metrics claim.
- Broader quantum threat timelines and NIST narrative — contextual, not implementation lemmas.

**Research paper:** `arXiv:2603.07974v2` (PDF in repo: `2603.07974v2.pdf`) — scientific framing; **consistency** with the implementation is in scope; **peer review status** of the paper is not.

---

## 6. Trust boundaries and key assets

**Trust boundaries (summary):**

| Boundary | Holds |
|----------|--------|
| **User device / browser** | Mnemonic, REV derivation (`PBKDF2` parameters in client), WASM prover execution, private key material never sent on-chain |
| **Hostile network** | Observes calldata, UserOps, on-chain state |
| **On-chain adversary** | May call contracts with arbitrary calldata and submit arbitrary proof blobs |
| **Dependencies** | Winterfell, viem, bundler, EntryPoint — correctness assumed per engagement |

**Key assets:**

- **Funds** held in `StarkZkAceAccount` instances.
- **Identity commitment (`idCom`)** and **nonce ordering** — integrity and availability of authorization.
- **Verifier correctness** — universal contract; a flaw affects all dependent accounts.

---

## 7. Known scoping caveats

1. **Unborn git history:** There is **no** merkle root of the source. Reproducibility is **weakened**: reviewers cannot diff “patched vs baseline” via VCS; escrow of archives (tarball hash) or an initial tag is strongly recommended before release-signing or external attestation.
2. **Dual-stack repository confusion:** The same tree contains **STARK** and **Groth16** stacks, a **combined** `Deploy.s.sol`, and shared test utilities. Mis-identifying which verifier bytecode is deployed for a given account is a **real** operational risk; this freeze **only** covers the STARK vault path above.
3. **Deployed bytecode vs source:** Frozen addresses on Arbitrum One are **not** automatically equivalent to the current working tree. Bytecode verification (e.g. Arbiscan) and/or reproducible builds must be an **explicit** follow-on if the engagement requires “matches production.”
4. **Client supply chain:** `vault-app` depends on npm ecosystem and prebuilt WASM; compromise of build pipelines or pinned artifacts is a **deployment** threat partially outside core cryptographic review.
5. **Parameter drift:** STARK security margins (queries, blowup, grinding) are split across Rust options, Solidity constants, and documentation (`threat_model.md`, comments). Inconsistency across layers is an **in-scope** implementation hazard.
6. **Built web assets are unstable identifiers:** hashed files under `vault-app/dist/assets/` are frozen only as the artifacts present when this memo was written. Any rebuild requires re-freezing those names or replacing them with a signed artifact manifest.

---

*End of scope freeze.*
