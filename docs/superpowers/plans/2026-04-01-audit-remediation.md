# Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all actionable findings from the security audit, test E2E locally, then deploy the hardened system to Arbitrum One.

**Architecture:** Fix 8 findings across Rust circuit layer and Solidity contract layer, regenerate trusted setup + proof fixtures, verify everything end-to-end on local chain and Arbitrum fork, then deploy.

**Tech Stack:** Rust/arkworks (circuit), Solidity 0.8.28/Foundry (contracts), Arbitrum One (deployment)

---

### Task 1: Remove dead C3 code from circuit (CRIT-3)

**Files:**
- Modify: `crates/zk-ace-circuit/src/circuit.rs:82-89`
- Modify: `crates/zk-ace-circuit/src/constraints.rs` (remove `compute_auth_var`)
- Test: existing circuit tests

Remove the unused C3 Authorization Binding computation. It adds ~1,615 constraints (~40%) but its output is discarded. The tx_hash is already bound as a Groth16 public input.

### Task 2: Fix C1 to use witness ctx_domain_var (LOW-1)

**Files:**
- Modify: `crates/zk-ace-circuit/src/circuit.rs:72-74`

Change C1 from `domain_var` (public input) to `ctx_domain_var` (witness). C5 still enforces they're equal, but now C1 is self-contained.

### Task 3: Zeroize REV in Rust types (HIGH-5)

**Files:**
- Modify: `crates/zk-ace-circuit/src/types.rs`
- Modify: `crates/zk-ace-circuit/Cargo.toml` (add zeroize dep)

Remove `Debug` and `Clone` from `ZkAceWitness`. Add `Zeroize` + `ZeroizeOnDrop`.

### Task 4: Add public input range validation to Solidity verifier (HIGH-4)

**Files:**
- Modify: `crates/zk-ace-prover/src/solidity.rs` (codegen template)

Add `require(input[i] < SNARK_SCALAR_FIELD)` for all 5 public inputs.

### Task 5: Add identity rotation with timelock (CRIT-4)

**Files:**
- Modify: `contracts/src/ZkAceAccount.sol`

Replace `immutable idCom` with mutable storage + a 2-step rotation: `proposeNewIdentity(newIdCom)` queues it, `confirmIdentityRotation()` activates it after a timelock. Only callable via a valid ZK proof through the EntryPoint (i.e. the current identity holder).

### Task 6: Remove separate nonce from signature encoding (HIGH-7)

**Files:**
- Modify: `contracts/src/ZkAceAccount.sol` (decode signature without separate nonce)

The nonce is already inside the ZK proof as part of rp_com. On-chain, use `zkNonce` directly instead of decoding a separate nonce from the signature. This eliminates the binding gap.

### Task 7: Reject dev-ceremony keys on mainnet (CRIT-2)

**Files:**
- Modify: `contracts/src/ZkAceAccount.sol` (add chainId guard in constructor)
- Modify: `crates/zk-ace-prover/src/bin/setup.rs`

Embed a flag in the setup to mark dev vs production keys. On-chain, the verifier contract itself doesn't need to change — but the setup binary should refuse deterministic seeds when `--production` flag is set.

### Task 8: Regenerate setup + fixtures, run all tests

Regenerate the trusted setup (constraint count changes after removing C3), regenerate proof fixtures for chain 31337 and 42161, update all hardcoded fixtures in Solidity tests.

### Task 9: Deploy to Arbitrum One and E2E test

Deploy the hardened contracts, verify proof on-chain, validate + execute a transaction via the new architecture.
