# ZK-ACE Threat Model & Invariants

This document formally specifies the trust boundaries, attacker capabilities, and cryptographic assumptions underpinning the ZK-ACE quantum-resistant wallet system. It forms the basis of the formal verification, fuzzing, and auditing strategy.

## 1. Trust Boundaries & Attacker Capabilities

### 1.1 In-Scope Threats
We assume a powerful adversary with the following capabilities:
- **Quantum Computing Access:** The attacker has access to a Cryptographically Relevant Quantum Computer (CRQC) capable of running Shor's algorithm (efficiently solving ECDLP) and Grover's algorithm (providing a quadratic speedup for unstructured search).
- **Network Omniscience:** The attacker can observe all on-chain state, memory, and mempool transactions (including calldata and signatures).
- **Prover Manipulation:** The attacker can generate valid, malformed, or perfectly structured but semantically invalid STARK proofs to submit to the verifier contract.
- **Contract State Manipulation:** The attacker can submit transactions calling any external function on the `StarkZkAceAccount` with arbitrary inputs.

### 1.2 Out-of-Scope Threats
- **Compromised Mnemonic/REV:** If an attacker obtains the user's 24-word mnemonic or 64-byte REV directly (via malware, social engineering, keylogging, or physical theft), the system is considered fully compromised.
- **L1 Consensus Failure:** 51% attacks, Arbitrum sequencer censorship, or Ethereum mainnet reorganization.
- **Compiler/EVM Bugs:** Bugs in the `solc` compiler or the Ethereum Virtual Machine implementation of Keccak256 or static calls.

## 2. Cryptographic Assumptions

ZK-ACE relies purely on symmetric cryptography and hash functions, avoiding elliptic curves completely.

### 2.1 Grover's Algorithm & Hash Collision Resistance
- **Assumption:** Keccak256 and Rescue-Prime (Rp64_256) behave as random oracles.
- **Post-Quantum Security:** Grover's algorithm reduces the collision resistance of an $n$-bit hash function to $n/2$ bits. Both Keccak256 and Rp64_256 output 256 bits, yielding 128 bits of post-quantum security.
- **Invariant:** It is computationally infeasible (requiring $\sim 2^{128}$ quantum operations) to find a second preimage for `IDcom` (identity commitment) or to forge a Merkle path in the STARK trace.

### 2.2 Goldilocks Field Arithmetic
- **Assumption:** The prime $p = 2^{64} - 2^{32} + 1$ is safe for all arithmetic operations. Elements must strictly be $< p$.
- **Invariant (Solidity Verifier):** The verifier contract MUST reject any public input $\ge p$. Failure to do so allows aliasing (multiple values mapping to the same field element modulo $p$), breaking soundness.

### 2.3 STARK Soundness (Fiat-Shamir & FRI)
- **Assumption:** The Fiat-Shamir transcript correctly binds all proof elements (trace commitments, constraint evaluations, OOD points, and FRI layers) to the public inputs.
- **Assumption:** The FRI protocol with 44 queries and a blowup factor of 8 provides 132 bits of soundness against classical and quantum adversaries.
- **Invariant:** Modifying *any* single bit of a valid STARK proof or its corresponding public inputs must deterministically result in rejection by the `StarkVerifier` contract.

## 3. Smart Contract Invariants (StarkZkAceAccount)

The state machine of the vault must enforce strict authorization and replay protection rules.

### 3.1 Replay Protection (Nonce Monotonicity)
- **Invariant 1:** The `zkNonce` must monotonically increase. It can never decrease or reset under any circumstance.
- **Invariant 2:** A STARK proof is strictly bound to a specific `zkNonce` via the `rpCom` public input ($rpCom = Rescue(IDcom, nonce)$). A valid proof for nonce $N$ cannot authorize a transaction for nonce $N+1$ or any other nonce.
- **Invariant 3:** The `domainTag` (chain ID) binds a proof to a specific chain, preventing cross-chain replays.

### 3.2 Context Binding (TxHash)
- **Invariant 4:** The `txHash` public input must be recomputed on-chain directly from the transaction `callData`. It must never be trusted as a prover-supplied input without recomputation.

### 3.3 Identity Rotation Timelock
- **Invariant 5:** `confirmIdentityRotation()` must strictly revert if `block.timestamp < rotationUnlocksAt`.
- **Invariant 6:** `rotationUnlocksAt` is always set to `block.timestamp + ROTATION_DELAY` (48 hours) upon `proposeIdentityRotation()`.
- **Invariant 7:** `zkNonce` is NOT reset during an identity rotation, preventing replay windows across identities.

### 3.4 Emergency Pause Safety
- **Invariant 8:** If `paused == true`, all standard `execute()` or `executeBatch()` calls must revert.
- **Invariant 9:** A valid STARK proof can always call `setPaused(false)` to unpause the contract, preventing a permanent deadlock. The pause check must not block the `setPaused` function itself.
