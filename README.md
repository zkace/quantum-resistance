# ZK-ACE: Quantum-Resistant EVM Wallets

The only deployed post-quantum wallet on any EVM chain. STARK proofs replace ECDSA signatures entirely. No elliptic curves. No pairings. No trusted setup. 128-bit post-quantum security.

Based on [ZK-ACE: Identity-Centric Zero-Knowledge Authorization for Post-Quantum Blockchain Systems](https://arxiv.org/abs/2603.07974v2) (Wang, 2026).

**Website:** [zkace.io](https://zkace.io) | **App:** [vault.zkace.io](https://vault.zkace.io) | **FAQ:** [zkace.io/faq.html](https://zkace.io/faq.html)

## Deployed on 4 EVM Chains

| Chain | StarkVerifier | Vault Factory |
|-------|-------------|---------------|
| Arbitrum One | [`0xE1B8...f6d4`](https://arbiscan.io/address/0xE1B8750ED6Fd835e7D27a1A4F08532BDbFb9F6d4) | [`0x5c7D...2614`](https://arbiscan.io/address/0x5c7D026978Fa2D159dCC0Bb87F25DbaBfE872614) |
| Base | [`0x6DE1...E010`](https://basescan.org/address/0x6DE1A42fD9c1aB4A46D8Af388a212F772513E010) | [`0x0189...8520`](https://basescan.org/address/0x01896D39682d9f95c801E286ed5abEB3D7738520) |
| Optimism | [`0x6DE1...E010`](https://optimistic.etherscan.io/address/0x6DE1A42fD9c1aB4A46D8Af388a212F772513E010) | [`0xc638...54b1`](https://optimistic.etherscan.io/address/0xc638FdFCb0Ae33d54ecff1A4c6FdaDb52D5654b1) |
| Polygon | [`0x6DE1...E010`](https://polygonscan.com/address/0x6DE1A42fD9c1aB4A46D8Af388a212F772513E010) | [`0x0189...8520`](https://polygonscan.com/address/0x01896D39682d9f95c801E286ed5abEB3D7738520) |

Confirmed end-to-end quantum-resistant transactions on [Arbitrum](https://arbiscan.io/tx/0x275451c9160e2f7fe72f6652e352bdd1e47e0853514a8278f7fefbe3e35e4491) and [Base](https://basescan.org/tx/0x11f38c2d720f348bbf7792ea2173026881991c5fb1dcd9adc0e49daca347d534).

## How It Works

```
24-word BIP-39 mnemonic
  -> PBKDF2-SHA512 (600K iterations)
    -> Identity secret (REV)
      -> Poseidon2 hash -> Identity commitment (on-chain, 32 bytes)
        -> STARK proof generated in browser (484 KB WASM, 5-10 sec)
          -> ERC-4337 UserOperation submitted via bundler
            -> On-chain STARK verification (~5.6M gas, ~$0.20 on L2)
              -> Transaction executed
```

No ECDSA signature anywhere. No elliptic curves. The entire authorization chain uses only hash-based cryptography (Keccak256 + Poseidon2, with Rescue-Prime retained for legacy vaults), which quantum computers cannot break.

## Architecture

```
Browser (no backend, no server)
  |-- BIP-39 Mnemonic -> PBKDF2-SHA512 -> REV (identity secret)
  |-- WASM Prover (Winterfell STARK, 484 KB)
  |     |-- Poseidon2 identity commitment (legacy Rescue-Prime supported)
  |     |-- 18-column AIR, 44 FRI queries, 20-bit PoW
  |     |-- 128-bit post-quantum security
  |-- ERC-4337 UserOperation construction
  |-- Pimlico bundler submission
       |-- EntryPoint v0.7
       |-- StarkZkAceAccount (_validateSignature)
       |     |-- Recompute txHash from calldata
       |     |-- Verify IDcom, domain, nonce
       |     |-- Call StarkVerifier.verifyProof()
       |-- StarkVerifier (19 verification checks)
             |-- Fiat-Shamir transcript reconstruction
             |-- OOD constraint evaluation
             |-- DEEP algebraic composition
             |-- Merkle proof verification (44 queries)
             |-- Remainder polynomial check
```

## Project Structure

```
crates/
  zk-ace-stark/          # STARK prover/verifier (Winterfell, Keccak256)
  zk-ace-stark-wasm/     # Browser WASM prover (484 KB)

contracts/src/
  StarkVerifier.sol            # Complete on-chain STARK verification
  StarkZkAceAccount.sol        # ERC-4337 account with STARK proof validation
  StarkZkAceAccountFactory.sol # CREATE2 factory for deterministic vault addresses
  GoldilocksField.sol          # Goldilocks field arithmetic + quadratic extension

vault-app/               # Production web app (Vite + TypeScript)
website/                 # Marketing site (zkace.io)
sdk/                     # TypeScript SDK (viem, bundler, paymaster)
```

## Technical Specifications

| Parameter | Value |
|-----------|-------|
| Proof system | STARK (Winterfell 0.13, transparent) |
| Field | Goldilocks (p = 2^64 - 2^32 + 1) + quadratic extension |
| Hash functions | Keccak256 (Merkle/Fiat-Shamir), Poseidon2 (commitments), Rescue-Prime for legacy vaults |
| Trace | 18 columns x 8 rows |
| FRI queries | 44 (132-bit soundness) |
| Blowup factor | 8 (LDE domain = 64) |
| Proof-of-work | 20-bit grinding |
| Proof size | ~44 KB |
| Verification gas | ~5.6M |
| Cost per tx | ~$0.20 on Arbitrum/Base |
| Security level | 128-bit post-quantum |
| Public inputs | 17 Goldilocks elements |
| WASM prover | 484 KB, 5-10 seconds in browser |
| Account standard | ERC-4337 (EntryPoint v0.7) |

## Security Properties

- No ECDSA keys anywhere in the authorization path
- No elliptic curves in any component
- No trusted setup (STARK proofs are transparent)
- TxHash recomputed from calldata on-chain (never trusted from prover)
- Domain bound to block.chainid (prevents cross-chain replay)
- Monotonic nonce (prevents same-chain replay)
- Identity rotation with 48-hour timelock
- Emergency pause (can unpause while paused via valid proof)
- REV zeroized in browser memory on session end

## Testing

```bash
# Rust tests
cargo test --workspace

# Solidity tests
forge test

# Total: 130 tests (43 Rust + 87 Solidity), 0 failures
```

## The Verifier

The Solidity STARK verifier performs 19 discrete verification checks:

1. All 17 public inputs validated as Goldilocks field elements
2. Trace commitment (Merkle root) extracted
3. Constraint commitment extracted
4. FRI commitment extracted
5. Fiat-Shamir transcript rebuilt from scratch
6. 36 constraint composition coefficients derived
7. OOD point z drawn from transcript
8. OOD digest recomputed and verified
9. 19 DEEP coefficients derived
10. 20-bit Proof-of-Work verified
11. 44 query positions derived from transcript
12. Query position deduplication enforced
13. 18 transition constraints evaluated at z
14. 18 boundary constraints evaluated at z
15. Constraint composition verified against OOD frame
16. Per-query: Merkle proof verified (trace)
17. Per-query: Merkle proof verified (constraints)
18. Per-query: DEEP composition computed and checked
19. Remainder polynomial evaluation verified

All verification happens in Solidity, on-chain, using the EVM's native KECCAK256 opcode.

## Cost (Arbitrum One)

| Operation | Gas | USD |
|-----------|-----|-----|
| Deploy factory | ~1M | ~$0.02 |
| Create vault | ~735K | ~$0.01 |
| STARK proof verification + tx | ~5.6M | ~$0.20 |

## Why This Approach

The Ethereum Foundation recommends account abstraction (ERC-4337) as the execution-layer migration path for post-quantum wallets. ZK-ACE is the only deployed implementation of that path. Until PQ signature precompiles arrive (~2029), this is the only way for EVM users to get quantum-resistant transaction authorization today.

NIST post-quantum signatures (ML-DSA, SPHINCS+) cannot be efficiently verified in the EVM without native precompiles (500M+ gas in Solidity). STARK-based authorization achieves quantum resistance at ~5.6M gas by using the EVM's native keccak256 opcode for all Merkle verification and Fiat-Shamir challenges.

## License

MIT
