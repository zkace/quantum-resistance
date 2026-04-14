# ZK-ACE: Quantum-Resistant EVM Wallets

Zero-knowledge authorization layer replacing ECDSA signatures with STARK proofs. No private keys — vaults are controlled by a 256-bit Root Entropy Value (REV) proven via zero-knowledge. No elliptic curves. No pairings. No trusted setup. Post-quantum secure.

Based on [ZK-ACE: Identity-Centric Zero-Knowledge Authorization for Post-Quantum Blockchain Systems](https://arxiv.org/abs/2603.07974) (Wang, 2026).

## Live on Arbitrum One

| Contract | Address | Type |
|---|---|---|
| StarkVerifier | `0xE1B8750ED6Fd835e7D27a1A4F08532BDbFb9F6d4` | Post-Quantum |
| STARK Account Factory | `0x5c7D026978Fa2D159dCC0Bb87F25DbaBfE872614` | CREATE2 |
| Groth16 Verifier | `0xfA56E270c36849072F41e8D44884fcae2CB9c70c` | Classical |

## Quick Start

```bash
# Generate a quantum-resistant identity
cargo run --release -p zk-ace-prover --bin cli -- new-identity --chain-id 42161

# View your identity (REV stays hidden)
cargo run --release -p zk-ace-prover --bin cli -- show

# Generate a proof for a transaction
cargo run --release -p zk-ace-prover --bin cli -- prove --calldata 0x...

# System info
cargo run --release -p zk-ace-prover --bin cli -- info
```

## Architecture

```
User's REV (256-bit secret, never leaves device)
    │
    ├──→ Rescue-Prime(REV, salt, domain) = IDcom ← stored on-chain (32 bytes)
    │
    ├──→ STARK Proof (Winterfell, Keccak256)    ← proves knowledge of REV
    │       │                                      no elliptic curves
    │       │                                      no trusted setup
    │       └──→ StarkVerifier contract          ← Full STARK verification (~5.6M gas)
    │               │
    │               └──→ StarkZkAceAccount       ← ERC-4337 smart wallet
    │                       │
    │                       └──→ execute()       ← any EVM transaction
    │
    └──→ Factory.createAccount(IDcom)            ← deterministic CREATE2 address
```

## Project Structure

```
crates/
  zk-ace-circuit/    # Arkworks R1CS circuit (Groth16 path, 2,409 constraints)
  zk-ace-prover/     # Groth16 prove/verify, Solidity codegen, CLI tool
  zk-ace-didp/       # Mnemonic-derived identity helpers
  zk-ace-stark/      # STARK prover/verifier (Winterfell, Keccak256, post-quantum)
  zk-ace-wasm/       # Browser WASM prover (573 KB)

contracts/
  src/
    StarkVerifier.sol        # STARK verifier (Fiat-Shamir + Merkle + PoW)
    StarkZkAceAccount.sol    # ERC-4337 account using STARK proofs
    ZkAceAccount.sol         # ERC-4337 account using Groth16 proofs
    ZkAceVerifier.sol        # Groth16 verifier (BN254 pairings)
    ZkAceAccountFactory.sol  # CREATE2 factory for deterministic addresses
    GoldilocksField.sol      # Goldilocks field arithmetic + quadratic extension

wallet/              # Browser wallet UI (Vite + WASM)
sdk/                 # TypeScript SDK (viem, bundler, paymaster)
website/             # Marketing site (zkace.vercel.app)
```

## Two Verification Paths

| | STARK (Post-Quantum) | Groth16 (Classical) |
|---|---|---|
| **Quantum-resistant** | Yes | No (BN254 pairings) |
| **Trusted setup** | None | Required |
| **Proof size** | 4.3 KB | 256 bytes |
| **Verify gas** | ~5.3M | ~270k |
| **Cost (Arbitrum)** | ~$0.20 | ~$0.01 |
| **Hash / commitment path** | Rescue-Prime commitments + Keccak256 transcript | Poseidon (α=17) |
| **Field** | Goldilocks + QuadExt (128-bit) | BN254 (254-bit) |
| **Soundness** | 132-bit | Knowledge soundness |

## Security

- **No ECDSA keys** anywhere in the authorization path
- **No elliptic curves** in the STARK path — only hash functions
- **No trusted setup** — STARK proofs are transparent
- **Replay resistance**: callData binding + monotonic zkNonce + ERC-4337 nonce semantics
- **Domain separation**: Proof bound to `block.chainid`
- **Identity rotation**: 2-step timelock (propose → 2 days → confirm)
- **Emergency pause**: Block transfers while allowing proof-backed unpause
- **128-bit post-quantum security**: Quadratic extension, 44 queries, 20-bit grinding

See [AUDIT_REPORT_V2.md](AUDIT_REPORT_V2.md) for the full security audit.

## Testing

```bash
# Rust tests (32)
cargo test --workspace

# Solidity tests (run from repo root so fixture-backed STARK suites resolve consistently)
forge test

# Total: 105 tests, 0 failures
```

## Cost (Arbitrum One)

| Operation | Gas | USD |
|---|---|---|
| Deploy factory | ~800k | $0.03 |
| Create vault (via factory) | ~400k | $0.01 |
| STARK proof verification | ~5.3M | $0.11 |
| Groth16 proof verification | ~270k | $0.01 |

## Website

[zkace.vercel.app](https://zkace.vercel.app)

## License

MIT
