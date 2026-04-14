# ZK-ACE Vault — Product Design Spec

## Overview

A production-grade web application for quantum-resistant EVM wallets. Users create vaults protected by STARK proofs — no ECDSA keys, no seed phrases that touch classical crypto. The identity secret (REV) is derived from a BIP-39 mnemonic via quantum-safe symmetric KDFs and never leaves the browser.

**Target users:** Crypto-native individuals, DAO treasuries, institutional holders on Arbitrum One.
**Form factor:** Single-page web app (no install, no extension, no backend).
**Assets:** ETH, any ERC-20, NFTs (ERC-721/1155).
**Chain:** Arbitrum One (only).
**Cost:** ~$0.20 per authorized transaction.

---

## Architecture

```
Browser App (Vite + TypeScript + viem)
    ├── WASM Prover (576 KB, Winterfell STARK)
    ├── Mnemonic → REV derivation (PBKDF2-SHA512, quantum-safe)
    ├── Proof generation (~5-10s in browser)
    └── ERC-4337 UserOp submission via bundler API
         └── Arbitrum One RPC
              ├── StarkZkAceAccount (on-chain vault)
              ├── StarkVerifier (on-chain proof verification)
              └── StarkZkAceAccountFactory (CREATE2 deployment)
```

**No backend server.** All computation is client-side. RPC calls go directly to Arbitrum. The REV exists only in browser memory during the active session.

---

## Key Management

### Mnemonic → REV Derivation

```
24-word BIP-39 mnemonic (256 bits entropy)
    → PBKDF2-HMAC-SHA512(mnemonic, salt="ZK-ACE-REV-v1", iterations=600000)
    → first 32 bytes = REV
    → Rescue-Prime-Hash(REV, salt, chainId) = IDcom (4 Goldilocks elements)
    → Factory.getAddress(IDcom) = vault address (deterministic)
```

**Why this is quantum-safe:** BIP-39 mnemonic generation uses `crypto.getRandomValues()` (OS CSPRNG). PBKDF2-HMAC-SHA512 is a symmetric KDF — Grover halves the security to 128 bits, which is our target. No elliptic curves anywhere in the key derivation chain.

### Session Management

- REV is derived when user enters mnemonic and held in a JavaScript variable (not localStorage)
- REV is zeroized (overwritten with zeros) when the session ends (tab close, explicit logout)
- Mnemonic is never stored — user re-enters it each session (or can opt into encrypted localStorage with a session password)

---

## Screens

### 1. Landing / Onboarding

Two paths:
- **"Create New Vault"** → generate mnemonic → show 24 words → verify user wrote them down → derive REV → compute vault address → show address + QR → offer to deploy (costs ~$0.01 gas)
- **"Import Vault"** → enter existing 24-word mnemonic → derive REV → compute vault address → auto-detect if deployed

### 2. Dashboard

- **Header:** Vault address (truncated, copyable) + network badge ("Arbitrum One") + "Quantum-Protected" indicator
- **Balance:** Total USD value across all assets
- **Asset list:** ETH + detected ERC-20 tokens + NFTs, each with balance and USD value
- **Recent activity:** Last 5-10 transactions (from on-chain events)
- **Quick actions:** Send, Receive, Settings

### 3. Send

- Select asset (dropdown: ETH, tokens, NFTs)
- Recipient address input (with ENS resolution if available)
- Amount input (with "Max" button)
- Gas estimate display
- **"Authorize with Quantum Proof"** button
- Progress states:
  1. "Generating zero-knowledge proof..." (5-10 seconds, animated)
  2. "Submitting to Arbitrum..." (1-3 seconds)
  3. "Confirmed ✓" (with tx hash link to Arbiscan)

### 4. Receive

- Vault address (full, copyable)
- QR code
- "Send any token to this address on Arbitrum One"

### 5. Settings

- **Identity Rotation:** "Propose New Identity" → 48-hour timelock → "Confirm Rotation"
- **Emergency Pause:** Toggle on/off (requires proof)
- **Export Mnemonic:** Behind double confirmation
- **Session:** Lock / Logout (zeroizes REV)
- **Advanced:** Vault nonce, contract addresses, proof system info

---

## Technical Implementation

### Stack

- **Framework:** Vite + TypeScript (no React — vanilla TS with minimal DOM manipulation for speed)
- **Chain interaction:** viem (Arbitrum transport)
- **WASM prover:** Compiled from `zk-ace-wasm` crate (576 KB)
- **Mnemonic:** `@scure/bip39` (audited, lightweight BIP-39 implementation)
- **KDF:** `@noble/hashes` (audited PBKDF2-SHA512)
- **Bundler:** Pimlico SDK (`permissionless` package) for ERC-4337 UserOp submission
- **Token list:** Arbitrum token list (JSON, cached)
- **NFTs:** On-chain ERC-721/1155 balance queries

### Proof Generation Flow

```typescript
async function authorizeTransaction(calldata: Hex): Promise<UserOpHash> {
  // 1. Compute tx_hash (split keccak256 into 4 Goldilocks elements)
  const txHash = splitKeccakToGoldilocks(keccak256(calldata));

  // 2. Build witness
  const witness = { rev, salt, algId: 1, domain: 42161, index: 0, nonce: zkNonce, txHash };

  // 3. Generate STARK proof via WASM (~5-10s)
  const proof = await wasmProver.generateProof(witness, provingKeyBytes);

  // 4. Build UserOperation
  const userOp = buildUserOp(vaultAddress, calldata, proof);

  // 5. Submit via bundler
  return await bundler.sendUserOperation(userOp);
}
```

### Token Detection

```typescript
// On dashboard load:
// 1. Fetch ETH balance
// 2. Fetch known token balances from Arbitrum token list (~200 tokens)
// 3. Filter to non-zero balances
// 4. For NFTs: query Transfer events to/from vault address
```

### Deployment

- **Hosting:** Vercel (static site, no server)
- **Domain:** vault.zkace.com (or similar)
- **WASM:** Loaded on first proof generation, cached by browser
- **Proving key:** ~500 KB, fetched once and cached in IndexedDB

---

## Security Considerations

1. **REV never persists** — derived on session start, zeroized on session end
2. **No server** — no backend to hack, no API keys to leak
3. **Mnemonic backup** — user's responsibility, clearly communicated
4. **WASM prover** — proof generation happens entirely in browser, no network calls
5. **Origin isolation** — WASM runs in same origin, no cross-origin data leaks
6. **CSP headers** — strict Content-Security-Policy to prevent XSS

---

## MVP Scope

### In Scope
- Create/import vault via mnemonic
- Dashboard with ETH + ERC-20 balances
- Send ETH and ERC-20 tokens
- Receive (address + QR)
- Proof generation in browser via WASM
- Transaction submission via Pimlico bundler
- Settings (identity rotation, pause, export)

### Out of Scope (v2)
- NFT display and transfer (contracts support it, UI deferred)
- WalletConnect integration (connect to DeFi apps)
- Multi-chain support (Base, Optimism)
- Hardware wallet integration
- Social recovery / guardians
- Mobile app
