# ZK-ACE Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ZK-ACE safe for real funds: proper trusted setup, account factory for anyone to deploy vaults, and a browser wallet UI.

**Architecture:** Three independent subsystems: (1) MPC ceremony tooling + mainnet redeploy with safe keys, (2) CREATE2 account factory + CLI for onboarding, (3) Browser wallet using the existing WASM prover. Each subsystem is independently testable and deployable.

**Tech Stack:** Rust/arkworks (ceremony), Solidity/Foundry (factory), TypeScript/Vite/WASM (wallet)

---

## Subsystem 1: MPC Trusted Setup + Redeploy

The deterministic seed `0xDEAD_BEEF_CAFE_BABE` means anyone can forge proofs. We need a multi-party ceremony where N participants each contribute randomness and destroy their share. If even 1 participant is honest, the toxic waste is unrecoverable.

### Task 1: Production setup binary with entropy enforcement

**Files:**
- Modify: `crates/zk-ace-prover/src/bin/setup.rs`
- Modify: `crates/zk-ace-prover/src/setup.rs`

- [ ] **Step 1: Add `--production` flag to setup binary**

Replace the setup binary to require either `--dev` (deterministic, refused on mainnet) or `--production` (OS entropy from `/dev/urandom`):

```rust
// setup.rs main():
let args: Vec<String> = std::env::args().collect();
let mode = args.get(1).map(|s| s.as_str()).unwrap_or("--dev");

let mut rng = match mode {
    "--production" => {
        println!("PRODUCTION MODE: Using OS entropy (OsRng)");
        // OsRng pulls from /dev/urandom — cannot be reconstructed
        None // signal to use OsRng below
    }
    "--dev" => {
        println!("DEV MODE: Deterministic seed (UNSAFE for real funds)");
        Some(ChaCha20Rng::seed_from_u64(0xDEAD_BEEF_CAFE_BABEu64))
    }
    _ => panic!("Usage: setup --dev | --production"),
};
```

- [ ] **Step 2: Embed ceremony metadata in the serialized keys**

Add a `CeremonyMetadata` struct serialized alongside the keys:

```rust
#[derive(Serialize, Deserialize)]
struct CeremonyMetadata {
    mode: String,           // "dev" or "production"
    timestamp: u64,
    participants: Vec<String>,
    chain_restriction: Option<u64>, // None = any chain, Some(id) = only that chain
}
```

- [ ] **Step 3: Add contribution combining for MPC**

For a simple N-of-N ceremony, each participant runs:
```
setup --contribute --input prev_pk.bin --output next_pk.bin
```
This multiplies the existing toxic waste by fresh randomness — sequential composition. If any participant's randomness is unknown, the combined toxic waste is unknown.

- [ ] **Step 4: Run the ceremony**

```bash
# Participant 1 (initiator):
cargo run -p zk-ace-prover --release --bin setup -- --production --output phase1.bin

# Participant 2 (adds their entropy):
cargo run -p zk-ace-prover --release --bin setup -- --contribute --input phase1.bin --output phase2.bin

# Final: export verifier
cargo run -p zk-ace-prover --release --bin setup -- --finalize --input phase2.bin \
  --output-pk artifacts/pk.bin --output-vk artifacts/vk.bin --output-sol artifacts/ZkAceVerifier.sol
```

- [ ] **Step 5: Regenerate fixtures and redeploy**

```bash
cargo run -p zk-ace-prover --bin gen_fixture -- 42161
# Copy new ZkAceVerifier.sol, deploy to Arbitrum, run E2E
```

---

## Subsystem 2: Account Factory + CLI Onboarding

### Task 2: ZkAceAccountFactory contract (CREATE2)

**Files:**
- Create: `contracts/src/ZkAceAccountFactory.sol`
- Create: `contracts/test/ZkAceAccountFactory.t.sol`

- [ ] **Step 1: Write the factory contract**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./ZkAceAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";

contract ZkAceAccountFactory {
    IEntryPoint public immutable entryPoint;
    IZkAceVerifier public immutable verifier;

    event AccountCreated(address indexed account, bytes32 indexed idCom);

    constructor(IEntryPoint entryPoint_, IZkAceVerifier verifier_) {
        entryPoint = entryPoint_;
        verifier = verifier_;
    }

    /// @notice Deploy a new ZK-ACE vault for the given identity commitment.
    ///         Uses CREATE2 so the address is deterministic from idCom alone.
    function createAccount(bytes32 idCom, uint256 salt) external returns (ZkAceAccount) {
        bytes32 create2Salt = keccak256(abi.encodePacked(idCom, salt));
        ZkAceAccount account = new ZkAceAccount{salt: create2Salt}(
            entryPoint, verifier, idCom
        );
        emit AccountCreated(address(account), idCom);
        return account;
    }

    /// @notice Compute the counterfactual address without deploying.
    function getAddress(bytes32 idCom, uint256 salt) external view returns (address) {
        bytes32 create2Salt = keccak256(abi.encodePacked(idCom, salt));
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            create2Salt,
            keccak256(abi.encodePacked(
                type(ZkAceAccount).creationCode,
                abi.encode(entryPoint, verifier, idCom)
            ))
        ));
        return address(uint160(uint256(hash)));
    }
}
```

- [ ] **Step 2: Write Forge tests**

Test: create account, verify address matches `getAddress`, verify second create with same salt reverts, verify account state is correct.

- [ ] **Step 3: Deploy factory to Arbitrum**

```bash
forge create contracts/src/ZkAceAccountFactory.sol:ZkAceAccountFactory \
  --rpc-url https://arb1.arbitrum.io/rpc --private-key $KEY --broadcast \
  --constructor-args $ENTRY_POINT $VERIFIER
```

### Task 3: CLI onboarding tool

**Files:**
- Create: `crates/zk-ace-prover/src/bin/cli.rs`

- [ ] **Step 1: Write CLI with subcommands**

```
zkace new-identity         # Generate REV + salt, compute IDcom, print address
zkace deploy --chain-id N  # Deploy vault via factory
zkace prove --calldata 0x  # Generate proof for a transaction
zkace send --to ADDR --value 0.01 --chain-id N  # Full flow: prove + submit UserOp
```

Each command uses the existing Rust crates (`zk-ace-circuit`, `zk-ace-prover`, `zk-ace-didp`).

- [ ] **Step 2: `new-identity` command**

Generates a random REV (32 bytes from OsRng), random salt, computes `IDcom = Poseidon(REV, salt, chainId)`, computes the counterfactual address via the factory, and outputs everything:

```
Your quantum-resistant identity:
  REV (SECRET — never share): 0xabc...
  Salt: 0xdef...
  Identity Commitment (IDcom): 0x123...
  Vault Address (Arbitrum): 0x456...

Save your REV securely. It cannot be recovered.
```

- [ ] **Step 3: `prove` and `send` commands**

`prove` generates a Groth16 proof for given calldata using REV from stdin or `--rev` flag.
`send` generates the proof, wraps in a UserOp, and submits to a bundler endpoint.

---

## Subsystem 3: Browser Wallet Frontend

### Task 4: Build WASM package

**Files:**
- Modify: `crates/zk-ace-wasm/src/lib.rs`

- [ ] **Step 1: Build WASM**

```bash
wasm-pack build crates/zk-ace-wasm --target web --out-dir ../../wallet/src/wasm-pkg
```

- [ ] **Step 2: Verify WASM size and exports**

The WASM module should export: `generate_proof`, `compute_id_commitment`, `compute_target`.
Expected size: ~2-5 MB (arkworks BN254 math is heavy in WASM).

### Task 5: Wallet web app

**Files:**
- Create: `wallet/index.html`
- Create: `wallet/src/main.ts`
- Create: `wallet/src/wallet.ts`
- Create: `wallet/src/ui.ts`
- Create: `wallet/vite.config.ts`
- Create: `wallet/package.json`

- [ ] **Step 1: Set up Vite project**

```bash
cd wallet && npm init -y
npm install vite viem typescript @types/node
```

- [ ] **Step 2: Create wallet core (`wallet.ts`)**

```typescript
import init, { generate_proof, compute_id_commitment } from './wasm-pkg';

export class ZkAceWallet {
  private rev: string;          // hex, never leaves this object
  private salt: string;
  private chainId: bigint;
  private pkBytes: Uint8Array;  // proving key
  private nonce: number = 0;

  static async create(chainId: bigint, pkUrl: string): Promise<ZkAceWallet> {
    await init();
    const pk = await fetch(pkUrl).then(r => r.arrayBuffer());
    const rev = crypto.getRandomValues(new Uint8Array(32));
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return new ZkAceWallet(toHex(rev), toHex(salt), chainId, new Uint8Array(pk));
  }

  get idCom(): string {
    return compute_id_commitment(this.rev, this.salt, Number(this.chainId));
  }

  async authorize(callData: Hex): Promise<{ proof: string; publicInputs: string }> {
    const txHash = keccak256(callData);
    const result = generate_proof(JSON.stringify({
      rev: this.rev, salt: this.salt,
      alg_id: 1, domain: Number(this.chainId), index: 0,
      nonce: this.nonce++, tx_hash: txHash,
    }), this.pkBytes);
    return result;
  }
}
```

- [ ] **Step 3: Create minimal UI (`ui.ts`)**

Single-page app with:
- "Create Wallet" button — generates identity, shows IDcom + vault address
- "Send ETH" form — recipient, amount, generates proof, submits
- Balance display — reads from RPC
- Transaction history

- [ ] **Step 4: Test in browser**

```bash
cd wallet && npx vite dev
# Open http://localhost:5173
# Click "Create Wallet" → see IDcom
# Fund the vault address with testnet ETH
# Send 0.001 ETH → verify proof generates and transaction submits
```

---

## Execution Order

1. **Task 2 (Factory)** — can be done now, no dependency on ceremony
2. **Task 3 (CLI)** — can be done in parallel with factory
3. **Task 1 (MPC Ceremony)** — requires 2+ participants, produces new keys
4. **Task 4 (WASM build)** — after ceremony (uses new proving key)
5. **Task 5 (Wallet UI)** — after WASM build

Tasks 2+3 are independent. Task 1 gates Tasks 4+5 (the wallet needs the production proving key).

---

## Verification Checklist

After all tasks:
- [ ] `cargo test --workspace` — all Rust tests pass
- [ ] `forge test` — all local Solidity tests pass
- [ ] `forge test --fork-url https://arb1.arbitrum.io/rpc --match-contract E2E_ArbitrumMainnet` — mainnet fork passes
- [ ] Factory deployed, `createAccount` works
- [ ] CLI `new-identity` produces valid IDcom
- [ ] CLI `prove` generates valid proof
- [ ] Wallet UI loads, generates proof in browser, shows balance
- [ ] No deterministic seed in any production artifact
