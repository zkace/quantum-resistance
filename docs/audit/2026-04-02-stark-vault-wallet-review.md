# Browser vault & operational path review (STARK)

**Scope:** `vault-app` client, hardcoded chain/contracts, WASM prover surface, ERC-4337 bundler usage, and alignment with `StarkZkAceAccount` / factory. Evidence is drawn from the referenced sources as of this review; no runtime pen-test was performed.

---

## Executive summary

- **Highest severity (operational / correctness):** If the STARK WASM bundle fails to load, `computeIdCom` falls back to a **Keccak-based** packing that is **not** the on-chain **Rescue-Prime** identity commitment. The send path refuses to run without WASM, but the user can still see a **counterfactual address derived from the factory** while WASM is loading—or, if `getVaultAddress` fails, a **documented placeholder address** unrelated to CREATE2. Any confusion about “which address is mine” before WASM is ready is a **funds-loss class** UX risk.
- **High (trust & availability):** The app relies on **Pimlico’s public bundler** (JSON-RPC over HTTPS), **viem’s default Arbitrum HTTP RPC** for reads, and **CoinGecko** for USD prices. There is **no user-configurable** RPC/bundler, **no pinning/SRI** on third-party assets (e.g. Google Fonts), and bundler responses are trusted for gas fields and submission.
- **High (state freshness / retry safety):** After send, the client optimistically increments `session.zkNonce`, then refreshes from chain. If `fetchVaultNonce()` fails, it falls back to **`0n`**, which can poison the next witness nonce and cause subsequent proof attempts to fail or desync until refresh/RPC recovery.
- **Medium (secret handling):** The full **BIP-39 mnemonic string** remains in `VaultSession` for the whole unlocked session (export flow, memory pressure, crash dumps). `beforeunload` zeroizes `rev` and `commitmentSalt` but **does not** clear the mnemonic string. Marketing copy (“no seed phrases touching classical crypto”) is **misleading** relative to PBKDF2-SHA512 over the mnemonic.
- **Medium (product completeness):** **Emergency pause** and **identity rotation** settings entries are **stubbed**: they only show toasts and do **not** build proofs or UserOps. **Receive** uses a **text placeholder**, not a QR code. **`fetchPauseStatus` is never called**, so the UI does not reflect on-chain pause state.

---

## Secret handling and session lifecycle

**Mnemonic generation and import** use `@scure/bip39` (24 words, 256-bit entropy) and `@noble/hashes` PBKDF2-HMAC-SHA512 with **600,000** iterations, salt string `ZK-ACE-REV-v1`, password = UTF-8 mnemonic after **NFKD** normalization. Output: first **32 bytes = REV**, last **32 bytes = commitment salt** (`vault-app/src/main.ts`).

**Session model:** `VaultSession` holds `mnemonic`, `rev`, `commitmentSalt`, `idCom`, `vaultAddress`, deployment flag, and `zkNonce`. The mnemonic is required for export and remains a **live string in JS heap** until logout.

**Clearing secrets:** `handleLogout` zeroizes `rev` and `commitmentSalt`, clears `mnemonic`, and nulls `session`. `beforeunload` only zeroizes `rev` and `commitmentSalt`—**not** the mnemonic string (which can still exist if `session` is non-null in edge timing cases; the handler also does not null `session`).

**Create flow quirk:** Between “Create” and “Confirm”, the mnemonic is stored on the confirm button as `(_mnemonic)`—an unusual pattern that keeps the phrase attached to a DOM-backed object.

**KDF salt:** Fixed application string (not per-user random). Acceptable for domain-separated key stretching from high-entropy mnemonics; auditors may still note absence of optional per-device salt or OS keystore integration.

**Circuit encoding (statement vs 32-byte secrets):** As documented in `docs/audit/2026-04-02-stark-vault-dataflow.md`, the STARK witness uses **only the first 8 bytes** of REV and of commitment salt, reduced mod Goldilocks **P**. Security messaging in the UI (“128-bit post-quantum”, “quantum protected”) should be reconciled with that encoding in any outward-facing claims.

---

## Deployment / account lifecycle

**Factory and verifier addresses** are **hardcoded** for Arbitrum One (`STARK_FACTORY`, `STARK_VERIFIER`, `ENTRYPOINT`, `CHAIN_ID`) in `vault-app/src/main.ts`.

**Counterfactual address:** `getVaultAddress(idCom, 0)` calls `StarkZkAceAccountFactory.getAddress`, matching `create2Salt = keccak256(abi.encodePacked(idCom, salt))` and CREATE2 init code hash in `contracts/src/StarkZkAceAccountFactory.sol`.

**If `getVaultAddress` fails and returns `null`:** The vault substitutes `keccak256(abi.encode(idCom, "ZK-ACE-VAULT"))` truncated to 20 bytes—explicitly labeled in code as a **placeholder** until the factory is “live”. **This is not the account address** users should fund for the real STARK account.

**Deployment via ERC-4337:** `submitUserOp` sets **`factory: null` and `factoryData: null`**. There is **no** client path to `createAccount` through the bundler (no `initCode`). Undeployed accounts cannot authorize sends through this app; the user sees a toast to fund first, but **the app does not implement factory deployment**.

**On-chain account behavior** (pause, rotation, nonce semantics) lives in `contracts/src/StarkZkAceAccount.sol`; the vault only exercises **execute** + STARK proof today.

---

## Bundler, RPC, and third-party trust assumptions

**Bundler:** `https://public.pimlico.io/v2/42161/rpc` — public tier (code comment: no API key, rate limits). Methods used include `pimlico_getUserOperationGasPrice`, `eth_sendUserOperation`, and `eth_getUserOperationReceipt`. The client **trusts** returned gas fields and receipt polling results; failures surface as thrown errors or timeouts (~90s). Operationally, the bundler is also a **censorship / availability / integrity** dependency: the wallet proves over exact `callData`, so any relaying layer must preserve the same bytes the client authorized.

**Read RPC:** `createPublicClient({ chain: arbitrum, transport: http() })` uses viem’s configured default HTTP endpoint(s) for Arbitrum unless overridden by environment (none in-repo in `vault-app`). All balance, nonce, factory, and multicall reads go through this transport.

**UserOp construction:** High `verificationGasLimit` (7M) and `callGasLimit` (200k) are fixed constants; `paymaster` fields are null (user pays).

**Other network dependencies:** `fetchPrices()` calls **CoinGecko**’s public API. `index.html` loads **Google Fonts** from `fonts.googleapis.com` / `fonts.gstatic.com` (third-party connection on every load).

**WASM delivery:** Prover is loaded from **`/wasm/zk_ace_stark_wasm.js`** and **`zk_ace_stark_wasm_bg.wasm`** under the site origin (`loadWasm`). Integrity depends on **how the static host serves these files** (not reviewed here); there is no Subresource Integrity on the module script in `index.html`.

---

## Product-readiness gaps / placeholder behavior

| Area | Evidence |
|------|----------|
| **Pause / rotate** | `handlePause` / `handleRotate` only `showToast(...)`; there is no implemented proof-generation + UserOp path for `setPaused`, `proposeIdentityRotation`, or `confirmIdentityRotation` (`vault-app/src/main.ts`). |
| **Pause status in UI** | `fetchPauseStatus` is **defined but never used**; dashboard does not show paused state. |
| **Receive / QR** | `#qr-display` is a styled box showing the address as text (`index.html` “qr-placeholder”), not a scannable QR. |
| **Send recipient** | Placeholder text mentions **ENS**; validation uses `isAddress` only—**no ENS resolution**. |
| **Marketing vs implementation** | Onboarding/meta claims **“No classical crypto”** / seed phrases not touching classical crypto; implementation runs **PBKDF2-SHA512** on the mnemonic and uses **Keccak** for `txHash` binding—**operationally misleading** for non-expert users. |
| **Local nonce bookkeeping** | After a successful send, `session.zkNonce += 1n` optimistically before `renderDashboard()` re-reads chain state; combined with failed refreshes, retry races, or `fetchVaultNonce()` falling back to `0n` on read error, this can still **desync** from `zkNonce()`. |
| **`userOpHash` binding** | Per `2026-04-02-stark-vault-dataflow.md`, authorization binds to **`keccak256(callData)`**, not the EntryPoint `userOpHash`; bundler must preserve exact `callData` the client proved over. |

---

## Concrete audit conclusions / likely findings

1. **Finding (correctness / UX safety):** Keccak **fallback** for `computeIdCom` when WASM is unavailable produces an **off-protocol** commitment relative to Rescue-Prime used in WASM and expected on-chain; combined with async WASM load, auditors should treat **address display timing** as a critical review item.
2. **Finding (deployment gap):** No **4337 initCode / factory** path in the vault—**operational deployment** of `StarkZkAceAccount` is **out of band** relative to this client.
3. **Finding (stubbed controls):** Settings actions for **pause** and **identity rotation** are **non-functional**; they present as security features but do not perform the on-chain flows that require proofs (`StarkZkAceAccount.setPaused`, `proposeIdentityRotation`, etc.).
4. **Finding (secret lifecycle):** Long-lived **mnemonic string** in memory and incomplete wipe on `beforeunload`; risk acceptable only for a **demo / self-custody prototype**, not a hardened wallet without further mitigations (secure screen, OS storage, shorter-lived secrets, etc.).
5. **Finding (third-party trust):** **Bundler + default RPC + CoinGecko + fonts** create a **centralized availability and privacy** footprint (IP/metadata leakage, censorship, rate limits) with **no** user override in code.
6. **Finding (statement scope):** Align user-facing “quantum” / bit-strength claims with the **8-byte field reduction** and STARK/Keccak assumptions documented in the dataflow note and `ZK-ACE-Guide.md` (guide is explanatory; product UI is more absolute).
7. **Finding (WASM ABI):** `crates/zk-ace-stark-wasm/src/lib.rs` exposes `compute_id_commitment`, `generate_stark_proof`, and `get_proof_public_inputs`; the vault uses the first two. Witness parsing enforces **32-byte** `tx_hash` hex and **≤8-byte** Goldilocks hex for `rev`/`salt`—consistent with the TS `reduceBytesToGoldilocks` helper.

---

*Primary sources: `vault-app/src/main.ts`, `vault-app/index.html`, `vault-app/package.json`, `crates/zk-ace-stark-wasm/src/lib.rs`, `contracts/src/StarkZkAceAccountFactory.sol`, `contracts/src/StarkZkAceAccount.sol`, `docs/audit/2026-04-02-stark-vault-dataflow.md`, `ZK-ACE-Guide.md` (introductory sections).*
