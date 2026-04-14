# STARK Vault — Final Findings, Remediation Priorities, and Residual Risk (2026-04-02)

**Audit slice:** ZK-ACE STARK vault stack (Winterfell prover, Solidity `StarkVerifier` / `StarkZkAceAccount`, `vault-app`, WASM bridge).  
**Inputs:** Scope freeze, dataflow, claim validation, cryptographic review, wallet review, and test-evidence workpapers dated 2026-04-02.  
**Conservative posture:** Items below distinguish **demonstrated defects** from **design assumptions**, **open review questions**, and **operational / UX hazards** where no end-to-end exploit was constructed in this pass.

---

## Executive summary

The STARK verifier and account contracts show **coherent binding** of proofs to `idCom`, `domainTag`, and `keccak256(userOp.callData)` limbs, with **strong test evidence** when Forge is run with paths aligned to `fs_permissions`. Several **high-severity gaps are not “bugs” in the narrow sense** but **assumption-heavy interfaces and product surfaces**: replay semantics lean on **ERC-4337 nonces and STARK soundness** without an explicit on-chain equality between witness `nonce` / `rp_com` and storage `zkNonce`; the vault can **display wrong or placeholder addresses** while WASM is unavailable; and **pause / identity rotation** appear as settings actions but **do not submit the on-chain flows**. **Marketing and NatSpec** in places **overstate** what Solidity enforces. **Tooling**: fixture-backed tests **fail from `contracts/`** as project root due to **path vs allowlist mismatch**—a **reproducibility and CI hazard**, not evidence of incorrect verifier math when fixtures load.

---

## Findings (by severity, high → low)

### STARK-F-001 — High — `idCom` / vault address UX: Keccak fallback and placeholder address

| Field | Detail |
|--------|--------|
| **Severity** | High (operational / user safety; not a demonstrated on-chain theft proof) |
| **Affected components** | `vault-app` (`computeIdCom`, address resolution), user-facing dashboard |
| **Description** | When WASM is not ready, `computeIdCom` uses a **Keccak-based** packing that is **not** equivalent to the **Rescue-Prime** commitment used in the prover and expected on-chain. The send path requires WASM, but users may still see **counterfactual addresses** derived via factory math during loading windows. If factory resolution fails, the app substitutes a **documented placeholder** address that is **not** the CREATE2 account address. |
| **Evidence** | `2026-04-02-stark-vault-wallet-review.md` §Executive summary, §Deployment; `2026-04-02-stark-vault-dataflow.md` §7; `2026-04-02-stark-vault-claim-validation.md` (partially supported `idCom` row). |
| **Impact** | **Wrong-address funding** or user confusion about “which address is mine” → **funds sent to unintended destinations** or loss of confidence in custody. |
| **Recommended remediation** | Block or clearly gate “copy address / receive” until WASM commitment matches on-chain semantics; never show placeholder as fundable without **prominent** non-dismissible warning; unify preview and on-chain `idCom` derivation or disable preview until WASM loads; consider loading WASM before any address display. |

---

### STARK-F-002 — High — Replay binding: `zkNonce`, `rp_com`, and witness `nonce` (open review item)

| Field | Detail |
|--------|--------|
| **Severity** | High (**assumption / composition risk**; **not** closed as a practical exploit in this engagement) |
| **Affected components** | `StarkZkAceAccount`, ERC-4337 `EntryPoint` / bundler behavior, prover public-input layout |
| **Description** | Solidity **does not** recompute `rp_com` from storage (Rescue cost) and **does not** require `witness.nonce == zkNonce` before accepting a proof. After verification, `zkNonce++` runs, but **on-chain enforcement** that the proof’s replay commitment matches the **current** stored counter is **indirect** (via STARK statement + public inputs + wallet honesty), not a simple storage equality check. **`userOpHash` is intentionally ignored**; binding is **`keccak256(callData)`**. The **concrete open shape** called out in workpapers: reuse of the **same** `signature` blob with a **fresh** EntryPoint nonce and **identical** `callData`—**treat as requiring further analysis**, not as “safe because `zkNonce` increments.” |
| **Evidence** | `2026-04-02-stark-vault-claim-validation.md` replay rows and §Replay summary; `2026-04-02-stark-vault-dataflow.md` §Audit-relevant boundaries (items 4–5); `2026-04-02-stark-vault-crypto-review.md` §Interface assumption / conclusions item 3. |
| **Impact** | If composition assumptions fail, **authorization or replay properties** could diverge from stakeholder expectations; **collateral** that claims “`zkNonce` alone prevents reuse” is **stronger than the EVM checks** documented. |
| **Recommended remediation** | **Threat-model** explicitly: dependence on **EntryPoint nonce**, **calldata integrity**, **bundler** behavior, and **honest wallet nonce**; add **on-chain** check `decodedWitnessNonce == zkNonce` if a **cheap encoding** of witness nonce can be passed and trusted, or otherwise **document and test** the composed replay story; align **NatSpec** (Step 9) with actual checks. |

---

### STARK-F-003 — High — Verifier transcript coupling and Winterfell / `ProofOptions` fragility

| Field | Detail |
|--------|--------|
| **Severity** | High (**deployment / maintenance**; mis-upgrade causes **verify failure** or **unintended transcript drift**, not a per-proof break under a pinned deployment) |
| **Affected components** | `StarkVerifier.sol`, `crates/zk-ace-stark` (prover options, Winterfell version), release process |
| **Description** | Fiat-Shamir seed material **hard-codes** Winterfell `AirContext` / option bytes. **No runtime self-check** that Rust and Solidity remain byte-aligned. Bumping Winterfell, trace shape, queries, blowup, or grinding **without** coordinated Solidity updates is **release-critical** risk. |
| **Evidence** | `2026-04-02-stark-vault-crypto-review.md` §Transcript, §Risks, §Concrete conclusions item 2; `2026-04-02-stark-vault-claim-validation.md` (Fiat-Shamir partially supported). |
| **Impact** | **Bricked verification** or **silent security drift** after dependency or parameter changes. |
| **Recommended remediation** | **Lock** Winterfell and proof-option versions; **regression tests** that fail on serialization drift; single source of truth or codegen for seed chunks; run **differential** / fixture tests on every release. |

---

### STARK-F-004 — Medium — Pause and identity rotation presented in UI without on-chain implementation

| Field | Detail |
|--------|--------|
| **Severity** | Medium (security **UX integrity** / false operational assurance) |
| **Affected components** | `vault-app` settings flows; contrast with `StarkZkAceAccount` pause / rotation entrypoints |
| **Description** | **Emergency pause** and **identity rotation** handlers **only show toasts**; they do **not** build proofs or UserOps for `setPaused`, `proposeIdentityRotation`, or `confirmIdentityRotation`. **`fetchPauseStatus` is never called**, so the dashboard does not reflect on-chain pause state. |
| **Evidence** | `2026-04-02-stark-vault-wallet-review.md` §Executive summary, §Product-readiness gaps. |
| **Impact** | Users may believe they **paused** or **initiated rotation** when **no** such transaction occurred—**availability and incident-response** expectations diverge from reality. |
| **Recommended remediation** | **Remove or clearly label** as “coming soon”; or **implement** full proof + UserOp paths consistent with account ABI; surface **live pause** state from chain. |

---

### STARK-F-005 — Medium — No in-app ERC-4337 factory / `initCode` deployment path

| Field | Detail |
|--------|--------|
| **Severity** | Medium (operational gap for self-serve deployment) |
| **Affected components** | `vault-app` UserOp construction (`factory` / `factoryData` / `initCode` absent) |
| **Description** | `submitUserOp` uses **`factory: null`** and **`factoryData: null`**. Undeployed accounts **cannot** be created through this client; deployment is **out of band** relative to the vault UX. |
| **Evidence** | `2026-04-02-stark-vault-wallet-review.md` §Deployment / account lifecycle. |
| **Impact** | **Friction and support burden**; risk of users **funding wrong addresses** or assuming the app deployed the account when it did not. |
| **Recommended remediation** | Add **4337-compliant** `initCode` path using `StarkZkAceAccountFactory` (or document **mandatory** external deployment playbook with verification steps). |

---

### STARK-F-006 — Medium — Session mnemonic lifetime, incomplete unload wiping, optimistic `zkNonce`, RPC read failure behavior

| Field | Detail |
|--------|--------|
| **Severity** | Medium (operational security / robustness; prototype-grade handling) |
| **Affected components** | `VaultSession` lifecycle, `beforeunload`, nonce refresh in `vault-app` |
| **Description** | **Full BIP-39 mnemonic** remains in memory for the unlocked session; **`beforeunload`** zeroizes `rev` and `commitmentSalt` but **not** the mnemonic string. After send, the client **optimistically** increments `session.zkNonce`; if **`fetchVaultNonce()` fails**, fallback to **`0n`** can **poison** the next witness nonce and **desync** until recovery. |
| **Evidence** | `2026-04-02-stark-vault-wallet-review.md` §Executive summary, §Secret handling, §Product-readiness gaps. |
| **Impact** | Increased **exposure window** for secrets on compromised or instrumented devices; **failed or confusing** signing after RPC errors. |
| **Recommended remediation** | Shorten mnemonic lifetime; extend wiping to **mnemonic** on unload where feasible; **avoid** defaulting nonce to **0** on error—**retry**, **block send**, or **preserve last known good**; reconcile marketing (“no seed phrases touching classical crypto”) with **PBKDF2 over mnemonic** and **Keccak** binding in pipeline. |

---

### STARK-F-007 — Medium — Public and guide claims overstate what code and tests guarantee

| Field | Detail |
|--------|--------|
| **Severity** | Medium (stakeholder / user **mis-risking**; compliance and communications) |
| **Affected components** | `ZK-ACE-Guide.md`, acquisition memo, product UI copy; contrast with `StarkZkAceAccount`, dataflow |
| **Description** | Examples: replay narrative tied **only** to `zkNonce++` **oversimplifies** enforcement (**F-002**); **“no ECDSA anywhere”** for the **product** is **not** established by the STARK account path alone (bundler, RPC TLS, EOAs, etc.); guide **REV “64-bit”** table vs **8-byte** field reduction is **unsupported** by current witness encoding; economics (**$/tx**, latency) are **environment-dependent**. |
| **Evidence** | `2026-04-02-stark-vault-claim-validation.md` §B; `2026-04-02-stark-vault-scope-freeze.md` §5.B; wallet review §Marketing vs implementation. |
| **Impact** | **Overconfidence** in quantum posture, replay, and operational costs. |
| **Recommended remediation** | **Rewrite** claims to track **exact bindings** (`callData` hash, `domainTag`, 4337 nonce, STARK assumptions); separate **implementation lemmas** from **market** assertions; fix guide tables to match **`main.ts` / prover** encoding. |

---

### STARK-F-008 — Low — Forge fixture path vs `fs_permissions` / project root mismatch

| Field | Detail |
|--------|--------|
| **Severity** | Low (engineering / audit **reproducibility**; **not** a verifier correctness finding when fixtures load) |
| **Affected components** | Repo-root `foundry.toml` vs `contracts/foundry.toml`, `StarkE2E.t.sol`, `StarkVerifierV2.t.sol` |
| **Description** | Fixture-backed tests **pass** from **repository root** with allowlisted `./contracts/test/fixtures` but **fail** when Forge’s project root is **`contracts/`**, because tests still request `contracts/test/fixtures/...` while the nested config allowlists `./test/fixtures`. |
| **Evidence** | `2026-04-02-stark-vault-test-evidence.md`; `2026-04-02-stark-vault-scope-freeze.md` normative invocation note. |
| **Impact** | **CI confusion**, failed local repro, false impression that STARK tests “don’t pass.” |
| **Recommended remediation** | **Unify** paths with `vm.projectRoot()` or align **hardcoded paths** with each `foundry.toml`; document **single canonical** `forge test` invocation in README/CI. |

---

### STARK-F-009 — Low (informational) — AIR statement scope and 8-byte witness encoding

| Field | Detail |
|--------|--------|
| **Severity** | Low / Informational (**design clarity**, affects **messaging** more than a single bug) |
| **Affected components** | `crates/zk-ace-stark/src/air.rs`, witness encoding, UI “bit strength” copy |
| **Description** | The trace enforces **constancy** of columns with **boundary** public inputs; **identity digests** are computed **off-chain** and bound via **`idCom` storage check** and Rescue assumptions—not re-derived inside constraints. Only **eight bytes** of REV and of commitment salt (reduced mod **P**) enter the STARK witness field elements. |
| **Evidence** | `2026-04-02-stark-vault-crypto-review.md` §AIR; `2026-04-02-stark-vault-dataflow.md` §2; claim-validation matrix caveat rows. |
| **Impact** | **Misaligned security narrative** if stakeholders assume full 32-byte preimage strength **inside** the algebraic proof. |
| **Recommended remediation** | Document **statement shape** precisely for auditors and users; align **marketing** with **encoding** limits. |

---

## Remediation priorities

### Immediate (before widening production exposure)

- **F-001:** Eliminate or hard-gate misleading **address preview**; **placeholder** must not be copyable as a normal receive address.
- **F-004:** **Remove, disable, or relabel** non-functional **pause / rotate** controls; or implement **end-to-end** flows before presenting them as security actions.
- **F-002 / F-007:** Publish an **accurate** replay and binding narrative; **fix NatSpec** where it implies on-chain `rp_com` recomputation that does not exist.
- **F-008:** Fix **Forge paths / permissions** or **document** the single supported test invocation so CI and auditors do not draw false negatives.

### Near-term (next release train)

- **F-003:** **Dependency locks** and **transcript drift** regression tests; release checklist for any Winterfell / AIR / query / blowup change.
- **F-005:** **Factory + `initCode`** path (or certified external deployment) so users can onboard without manual bytecode steps.
- **F-006:** **Nonce refresh** error handling; **mnemonic** lifecycle hardening for any non-demo deployment.
- **F-002:** Close the **open composition question** with either **additional on-chain checks** (if feasible) or **formalized** assumptions + **negative tests** under adversarial bundler models (engagement-dependent).

### Follow-up (continuous assurance)

- **Bytecode ↔ source** verification for deployed Arbitrum addresses; **immutable git baseline** (tags/tarball hashes) per scope-freeze caveats.
- **Third-party surface** review: bundler, default RPC, static asset integrity (**SRI**), optional user-configurable endpoints (wallet review).
- **Broader** differential proving, extended adversarial vectors, and **economic** / MEV analysis—not covered by current test evidence doc.

---

## Residual risk statement

After this review slice, **residual risk remains material** for any “production wallet” interpretation: **(1)** replay and authorization semantics are **compositionally** dependent on **ERC-4337**, **bundler behavior**, and **correct client nonce usage**, with an **explicit on-chain gap** between **`rp_com` / witness nonce** and **storage `zkNonce`** that was **not** reduced to a demonstrated exploit here but **must** be **assumed or closed** explicitly; **(2)** the **vault client** can still mislead users on **addresses**, **pause/rotate**, and **cryptographic story** relative to the **PBKDF2 / Keccak / 8-byte witness** reality; **(3)** **verifier correctness** is **well exercised by tests only under stated invocation assumptions**, while **soundness margins** and **paper ↔ implementation** parity are **not** formally proven in this pass; **(4)** **deployed bytecode** is **not** proven equivalent to this tree without further attestation. The stack may be **appropriate for controlled pilots** with **disclosure of limitations**; **broader claims** should be **treated as unwarranted** until **remediation** and **external verification** close the above gaps.

---

*End of final findings (Task 7).*
