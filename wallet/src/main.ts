import {
  createPublicClient,
  http,
  formatEther,
  parseEther,
  encodeFunctionData,
  keccak256,
  toHex,
  type Address,
  type Hex,
} from 'viem';
import { arbitrum } from 'viem/chains';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FACTORY: Address = '0xf50Fa247F5C0FCB5524f7dcf3A709F3345dfeF0d';
const STARK_VERIFIER: Address = '0xE1B8750ED6Fd835e7D27a1A4F08532BDbFb9F6d4';
const GROTH16_VERIFIER: Address = '0xfA56E270c36849072F41e8D44884fcae2CB9c70c';
const ENTRYPOINT: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'; // v0.7

/** BN254 scalar field modulus */
const BN254_FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const STORAGE_KEY = 'zkace_wallet';

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const client = createPublicClient({
  chain: arbitrum,
  transport: http(),
});

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

interface WalletState {
  rev: string;         // hex, 32 bytes
  salt: string;        // hex, 32 bytes
  idCom: string;       // hex, 32 bytes
  vaultAddress: string;
}

let state: WalletState | null = null;
let activityLog: string[] = [];

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function show(id: string) {
  $(id).style.display = '';
}

function hide(id: string) {
  $(id).style.display = 'none';
}

function setStatus(msg: string, isError = false) {
  const el = $('status-msg');
  el.textContent = msg;
  el.style.color = isError ? '#ff5252' : '#69f0ae';
}

function addActivity(msg: string) {
  const time = new Date().toLocaleTimeString();
  activityLog.unshift(`[${time}] ${msg}`);
  if (activityLog.length > 50) activityLog.pop();
  renderActivity();
}

function renderActivity() {
  const el = $('activity-list');
  if (activityLog.length === 0) {
    el.innerHTML = '<div class="empty">No activity yet.</div>';
    return;
  }
  el.innerHTML = activityLog
    .map((a) => `<div class="activity-row">${escapeHtml(a)}</div>`)
    .join('');
}

function escapeHtml(s: string): string {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function truncateAddr(a: string): string {
  if (a.length <= 14) return a;
  return a.slice(0, 8) + '...' + a.slice(-6);
}

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function randomBytes32(): Hex {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

// WASM module for real Poseidon hashing and proof generation
let wasmReady = false;
let wasmModule: any = null;
let pkBytes: Uint8Array | null = null;

async function initWasm() {
  try {
    const wasm = await import('./wasm-pkg/zk_ace_wasm.js');
    await wasm.default();
    wasmModule = wasm;
    wasmReady = true;
    console.log('WASM module loaded');
  } catch (e) {
    console.warn('WASM module not available, using fallback IDcom:', e);
  }
}

// Initialize WASM on page load
initWasm();

/** Compute IDcom using real Poseidon hash via WASM (or keccak fallback). */
function computeIdCom(rev: Hex, salt: Hex): Hex {
  if (wasmReady && wasmModule) {
    try {
      const idComHex = wasmModule.compute_id_commitment(rev, salt, 42161);
      return ('0x' + idComHex) as Hex;
    } catch (e) {
      console.warn('WASM IDcom failed, using fallback:', e);
    }
  }
  // Fallback: keccak256 (won't match on-chain Poseidon — display warning)
  const packed = (rev + salt.slice(2)) as Hex;
  const hash = keccak256(packed);
  const num = BigInt(hash) % BN254_FR;
  return ('0x' + num.toString(16).padStart(64, '0')) as Hex;
}

// ---------------------------------------------------------------------------
// Contract interactions
// ---------------------------------------------------------------------------

const FACTORY_ABI = [
  {
    name: 'getAddress',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'idCom', type: 'bytes32' },
      { name: 'salt', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'address' }],
  },
] as const;

const ACCOUNT_ABI = [
  {
    name: 'zkNonce',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    name: 'idCom',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32' }],
  },
] as const;

async function fetchVaultAddress(
  idCom: Hex,
  salt: Hex,
): Promise<Address> {
  return client.readContract({
    address: FACTORY,
    abi: FACTORY_ABI,
    functionName: 'getAddress',
    args: [idCom, BigInt(salt)],
  });
}

async function fetchBalance(addr: Address): Promise<bigint> {
  return client.getBalance({ address: addr });
}

async function fetchNonce(addr: Address): Promise<bigint> {
  try {
    return await client.readContract({
      address: addr,
      abi: ACCOUNT_ABI,
      functionName: 'zkNonce',
    });
  } catch {
    return 0n; // Account not yet deployed
  }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

function saveState() {
  if (state) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }
}

function loadState(): WalletState | null {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as WalletState;
  } catch {
    return null;
  }
}

function clearState() {
  localStorage.removeItem(STORAGE_KEY);
  state = null;
}

// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------

const TAB_IDS = ['tab-create', 'tab-dashboard', 'tab-send', 'tab-activity'];
const PANEL_IDS = [
  'panel-create',
  'panel-dashboard',
  'panel-send',
  'panel-activity',
];

function switchTab(tabId: string) {
  const idx = TAB_IDS.indexOf(tabId);
  TAB_IDS.forEach((t, i) => {
    $(t).classList.toggle('active', i === idx);
  });
  PANEL_IDS.forEach((p, i) => {
    if (i === idx) show(p);
    else hide(p);
  });
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function createWallet() {
  setStatus('Generating wallet...');
  try {
    const rev = randomBytes32();
    const salt = randomBytes32();
    const idCom = computeIdCom(rev, salt);

    setStatus('Computing vault address via factory...');
    let vaultAddress: string;
    try {
      vaultAddress = await fetchVaultAddress(idCom, salt);
    } catch {
      // If factory call fails (e.g. not deployed), derive locally
      vaultAddress = '0x' + keccak256(
        ('0xff' + FACTORY.slice(2) +
          keccak256(('0x' + idCom.slice(2) + BigInt(salt).toString(16).padStart(64, '0')) as Hex).slice(2)) as Hex,
      ).slice(26);
      addActivity('Factory call failed; address derived locally (may differ).');
    }

    state = {
      rev,
      salt,
      idCom,
      vaultAddress,
    };
    saveState();

    renderWalletInfo();
    setStatus('Wallet created! Your REV is stored in localStorage.');
    addActivity('Wallet created. IDcom: ' + truncateAddr(idCom));
    addActivity('Vault address: ' + truncateAddr(vaultAddress));

    // Switch to dashboard
    switchTab('tab-dashboard');
    await refreshDashboard();
  } catch (err: any) {
    setStatus('Error: ' + (err.message || String(err)), true);
    addActivity('Create wallet failed: ' + (err.message || String(err)));
  }
}

async function refreshDashboard() {
  if (!state) return;
  setStatus('Fetching vault data...');
  try {
    const addr = state.vaultAddress as Address;
    const [balance, nonce] = await Promise.all([
      fetchBalance(addr),
      fetchNonce(addr),
    ]);

    $('dash-balance').textContent = formatEther(balance) + ' ETH';
    $('dash-idcom').textContent = state.idCom;
    $('dash-nonce').textContent = nonce.toString();
    $('dash-address').textContent = state.vaultAddress;

    setStatus('Dashboard updated.');
    addActivity('Balance refreshed: ' + formatEther(balance) + ' ETH');
  } catch (err: any) {
    setStatus('Error fetching data: ' + (err.message || String(err)), true);
  }
}

async function sendTransaction() {
  if (!state) {
    setStatus('Create a wallet first.', true);
    return;
  }

  const recipient = ($('send-to') as HTMLInputElement).value.trim();
  const amountStr = ($('send-amount') as HTMLInputElement).value.trim();

  if (!recipient || !recipient.startsWith('0x') || recipient.length !== 42) {
    setStatus('Invalid recipient address.', true);
    return;
  }
  if (!amountStr || isNaN(Number(amountStr)) || Number(amountStr) <= 0) {
    setStatus('Invalid amount.', true);
    return;
  }

  const amount = parseEther(amountStr);

  // Build execute calldata: execute(address dest, uint256 value, bytes func)
  const calldata = encodeFunctionData({
    abi: [
      {
        name: 'execute',
        type: 'function',
        stateMutability: 'nonpayable',
        inputs: [
          { name: 'dest', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'func', type: 'bytes' },
        ],
        outputs: [],
      },
    ],
    functionName: 'execute',
    args: [recipient as Address, amount, '0x'],
  });

  setStatus('Calldata built. Proof generation required...');
  addActivity(
    `Send ${amountStr} ETH to ${truncateAddr(recipient)} -- calldata ready`,
  );

  $('send-result').style.display = '';
  $('send-calldata').textContent = calldata;

  if (wasmReady && wasmModule && pkBytes) {
    // Real WASM proof generation
    setStatus('Generating ZK proof in browser...');
    try {
      const txHash = keccak256(calldata);
      const nonce = state.vaultAddress
        ? Number(await client.readContract({
            address: state.vaultAddress as Address,
            abi: ACCOUNT_ABI,
            functionName: 'zkNonce',
          }))
        : 0;

      const witnessJson = JSON.stringify({
        rev: state.rev,
        salt: state.salt,
        alg_id: 1,
        domain: 42161,
        index: 0,
        nonce: nonce,
        tx_hash: txHash,
      });

      const result = wasmModule.generate_proof(witnessJson, pkBytes);
      setStatus('Proof generated! Signature ready for submission.');
      $('send-cli-hint').textContent = `Proof: ${result.proof.slice(0, 40)}...\nPublic inputs: ${result.public_inputs.slice(0, 40)}...`;
      addActivity(`ZK proof generated for ${amountStr} ETH to ${truncateAddr(recipient)}`);
    } catch (e: any) {
      setStatus(`Proof generation failed: ${e.message || e}`, true);
    }
  } else {
    // Fallback: show CLI command
    $('send-cli-hint').textContent =
      `WASM prover not loaded. Use CLI:\nzkace prove --calldata ${calldata}`;
    addActivity(`Calldata ready for ${amountStr} ETH to ${truncateAddr(recipient)} (use CLI to prove)`);
  }
}

function deleteWallet() {
  if (!confirm('This will delete your REV from localStorage. Are you sure? Make sure you have backed up your REV.')) {
    return;
  }
  clearState();
  renderWalletInfo();
  switchTab('tab-create');
  setStatus('Wallet deleted.');
  addActivity('Wallet deleted from localStorage.');
}

function exportWallet() {
  if (!state) return;
  const data = JSON.stringify(state, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'zkace-wallet-backup.json';
  a.click();
  URL.revokeObjectURL(url);
  addActivity('Wallet backup exported.');
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderWalletInfo() {
  const hasWallet = state !== null;

  // Show/hide relevant controls
  if (hasWallet) {
    $('create-section').style.display = 'none';
    $('wallet-info').style.display = '';
    $('info-address').textContent = state!.vaultAddress;
    $('info-idcom').textContent = truncateAddr(state!.idCom);
    // Enable tabs
    TAB_IDS.forEach((t) => ($(t) as HTMLButtonElement).disabled = false);
  } else {
    $('create-section').style.display = '';
    $('wallet-info').style.display = 'none';
    // Disable all tabs except create
    TAB_IDS.forEach((t, i) => {
      ($(t) as HTMLButtonElement).disabled = i !== 0;
    });
    switchTab('tab-create');
  }

  // Connection info
  $('chain-name').textContent = 'Arbitrum One';
  $('chain-id').textContent = '42161';
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

function init() {
  // Load saved state
  state = loadState();

  // Tab listeners
  TAB_IDS.forEach((t) => {
    $(t).addEventListener('click', () => {
      switchTab(t);
      if (t === 'tab-dashboard' && state) refreshDashboard();
      if (t === 'tab-activity') renderActivity();
    });
  });

  // Action listeners
  $('btn-create').addEventListener('click', createWallet);
  $('btn-refresh').addEventListener('click', refreshDashboard);
  $('btn-send').addEventListener('click', sendTransaction);
  $('btn-delete').addEventListener('click', deleteWallet);
  $('btn-export').addEventListener('click', exportWallet);

  // Copy buttons
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = (btn as HTMLElement).getAttribute('data-copy')!;
      const text = $(target).textContent || '';
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => (btn.textContent = orig), 1200);
      });
    });
  });

  renderWalletInfo();
  renderActivity();

  // Auto-refresh dashboard if wallet exists
  if (state) {
    switchTab('tab-dashboard');
    refreshDashboard();
  }

  setStatus('Ready.');
}

document.addEventListener('DOMContentLoaded', init);
