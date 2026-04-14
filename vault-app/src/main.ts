// ============================================================
// ZK-ACE Vault — Quantum-Resistant Wallet Application
// ============================================================
//
// Pure client-side ERC-4337 wallet with STARK proof authorization.
// No backend. REV exists only in browser memory during the session.
// ============================================================

import { generateMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { pbkdf2Async } from '@noble/hashes/pbkdf2';
import { sha512 } from '@noble/hashes/sha512';
import {
  createPublicClient,
  http,
  formatEther,
  parseEther,
  encodeFunctionData,
  encodeAbiParameters,
  keccak256,
  toHex,
  getAddress,
  isAddress,
  formatUnits,
  type Address,
  type Hex,
} from 'viem';
import { arbitrum } from 'viem/chains';

// ── Constants ──────────────────────────────────────────────

const CHAIN_ID = 42161n;
const GOLDILOCKS_P = 18446744069414584321n;
const ENTRYPOINT: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
const STARK_VERIFIER: Address = '0xE1B8750ED6Fd835e7D27a1A4F08532BDbFb9F6d4';
const KDF_SALT = 'ZK-ACE-REV-v1';
const KDF_ITERATIONS = 600_000;
const ZERO_BYTES32 = ('0x' + '0'.repeat(64)) as Hex;
// StarkZkAceAccountFactory deployed on Arbitrum One
const STARK_FACTORY: Address = '0x5c7D026978Fa2D159dCC0Bb87F25DbaBfE872614';

// ── ABIs ───────────────────────────────────────────────────

const FACTORY_ABI = [
  {
    type: 'function',
    name: 'getAddress',
    inputs: [
      { name: 'idCom', type: 'bytes32' },
      { name: 'salt', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'createAccount',
    inputs: [
      { name: 'idCom', type: 'bytes32' },
      { name: 'salt', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'nonpayable',
  },
] as const;

const ACCOUNT_ABI = [
  {
    type: 'function',
    name: 'zkNonce',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'paused',
    inputs: [],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'idCom',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'execute',
    inputs: [
      { name: 'dest', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'func', type: 'bytes' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'setPaused',
    inputs: [{ name: '_paused', type: 'bool' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'proposeIdentityRotation',
    inputs: [{ name: 'newIdCom', type: 'bytes32' }],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'confirmIdentityRotation',
    inputs: [],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'pendingIdCom',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'rotationUnlocksAt',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
] as const;

const ERC20_ABI = [
  {
    type: 'function',
    name: 'balanceOf',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'decimals',
    inputs: [],
    outputs: [{ name: '', type: 'uint8' }],
    stateMutability: 'view',
  },
] as const;

// ── Token List (Top Arbitrum ERC-20s) ──────────────────────

interface TokenInfo {
  address: Address;
  symbol: string;
  name: string;
  decimals: number;
  icon: string;
  coingeckoId: string;
}

const TOKENS: TokenInfo[] = [
  { address: '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1', symbol: 'WETH', name: 'Wrapped Ether', decimals: 18, icon: 'Ξ', coingeckoId: 'ethereum' },
  { address: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', symbol: 'USDC', name: 'USD Coin', decimals: 6, icon: '$', coingeckoId: 'usd-coin' },
  { address: '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9', symbol: 'USDT', name: 'Tether USD', decimals: 6, icon: '$', coingeckoId: 'tether' },
  { address: '0x912CE59144191C1204E64559FE8253a0e49E6548', symbol: 'ARB', name: 'Arbitrum', decimals: 18, icon: 'A', coingeckoId: 'arbitrum' },
  { address: '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1', symbol: 'DAI', name: 'Dai', decimals: 18, icon: 'D', coingeckoId: 'dai' },
  { address: '0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f', symbol: 'WBTC', name: 'Wrapped BTC', decimals: 8, icon: '₿', coingeckoId: 'wrapped-bitcoin' },
];

// ── Types ──────────────────────────────────────────────────

interface VaultSession {
  rev: Uint8Array;           // 32 bytes — identity secret, never persisted
  commitmentSalt: Uint8Array; // 32 bytes — deterministic from mnemonic
  idCom: Hex;                // bytes32 — packed 4 Goldilocks elements
  vaultAddress: Address;
  deployed: boolean;
  zkNonce: bigint | null;
  paused: boolean | null;
  pendingIdCom: Hex;
  rotationUnlocksAt: bigint | null;
}

interface AssetBalance {
  symbol: string;
  name: string;
  icon: string;
  balance: bigint;
  decimals: number;
  usdPrice: number;
}

// ── WASM Prover ────────────────────────────────────────────

let wasmModule: any = null;
let wasmReady = false;
let wasmLoadError: string | null = null;
let wasmLoadPromise: Promise<void> | null = null;

async function loadWasm(): Promise<void> {
  try {
    // Dynamic import from public/ — use string concatenation to avoid Vite bundling
    const wasmPath = '/wasm/zk_ace_stark_wasm.js';
    const wasm = await import(/* @vite-ignore */ wasmPath);
    await wasm.default('/wasm/zk_ace_stark_wasm_bg.wasm');
    wasmModule = wasm;
    wasmReady = true;
    wasmLoadError = null;
    console.log('STARK WASM prover loaded (484 KB)');
  } catch (err) {
    wasmReady = false;
    wasmModule = null;
    wasmLoadError = err instanceof Error ? err.message : String(err);
    console.warn('WASM prover failed to load:', err);
    throw err;
  }
}

function startWasmLoad(): Promise<void> {
  if (!wasmLoadPromise || wasmLoadError) {
    wasmLoadPromise = loadWasm().catch(() => undefined);
  }
  return wasmLoadPromise;
}

async function ensureWasmReady(): Promise<void> {
  if (wasmReady && wasmModule) return;
  await startWasmLoad();
  if (!wasmReady || !wasmModule) {
    throw new Error(wasmLoadError || 'STARK prover is still loading. Please try again.');
  }
}

// ── State ──────────────────────────────────────────────────

let session: VaultSession | null = null;
let prices: Record<string, number> = {};
let assets: AssetBalance[] = [];
let refreshTimer: ReturnType<typeof setInterval> | null = null;

// Pimlico bundler — public endpoint (no API key, 20 req/min)
const BUNDLER_RPC = 'https://public.pimlico.io/v2/42161/rpc';

// ── Viem Client ────────────────────────────────────────────

const client = createPublicClient({
  chain: arbitrum,
  transport: http(),
});

// ── DOM Helpers ────────────────────────────────────────────

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function showScreen(id: string) {
  document.querySelectorAll('.screen').forEach((el) => {
    el.classList.remove('active');
  });
  $(id).classList.add('active');

  // Update nav tab active state
  document.querySelectorAll('.nav-tab').forEach((tab) => {
    tab.classList.remove('active');
    if ((tab as HTMLElement).dataset.screen === id.replace('screen-', '')) {
      tab.classList.add('active');
    }
  });
}

function showNav(visible: boolean) {
  $('nav-tabs').style.display = visible ? 'flex' : 'none';
  $('btn-logout').style.display = visible ? '' : 'none';
}

function truncateAddr(addr: string): string {
  if (addr.length <= 14) return addr;
  return addr.slice(0, 8) + '\u2026' + addr.slice(-6);
}

function formatBalance(value: bigint, decimals: number, maxFrac = 4): string {
  const s = formatUnits(value, decimals);
  const [whole, frac = ''] = s.split('.');
  return frac ? `${whole}.${frac.slice(0, maxFrac)}` : whole;
}

function formatUsd(amount: number): string {
  if (amount < 0.01 && amount > 0) return '<$0.01';
  return '$' + amount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function showToast(message: string, type: 'success' | 'error' | 'warn' = 'success') {
  // Remove any existing toast
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast alert alert-${type}`;
  toast.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:2000;max-width:460px;width:90%;animation:fadeIn 0.3s ease';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

function showProofOverlay(visible: boolean, status = '', detail = '') {
  const overlay = $('proof-overlay');
  if (visible) {
    $('proof-status').textContent = status || 'Generating Quantum Proof';
    $('proof-detail').textContent = detail || 'Creating a zero-knowledge proof that authorizes this transaction without revealing your identity\u2026';
    overlay.classList.add('active');
  } else {
    overlay.classList.remove('active');
  }
}

// ── Cryptography ───────────────────────────────────────────

async function deriveKeyMaterial(mnemonic: string): Promise<{ rev: Uint8Array; salt: Uint8Array }> {
  const encoder = new TextEncoder();
  const password = encoder.encode(mnemonic.normalize('NFKD'));
  const saltBytes = encoder.encode(KDF_SALT);

  // PBKDF2-HMAC-SHA512: 600k iterations → 64 bytes
  // First 32 = REV (identity secret), last 32 = commitment salt
  const derived = await pbkdf2Async(sha512, password, saltBytes, {
    c: KDF_ITERATIONS,
    dkLen: 64,
  });

  return {
    rev: derived.slice(0, 32),
    salt: derived.slice(32, 64),
  };
}

/**
 * Compute identity commitment from REV + salt + domain.
 *
 * Uses the Rescue-Prime WASM path only.
 * If the prover is not loaded, derivation is blocked.
 *
 * The result is packed as bytes32: 4 × uint64 big-endian.
 */
function computeIdCom(rev: Uint8Array, salt: Uint8Array, domain: bigint): Hex {
  if (!wasmReady || !wasmModule) {
    throw new Error('STARK prover is not ready. Wallet address derivation is blocked until WASM loads.');
  }

  // Production path only: Rescue-Prime hash via WASM.
  const revElem = reduceBytesToGoldilocks(rev);
  const saltElem = reduceBytesToGoldilocks(salt);
  return wasmModule.compute_id_commitment(revElem, saltElem, domain) as Hex;
}

function packGoldilocksElements(e0: bigint, e1: bigint, e2: bigint, e3: bigint): Hex {
  const packed = (e0 << 192n) | (e1 << 128n) | (e2 << 64n) | e3;
  return ('0x' + packed.toString(16).padStart(64, '0')) as Hex;
}

function splitKeccakToGoldilocks(hash: Hex): [bigint, bigint, bigint, bigint] {
  const hval = BigInt(hash);
  return [
    (hval >> 192n) % GOLDILOCKS_P,
    ((hval >> 128n) & 0xFFFFFFFFFFFFFFFFn) % GOLDILOCKS_P,
    ((hval >> 64n) & 0xFFFFFFFFFFFFFFFFn) % GOLDILOCKS_P,
    (hval & 0xFFFFFFFFFFFFFFFFn) % GOLDILOCKS_P,
  ];
}

/**
 * Reduce a byte array to a Goldilocks field element hex string.
 * Takes the first 8 bytes as big-endian u64, reduces mod P.
 */
function reduceBytesToGoldilocks(bytes: Uint8Array): string {
  const dv = new DataView(bytes.buffer, bytes.byteOffset);
  const val = dv.getBigUint64(0, false) % GOLDILOCKS_P; // big-endian, reduce mod P
  return '0x' + val.toString(16).padStart(16, '0');
}

function zeroize(arr: Uint8Array) {
  arr.fill(0);
}

// ── Chain Interaction ──────────────────────────────────────

async function getVaultAddress(idCom: Hex): Promise<Address | null> {
  try {
    const addr = await client.readContract({
      address: STARK_FACTORY,
      abi: FACTORY_ABI,
      functionName: 'getAddress',
      args: [idCom, 0n],
    });
    return addr;
  } catch {
    return null;
  }
}

async function checkDeployed(address: Address): Promise<boolean> {
  try {
    const code = await client.getCode({ address });
    return !!code && code !== '0x';
  } catch {
    return false;
  }
}

async function fetchEthBalance(address: Address): Promise<bigint> {
  try {
    return await client.getBalance({ address });
  } catch {
    return 0n;
  }
}

async function fetchTokenBalances(address: Address): Promise<AssetBalance[]> {
  const balances: AssetBalance[] = [];

  try {
    const results = await client.multicall({
      contracts: TOKENS.map((t) => ({
        address: t.address,
        abi: ERC20_ABI,
        functionName: 'balanceOf',
        args: [address],
      })),
    });

    for (let i = 0; i < TOKENS.length; i++) {
      const result = results[i];
      if (result.status === 'success') {
        const balance = result.result as bigint;
        if (balance > 0n) {
          balances.push({
            symbol: TOKENS[i].symbol,
            name: TOKENS[i].name,
            icon: TOKENS[i].icon,
            balance,
            decimals: TOKENS[i].decimals,
            usdPrice: prices[TOKENS[i].symbol] ?? 0,
          });
        }
      }
    }
  } catch {
    // multicall failed — balances stay empty
  }

  return balances;
}

async function fetchPrices(): Promise<Record<string, number>> {
  try {
    const ids = ['ethereum', ...TOKENS.map((t) => t.coingeckoId)].join(',');
    const res = await fetch(
      `https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`
    );
    const data = await res.json();
    const map: Record<string, number> = { ETH: data.ethereum?.usd ?? 0 };
    for (const t of TOKENS) {
      map[t.symbol] = data[t.coingeckoId]?.usd ?? 0;
    }
    return map;
  } catch {
    return {};
  }
}

async function fetchVaultNonce(address: Address): Promise<bigint | null> {
  try {
    const nonce = await client.readContract({
      address,
      abi: ACCOUNT_ABI,
      functionName: 'zkNonce',
    });
    return nonce;
  } catch {
    return null;
  }
}

async function fetchPauseStatus(address: Address): Promise<boolean | null> {
  try {
    return await client.readContract({
      address,
      abi: ACCOUNT_ABI,
      functionName: 'paused',
    });
  } catch {
    return null;
  }
}

async function fetchRotationState(address: Address): Promise<{ pendingIdCom: Hex; rotationUnlocksAt: bigint | null } | null> {
  try {
    const [pendingIdCom, rotationUnlocksAt] = await Promise.all([
      client.readContract({
        address,
        abi: ACCOUNT_ABI,
        functionName: 'pendingIdCom',
      }),
      client.readContract({
        address,
        abi: ACCOUNT_ABI,
        functionName: 'rotationUnlocksAt',
      }),
    ]);

    return {
      pendingIdCom: pendingIdCom as Hex,
      rotationUnlocksAt: rotationUnlocksAt === 0n ? null : rotationUnlocksAt,
    };
  } catch {
    return null;
  }
}

// ── UI Rendering ───────────────────────────────────────────

function renderMnemonic(words: string[]) {
  const grid = $('mnemonic-display');
  grid.innerHTML = words
    .map(
      (word, i) =>
        `<div class="mnemonic-word"><span class="mnemonic-num">${i + 1}</span>${escapeHtml(word)}</div>`
    )
    .join('');
}

function escapeHtml(s: string): string {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

async function renderDashboard() {
  if (!session) return;

  // Address
  $('vault-addr-display').textContent = truncateAddr(session.vaultAddress);
  $('receive-addr').textContent = session.vaultAddress;
  $('qr-display').textContent = session.vaultAddress;

  // Fetch ETH balance
  const ethBalance = await fetchEthBalance(session.vaultAddress);
  const ethFormatted = formatBalance(ethBalance, 18);
  $('balance-eth').textContent = ethFormatted + ' ETH';

  const ethUsd = Number(formatEther(ethBalance)) * (prices.ETH ?? 0);

  // Fetch token balances
  assets = await fetchTokenBalances(session.vaultAddress);

  // Total USD
  let totalUsd = ethUsd;
  for (const a of assets) {
    totalUsd += Number(formatUnits(a.balance, a.decimals)) * a.usdPrice;
  }
  $('balance-usd').textContent = formatUsd(totalUsd);

  renderAssetList(ethBalance, ethUsd);

  // Settings
  if (session.deployed) {
    const [nonce, paused, rotation] = await Promise.all([
      fetchVaultNonce(session.vaultAddress),
      fetchPauseStatus(session.vaultAddress),
      fetchRotationState(session.vaultAddress),
    ]);

    session.zkNonce = nonce;
    session.paused = paused;
    session.pendingIdCom = rotation?.pendingIdCom ?? ZERO_BYTES32;
    session.rotationUnlocksAt = rotation?.rotationUnlocksAt ?? null;

    $('settings-deployed').textContent = 'Live on Arbitrum';
    $('settings-nonce').textContent = nonce === null ? 'Unavailable' : nonce.toString();
    $('settings-paused').textContent = paused === null ? 'Unavailable' : paused ? 'Paused' : 'Active';

    if (session.pendingIdCom !== ZERO_BYTES32) {
      if (session.rotationUnlocksAt && session.rotationUnlocksAt > BigInt(Math.floor(Date.now() / 1000))) {
        $('settings-rotation').textContent = 'Pending timelock';
        $('rotate-label').textContent = 'Rotation Pending';
        $('rotate-desc').textContent = 'Waiting for the 48h timelock before confirmation.';
      } else {
        $('settings-rotation').textContent = 'Ready to confirm';
        $('rotate-label').textContent = 'Confirm Rotation';
        $('rotate-desc').textContent = 'Submit a proof to finalize the pending identity change.';
      }
    } else {
      $('settings-rotation').textContent = 'None pending';
      $('rotate-label').textContent = 'Rotate Identity';
      $('rotate-desc').textContent = 'Paste a new 24-word recovery phrase to start a 48h timelock.';
    }

    $('pause-label').textContent = paused ? 'Unpause Vault' : 'Emergency Pause';
    $('pause-desc').textContent = paused ? 'Re-enable vault operations with a proof-backed UserOp.' : 'Freeze vault operations with a proof-backed UserOp.';
  } else {
    session.zkNonce = 0n;
    session.paused = null;
    session.pendingIdCom = ZERO_BYTES32;
    session.rotationUnlocksAt = null;
    $('settings-deployed').textContent = 'Counterfactual only';
    $('settings-nonce').textContent = '0 (predeploy)';
    $('settings-paused').textContent = 'Unavailable until deployment';
    $('settings-rotation').textContent = 'Unavailable until deployment';
    $('pause-label').textContent = 'Emergency Pause';
    $('pause-desc').textContent = 'Deploy the vault first to change pause state.';
    $('rotate-label').textContent = 'Rotate Identity';
    $('rotate-desc').textContent = 'Deploy the vault first to start or confirm a rotation.';
  }
}

function renderAssetList(ethBalance: bigint, ethUsd: number) {
  const list = $('asset-list');
  let html = `
    <div class="asset-row">
      <div class="asset-icon">Ξ</div>
      <div class="asset-info">
        <div class="asset-name">Ethereum</div>
        <div class="asset-symbol">ETH</div>
      </div>
      <div class="asset-balance">
        <div class="asset-amount">${formatBalance(ethBalance, 18)}</div>
        <div class="asset-usd">${formatUsd(ethUsd)}</div>
      </div>
    </div>`;

  for (const a of assets) {
    const usd = Number(formatUnits(a.balance, a.decimals)) * a.usdPrice;
    html += `
    <div class="asset-row">
      <div class="asset-icon">${escapeHtml(a.icon)}</div>
      <div class="asset-info">
        <div class="asset-name">${escapeHtml(a.name)}</div>
        <div class="asset-symbol">${escapeHtml(a.symbol)}</div>
      </div>
      <div class="asset-balance">
        <div class="asset-amount">${formatBalance(a.balance, a.decimals)}</div>
        <div class="asset-usd">${formatUsd(usd)}</div>
      </div>
    </div>`;
  }

  list.innerHTML = html;
}

// ── Bundler (ERC-4337) ─────────────────────────────────────

const ENTRYPOINT_ABI = [
  {
    type: 'function',
    name: 'getNonce',
    inputs: [
      { name: 'sender', type: 'address' },
      { name: 'key', type: 'uint192' },
    ],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
] as const;

async function bundlerRpc(method: string, params: any[]): Promise<any> {
  const res = await fetch(BUNDLER_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
  return json.result;
}

async function getEntryPointNonce(sender: Address): Promise<bigint> {
  const nonce = await client.readContract({
    address: ENTRYPOINT,
    abi: ENTRYPOINT_ABI,
    functionName: 'getNonce',
    args: [sender, 0n],
  });
  return nonce;
}

function packGasLimits(verificationGas: bigint, callGas: bigint): Hex {
  return ('0x' + verificationGas.toString(16).padStart(32, '0') + callGas.toString(16).padStart(32, '0')) as Hex;
}

function packGasFees(maxPriorityFee: bigint, maxFee: bigint): Hex {
  return ('0x' + maxPriorityFee.toString(16).padStart(32, '0') + maxFee.toString(16).padStart(32, '0')) as Hex;
}

function toHexBigInt(n: bigint): string {
  return '0x' + n.toString(16);
}

async function submitUserOp(
  sender: Address,
  calldata: Hex,
  signature: Hex,
  nonce: bigint,
  deployment?: { factory: Address; factoryData: Hex } | null,
): Promise<{ userOpHash: Hex; txHash: Hex }> {
  // Get gas prices from Pimlico
  const gasPrices = await bundlerRpc('pimlico_getUserOperationGasPrice', []);
  const maxFeePerGas = BigInt(gasPrices.fast.maxFeePerGas);
  const maxPriorityFeePerGas = BigInt(gasPrices.fast.maxPriorityFeePerGas);

  // Build UserOp with generous gas limits for STARK verification (~6M gas)
  const verificationGasLimit = 7_000_000n;
  const callGasLimit = 200_000n;
  const preVerificationGas = 100_000n;

  const userOp = {
    sender,
    nonce: toHexBigInt(nonce),
    factory: deployment?.factory ?? null,
    factoryData: deployment?.factoryData ?? null,
    callData: calldata,
    callGasLimit: toHexBigInt(callGasLimit),
    verificationGasLimit: toHexBigInt(verificationGasLimit),
    preVerificationGas: toHexBigInt(preVerificationGas),
    maxFeePerGas: toHexBigInt(maxFeePerGas),
    maxPriorityFeePerGas: toHexBigInt(maxPriorityFeePerGas),
    paymaster: null,
    paymasterVerificationGasLimit: null,
    paymasterPostOpGasLimit: null,
    paymasterData: null,
    signature,
  };

  // Submit to bundler
  const userOpHash = await bundlerRpc('eth_sendUserOperation', [userOp, ENTRYPOINT]);

  // Poll for receipt
  const start = Date.now();
  while (Date.now() - start < 90_000) {
    const receipt = await bundlerRpc('eth_getUserOperationReceipt', [userOpHash]);
    if (receipt) {
      return {
        userOpHash: userOpHash as Hex,
        txHash: receipt.receipt.transactionHash as Hex,
      };
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error('Timeout waiting for transaction confirmation');
}

// ── Flows ──────────────────────────────────────────────────

function normalizeMnemonicInput(raw: string): string {
  return raw.trim().toLowerCase().replace(/\s+/g, ' ');
}

function toSafeJsNumber(value: bigint, label: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} is too large for the current browser prover encoding.`);
  }
  return Number(value);
}

async function resolveProofNonce(activeSession: VaultSession): Promise<bigint> {
  if (!activeSession.deployed) return 0n;

  const latestNonce = await fetchVaultNonce(activeSession.vaultAddress);
  if (latestNonce === null) {
    throw new Error('Unable to read the current vault nonce from chain. Please retry.');
  }

  activeSession.zkNonce = latestNonce;
  return latestNonce;
}

function getDeploymentInit(activeSession: VaultSession): { factory: Address; factoryData: Hex } | null {
  if (activeSession.deployed) return null;
  return {
    factory: STARK_FACTORY,
    factoryData: encodeFunctionData({
      abi: FACTORY_ABI,
      functionName: 'createAccount',
      args: [activeSession.idCom, 0n],
    }),
  };
}

async function buildStarkSignature(activeSession: VaultSession, calldata: Hex): Promise<Hex> {
  await ensureWasmReady();

  const zkNonce = await resolveProofNonce(activeSession);
  const txHash = keccak256(calldata);

  const witness = {
    rev: reduceBytesToGoldilocks(activeSession.rev),
    salt: reduceBytesToGoldilocks(activeSession.commitmentSalt),
    alg_id: 1,
    domain: Number(CHAIN_ID),
    index: 0,
    nonce: toSafeJsNumber(zkNonce, 'zkNonce'),
    tx_hash: txHash,
  };

  await new Promise((r) => setTimeout(r, 50));
  const resultJson = wasmModule.generate_stark_proof(JSON.stringify(witness));
  const result = JSON.parse(resultJson);
  const proofBytes = result.proof as Hex;
  const pubInputs = result.pub_inputs as number[];

  $('proof-status').textContent = 'Proof Generated';
  $('proof-detail').textContent = `STARK proof: ${Math.round(proofBytes.length / 2)} bytes. Submitting to Arbitrum...`;

  return encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'uint64[17]' }],
    [proofBytes, pubInputs.map(BigInt) as any]
  );
}

async function submitAuthorizedCall(
  activeSession: VaultSession,
  calldata: Hex,
  provingDetail: string,
): Promise<{ txHash: Hex }> {
  showProofOverlay(true, 'Generating Quantum Proof', provingDetail);

  const signature = await buildStarkSignature(activeSession, calldata);
  const epNonce = await getEntryPointNonce(activeSession.vaultAddress);
  const deployment = getDeploymentInit(activeSession);
  const { txHash } = await submitUserOp(
    activeSession.vaultAddress,
    calldata,
    signature,
    epNonce,
    deployment,
  );

  if (deployment) {
    activeSession.deployed = true;
  }

  return { txHash };
}

async function handleCreate() {
  // Generate 24-word BIP-39 mnemonic (256 bits entropy)
  const mnemonic = generateMnemonic(wordlist, 256);
  const words = mnemonic.split(' ');
  renderMnemonic(words);
  showScreen('screen-create');

  // Store mnemonic temporarily for the confirm step
  ($('btn-confirm-create') as any)._mnemonic = mnemonic;
}

async function handleConfirmCreate() {
  const mnemonic: string = ($('btn-confirm-create') as any)._mnemonic;
  if (!mnemonic) return;
  delete ($('btn-confirm-create') as any)._mnemonic;

  await unlockVault(mnemonic);
}

async function handleImport() {
  showScreen('screen-import');
  ($('import-mnemonic') as HTMLTextAreaElement).value = '';
  ($('import-mnemonic') as HTMLTextAreaElement).focus();
}

async function handleConfirmImport() {
  const raw = normalizeMnemonicInput(($('import-mnemonic') as HTMLTextAreaElement).value);

  if (!validateMnemonic(raw, wordlist)) {
    showToast('Invalid mnemonic. Please enter a valid 24-word recovery phrase.', 'error');
    return;
  }

  await unlockVault(raw);
}

async function unlockVault(mnemonic: string) {
  showProofOverlay(true, 'Deriving Keys', 'Running PBKDF2-SHA512 with 600,000 iterations\u2026');

  try {
    await ensureWasmReady();
    const { rev, salt } = await deriveKeyMaterial(mnemonic);
    const idCom = computeIdCom(rev, salt, CHAIN_ID);

    const vaultAddress = await getVaultAddress(idCom);
    if (!vaultAddress) {
      throw new Error('Unable to derive the vault address from the live STARK factory.');
    }

    const deployed = await checkDeployed(vaultAddress);

    session = {
      rev,
      commitmentSalt: salt,
      idCom,
      vaultAddress,
      deployed,
      zkNonce: deployed ? null : 0n,
      paused: null,
      pendingIdCom: ZERO_BYTES32,
      rotationUnlocksAt: null,
    };

    // Fetch prices and render dashboard
    prices = await fetchPrices();
    await renderDashboard();

    showProofOverlay(false);
    showNav(true);
    showScreen('screen-dashboard');

    // Auto-refresh every 30s
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(async () => {
      prices = await fetchPrices();
      await renderDashboard();
    }, 30_000);
  } catch (err) {
    showProofOverlay(false);
    showToast('Failed to unlock vault: ' + (err as Error).message, 'error');
  }
}

async function handleSend() {
  if (!session) return;

  const recipientRaw = ($('send-to') as HTMLInputElement).value.trim();
  const amountStr = ($('send-amount') as HTMLInputElement).value.trim();

  if (!recipientRaw) {
    showToast('Please enter a recipient address.', 'error');
    return;
  }

  if (!isAddress(recipientRaw)) {
    showToast('Invalid recipient address.', 'error');
    return;
  }

  const amount = parseFloat(amountStr);
  if (isNaN(amount) || amount <= 0) {
    showToast('Please enter a valid amount.', 'error');
    return;
  }

  const recipient = getAddress(recipientRaw);
  const value = parseEther(amountStr);

  // Build execute calldata
  const calldata = encodeFunctionData({
    abi: ACCOUNT_ABI,
    functionName: 'execute',
    args: [recipient, value, '0x'],
  });

  try {
    const verb = session.deployed ? 'authorizes this transfer' : 'deploys the vault and authorizes this transfer';
    const { txHash: confirmedTxHash } = await submitAuthorizedCall(
      session,
      calldata,
      `Running the browser STARK prover for the proof that ${verb}... This takes 5-10 seconds.`,
    );

    showProofOverlay(false);

    // Clear send form
    ($('send-to') as HTMLInputElement).value = '';
    ($('send-amount') as HTMLInputElement).value = '';

    showToast('Transaction confirmed! ' + confirmedTxHash.slice(0, 18) + '\u2026', 'success');

    // Refresh dashboard
    showScreen('screen-dashboard');
    await renderDashboard();
  } catch (err) {
    showProofOverlay(false);
    showToast('Proof generation failed: ' + (err as Error).message, 'error');
  }
}

function handleLogout() {
  if (session) {
    // Zeroize sensitive material
    zeroize(session.rev);
    zeroize(session.commitmentSalt);
    session = null;
  }
  assets = [];
  prices = {};
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }

  showNav(false);
  showScreen('screen-onboard');

  // Clear send form
  ($('send-to') as HTMLInputElement).value = '';
  ($('send-amount') as HTMLInputElement).value = '';
}

async function handleCopyAddress() {
  if (!session) return;
  try {
    await navigator.clipboard.writeText(session.vaultAddress);
    showToast('Address copied', 'success');
  } catch {
    showToast('Failed to copy', 'error');
  }
}

async function handlePause() {
  if (!session) return;
  if (!session.deployed) {
    showToast('Deploy the vault before changing pause state.', 'warn');
    return;
  }

  const paused = await fetchPauseStatus(session.vaultAddress);
  if (paused === null) {
    showToast('Unable to read the current pause state. Please retry.', 'error');
    return;
  }

  const calldata = encodeFunctionData({
    abi: ACCOUNT_ABI,
    functionName: 'setPaused',
    args: [!paused],
  });

  try {
    const { txHash } = await submitAuthorizedCall(
      session,
      calldata,
      `${paused ? 'Generating a proof to unpause the vault' : 'Generating a proof to pause the vault'}...`
    );
    showProofOverlay(false);
    showToast(`${paused ? 'Unpause' : 'Pause'} confirmed: ${txHash.slice(0, 18)}...`, 'success');
    await renderDashboard();
  } catch (err) {
    showProofOverlay(false);
    showToast('Pause flow failed: ' + (err as Error).message, 'error');
  }
}

async function handleRotate() {
  if (!session) return;
  if (!session.deployed) {
    showToast('Deploy the vault before rotating identity.', 'warn');
    return;
  }

  const rotation = await fetchRotationState(session.vaultAddress);
  if (!rotation) {
    showToast('Unable to read the current rotation state. Please retry.', 'error');
    return;
  }

  try {
    if (rotation.pendingIdCom !== ZERO_BYTES32) {
      const now = BigInt(Math.floor(Date.now() / 1000));
      if (rotation.rotationUnlocksAt && rotation.rotationUnlocksAt > now) {
        showToast('Rotation is pending and still in its 48h timelock window.', 'warn');
        return;
      }

      if (!confirm('Confirm the pending identity rotation now? This switches the vault to the queued identity commitment.')) {
        return;
      }

      const confirmCalldata = encodeFunctionData({
        abi: ACCOUNT_ABI,
        functionName: 'confirmIdentityRotation',
      });

      const { txHash } = await submitAuthorizedCall(
        session,
        confirmCalldata,
        'Generating a proof to confirm the pending identity rotation...'
      );
      showProofOverlay(false);
      showToast('Rotation confirmed: ' + txHash.slice(0, 18) + '...', 'success');
      await renderDashboard();
      return;
    }

    const rawMnemonic = prompt('Paste the new 24-word recovery phrase that should control this vault after the 48h timelock.');
    if (!rawMnemonic) return;

    const nextMnemonic = normalizeMnemonicInput(rawMnemonic);
    if (!validateMnemonic(nextMnemonic, wordlist)) {
      showToast('Invalid mnemonic. Rotation requires a valid 24-word recovery phrase.', 'error');
      return;
    }

    const { rev, salt } = await deriveKeyMaterial(nextMnemonic);
    try {
      await ensureWasmReady();
      const nextIdCom = computeIdCom(rev, salt, CHAIN_ID);
      if (nextIdCom === session.idCom) {
        showToast('That recovery phrase already controls this vault.', 'warn');
        return;
      }

      const proposeCalldata = encodeFunctionData({
        abi: ACCOUNT_ABI,
        functionName: 'proposeIdentityRotation',
        args: [nextIdCom],
      });

      const { txHash } = await submitAuthorizedCall(
        session,
        proposeCalldata,
        'Generating a proof to start the 48h identity-rotation timelock...'
      );
      showProofOverlay(false);
      showToast('Rotation proposed: ' + txHash.slice(0, 18) + '...', 'success');
      await renderDashboard();
    } finally {
      zeroize(rev);
      zeroize(salt);
    }
  } catch (err) {
    showProofOverlay(false);
    showToast('Rotation flow failed: ' + (err as Error).message, 'error');
  }
}

async function handleExportMnemonic() {
  if (!session) return;
  showToast('Recovery phrases are not retained after unlock in this build. Use the original backup phrase.', 'warn');
}

// ── Event Binding ──────────────────────────────────────────

function bindEvents() {
  // Onboarding
  $('btn-create').addEventListener('click', handleCreate);
  $('btn-import').addEventListener('click', handleImport);

  // Create flow
  $('btn-create-back').addEventListener('click', () => showScreen('screen-onboard'));
  $('btn-confirm-create').addEventListener('click', handleConfirmCreate);

  // Import flow
  $('btn-import-back').addEventListener('click', () => showScreen('screen-onboard'));
  $('btn-confirm-import').addEventListener('click', handleConfirmImport);

  // Dashboard
  $('btn-copy-addr').addEventListener('click', handleCopyAddress);
  $('btn-send').addEventListener('click', () => showScreen('screen-send'));
  $('btn-receive').addEventListener('click', () => showScreen('screen-receive'));

  // Send
  $('btn-send-back').addEventListener('click', () => showScreen('screen-dashboard'));
  $('btn-authorize').addEventListener('click', handleSend);

  // Receive
  $('btn-receive-back').addEventListener('click', () => showScreen('screen-dashboard'));
  $('btn-copy-receive').addEventListener('click', handleCopyAddress);

  // Settings
  $('btn-pause').addEventListener('click', handlePause);
  $('btn-rotate').addEventListener('click', handleRotate);
  $('btn-export-mnemonic').addEventListener('click', handleExportMnemonic);

  // Logout
  $('btn-logout').addEventListener('click', () => {
    if (confirm('Lock your vault? You will need your recovery phrase to unlock again.')) {
      handleLogout();
    }
  });

  // Nav tabs
  document.querySelectorAll('.nav-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const screen = (tab as HTMLElement).dataset.screen;
      if (screen) {
        showScreen('screen-' + screen);
        // Refresh dashboard when switching to it
        if (screen === 'dashboard') renderDashboard();
      }
    });
  });

  // Zeroize on tab close / navigation away
  window.addEventListener('beforeunload', () => {
    if (session) {
      zeroize(session.rev);
      zeroize(session.commitmentSalt);
    }
  });
}

// ── Init ───────────────────────────────────────────────────

function init() {
  bindEvents();
  showScreen('screen-onboard');
  showNav(false);
  // Load WASM prover in background — non-blocking
  startWasmLoad();
}

document.addEventListener('DOMContentLoaded', init);
