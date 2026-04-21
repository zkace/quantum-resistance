import type { Hex, Address } from 'viem';
import type { UserOperation } from './userop.js';

/** Configuration for the bundler client. */
export interface BundlerConfig {
  /** Bundler RPC endpoint URL (e.g., Pimlico, Alchemy) */
  url: string;
  /** Chain ID */
  chainId: bigint;
  /** EntryPoint address */
  entryPoint: Address;
}

/**
 * Bundler client for submitting ZK-ACE UserOperations.
 *
 * Wraps a standard ERC-4337 bundler API (Pimlico, Alchemy, etc.)
 * to route ZK-ACE proofs through the bundler infrastructure.
 */
export class ZkAceBundlerClient {
  private config: BundlerConfig;

  constructor(config: BundlerConfig) {
    this.config = config;
  }

  /** Submit a UserOperation to the bundler. */
  async submitUserOp(userOp: UserOperation): Promise<Hex> {
    const response = await fetch(this.config.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_sendUserOperation',
        params: [serializeUserOp(userOp), this.config.entryPoint],
      }),
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(`Bundler error: ${result.error.message}`);
    }
    return result.result as Hex;
  }

  /** Wait for a UserOperation receipt. */
  async waitForReceipt(userOpHash: Hex, timeout = 60000): Promise<any> {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      const response = await fetch(this.config.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'eth_getUserOperationReceipt',
          params: [userOpHash],
        }),
      });
      const result = await response.json();
      if (result.result) return result.result;
      await new Promise((r) => setTimeout(r, 2000));
    }
    throw new Error('Timeout waiting for UserOperation receipt');
  }
}

function serializeUserOp(userOp: UserOperation): Record<string, string> {
  return {
    sender: userOp.sender,
    nonce: `0x${userOp.nonce.toString(16)}`,
    initCode: userOp.initCode,
    callData: userOp.callData,
    accountGasLimits: userOp.accountGasLimits,
    preVerificationGas: `0x${userOp.preVerificationGas.toString(16)}`,
    gasFees: userOp.gasFees,
    paymasterAndData: userOp.paymasterAndData,
    signature: userOp.signature,
  };
}
