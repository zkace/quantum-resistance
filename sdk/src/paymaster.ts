import type { Hex, Address } from 'viem';
import type { UserOperation } from './userop.js';

/** Configuration for the paymaster. */
export interface PaymasterConfig {
  /** Pimlico/Alchemy paymaster API URL */
  url: string;
  /** Paymaster contract address (if using a verifying paymaster) */
  paymasterAddress?: Address;
}

/**
 * Gas abstraction via ERC-4337 Paymaster.
 *
 * Sponsors gas for ZK-ACE UserOperations, allowing the vault
 * to hold only the target asset (e.g., USDC) with 0 ETH.
 */
export class ZkAcePaymaster {
  private config: PaymasterConfig;

  constructor(config: PaymasterConfig) {
    this.config = config;
  }

  /**
   * Request gas sponsorship for a UserOperation.
   * Returns the UserOperation with paymasterAndData filled in.
   */
  async sponsorUserOp(userOp: UserOperation): Promise<UserOperation> {
    const response = await fetch(this.config.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'pm_sponsorUserOperation',
        params: [
          {
            sender: userOp.sender,
            nonce: `0x${userOp.nonce.toString(16)}`,
            initCode: userOp.initCode,
            callData: userOp.callData,
            signature: userOp.signature,
          },
        ],
      }),
    });

    const result = await response.json();
    if (result.error) {
      throw new Error(`Paymaster error: ${result.error.message}`);
    }

    return {
      ...userOp,
      paymasterAndData: result.result.paymasterAndData as Hex,
      accountGasLimits: result.result.accountGasLimits || userOp.accountGasLimits,
      preVerificationGas: BigInt(result.result.preVerificationGas || userOp.preVerificationGas),
      gasFees: result.result.gasFees || userOp.gasFees,
    };
  }
}
