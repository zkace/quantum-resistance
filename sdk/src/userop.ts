import type { Hex, Address } from 'viem';
import type { ZkAceWitness } from './types.js';
import { ZkAceProver } from './prover.js';

/** Minimal ERC-4337 PackedUserOperation fields needed for ZK-ACE. */
export interface UserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterAndData: Hex;
  signature: Hex;
}

/**
 * Build a UserOperation with a ZK-ACE proof in the signature field.
 *
 * @param params.sender - ZkAceAccount address
 * @param params.callData - Transaction calldata to authorize
 * @param params.witness - Private witness values
 * @param params.prover - Initialized ZkAceProver
 * @param params.nonce - ERC-4337 EntryPoint nonce
 * @returns Complete UserOperation ready for bundler submission
 */
export async function buildZkAceUserOp(params: {
  sender: Address;
  callData: Hex;
  witness: ZkAceWitness;
  prover: ZkAceProver;
  nonce?: bigint;
}): Promise<UserOperation> {
  const { sender, callData, witness, prover, nonce = 0n } = params;

  // Generate ZK-ACE proof
  const proofResult = await prover.generateProof(witness, callData);

  return {
    sender,
    nonce,
    initCode: '0x',
    callData,
    accountGasLimits: '0x00000000000000000000000000030d4000000000000000000000000000030d40',
    preVerificationGas: 50000n,
    gasFees: '0x0000000000000000000000003b9aca000000000000000000000000003b9aca00',
    paymasterAndData: '0x',
    signature: proofResult.encodedSignature,
  };
}
