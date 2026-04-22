import type { Hex } from 'viem';

export type HashChoice = 'rescue' | 'poseidon2';

export interface ZkAceWitness {
  /** 256-bit Root Entropy Value (hex, 32 bytes) */
  rev: `0x${string}`;
  /** Commitment salt (hex, 32 bytes) */
  salt: `0x${string}`;
  /** Algorithm ID for context derivation */
  algId: bigint;
  /** Chain/application domain (e.g., chain ID) */
  domain: bigint;
  /** Derivation index */
  index: bigint;
  /** Replay-prevention nonce */
  nonce: bigint;
  /** Hash function for idCom / rpCom derivation. Defaults to Poseidon2. */
  hashChoice?: HashChoice;
}

export type ZkAcePublicInputs = bigint[];

export interface ProofResult {
  proof: Hex;
  publicInputs: ZkAcePublicInputs;
  idCom: Hex;
  hashChoice: HashChoice;
  /** ABI-encoded signature bytes for userOp.signature */
  encodedSignature: Hex;
}
