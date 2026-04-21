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
}

export interface Groth16Proof {
  a: [bigint, bigint];
  b: [[bigint, bigint], [bigint, bigint]];
  c: [bigint, bigint];
}

export interface ZkAcePublicInputs {
  idCom: bigint;
  txHash: bigint;
  domain: bigint;
  target: bigint;
  rpCom: bigint;
}

export interface ProofResult {
  proof: Groth16Proof;
  publicInputs: ZkAcePublicInputs;
  /** ABI-encoded signature bytes for userOp.signature */
  encodedSignature: `0x${string}`;
}
