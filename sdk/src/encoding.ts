import { encodeAbiParameters, keccak256, type Hex } from 'viem';
import type { ZkAcePublicInputs } from './types.js';

type EncodedPublicInputs17 = [
  bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint,
  bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint,
];

/** Compute the 32-byte calldata hash consumed by the STARK witness. */
export function computeTxHash(callData: Hex): Hex {
  return keccak256(callData);
}

/** ABI-encode the STARK proof payload expected by StarkZkAceAccount. */
export function encodeSignature(
  proof: Hex,
  publicInputs: ZkAcePublicInputs,
): Hex {
  if (publicInputs.length !== 17) {
    throw new Error(`Expected 17 public inputs, received ${publicInputs.length}.`);
  }

  const encodedInputs = publicInputs.map(BigInt) as EncodedPublicInputs17;

  return encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'uint64[17]' }],
    [proof, encodedInputs]
  );
}
