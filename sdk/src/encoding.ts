import { encodeAbiParameters, parseAbiParameters, keccak256, type Hex } from 'viem';
import type { Groth16Proof, ZkAcePublicInputs } from './types.js';

/** BN254 scalar field modulus */
const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Compute TxHash from calldata, reduced to BN254 scalar field. */
export function computeTxHash(callData: Hex): bigint {
  const hash = keccak256(callData);
  return BigInt(hash) % BN254_FR_MODULUS;
}

/** ABI-encode a ZK-ACE proof + public inputs into the signature field format
 *  expected by ZkAceAccount._validateSignature.
 *  No separate nonce — the contract uses its internal zkNonce. */
export function encodeSignature(
  proof: Groth16Proof,
  publicInputs: ZkAcePublicInputs,
): Hex {
  return encodeAbiParameters(
    parseAbiParameters([
      'uint256[2] a',
      'uint256[2][2] b',
      'uint256[2] c',
      'uint256[5] pubInputs',
    ]),
    [
      proof.a,
      proof.b,
      proof.c,
      [publicInputs.idCom, publicInputs.txHash, publicInputs.domain, publicInputs.target, publicInputs.rpCom],
    ],
  );
}
