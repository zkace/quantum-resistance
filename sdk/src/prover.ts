import type { ZkAceWitness, ProofResult, Groth16Proof, ZkAcePublicInputs } from './types.js';
import type { Hex } from 'viem';
import { computeTxHash, encodeSignature } from './encoding.js';

/**
 * ZK-ACE WASM Prover.
 *
 * Wraps the Rust-compiled WASM module to generate Groth16 proofs
 * directly in the browser (~300-600ms per proof).
 */
export class ZkAceProver {
  private wasmModule: any;
  private provingKey: Uint8Array | null = null;

  /** Initialize the prover with the WASM module and proving key. */
  async init(wasmModule: any, pkBytes: Uint8Array): Promise<void> {
    this.wasmModule = wasmModule;
    this.provingKey = pkBytes;
  }

  /** Check if the prover is initialized. */
  get isReady(): boolean {
    return this.wasmModule != null && this.provingKey != null;
  }

  /**
   * Generate a ZK-ACE proof for authorizing a transaction.
   *
   * @param witness - Private witness values (REV, salt, Ctx, nonce)
   * @param callData - The transaction calldata to authorize
   * @returns Proof result including ABI-encoded signature
   */
  async generateProof(witness: ZkAceWitness, callData: Hex): Promise<ProofResult> {
    if (!this.isReady) {
      throw new Error('Prover not initialized. Call init() first.');
    }

    const txHash = computeTxHash(callData);

    // Build witness JSON for WASM
    const witnessJson = JSON.stringify({
      rev: witness.rev,
      salt: witness.salt,
      alg_id: Number(witness.algId),
      domain: Number(witness.domain),
      index: Number(witness.index),
      nonce: Number(witness.nonce),
      tx_hash: txHash.toString(16).padStart(64, '0'),
    });

    // Call WASM prover
    const result = this.wasmModule.generate_proof(witnessJson, this.provingKey);

    // Parse proof output
    const proofBytes = hexToBytes(result.proof);
    const piBytes = hexToBytes(result.public_inputs);

    const proof: Groth16Proof = {
      a: [bytesToBigInt(proofBytes, 0, 32), bytesToBigInt(proofBytes, 32, 64)],
      b: [
        [bytesToBigInt(proofBytes, 64, 96), bytesToBigInt(proofBytes, 96, 128)],
        [bytesToBigInt(proofBytes, 128, 160), bytesToBigInt(proofBytes, 160, 192)],
      ],
      c: [bytesToBigInt(proofBytes, 192, 224), bytesToBigInt(proofBytes, 224, 256)],
    };

    const publicInputs: ZkAcePublicInputs = {
      idCom: bytesToBigInt(piBytes, 0, 32),
      txHash: bytesToBigInt(piBytes, 32, 64),
      domain: bytesToBigInt(piBytes, 64, 96),
      target: bytesToBigInt(piBytes, 96, 128),
      rpCom: bytesToBigInt(piBytes, 128, 160),
    };

    const encodedSignature = encodeSignature(proof, publicInputs);

    return { proof, publicInputs, encodedSignature };
  }
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToBigInt(bytes: Uint8Array, start: number, end: number): bigint {
  let result = 0n;
  for (let i = start; i < end; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}
