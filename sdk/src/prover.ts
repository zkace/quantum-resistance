import type { HashChoice, ZkAceWitness, ProofResult } from './types.js';
import type { Hex } from 'viem';
import { computeTxHash, encodeSignature } from './encoding.js';

/**
 * ZK-ACE WASM Prover.
 *
 * Wraps the Rust-compiled WASM module to generate STARK proofs
 * directly in the browser.
 */
export class ZkAceProver {
  private wasmModule: any;

  /** Initialize the prover with the loaded WASM module. */
  async init(wasmModule: any): Promise<void> {
    this.wasmModule = wasmModule;
  }

  /** Check if the prover is initialized. */
  get isReady(): boolean {
    return this.wasmModule != null;
  }

  /**
   * Generate a ZK-ACE proof for authorizing a transaction.
   *
   * @param witness - Private witness values (REV, salt, Ctx, nonce)
   * @param callData - The transaction calldata to authorize
   * @returns Proof result including ABI-encoded signature
   */
  async generateProof(
    witness: ZkAceWitness,
    callData: Hex,
    hashChoice: HashChoice = witness.hashChoice ?? 'poseidon2'
  ): Promise<ProofResult> {
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
      tx_hash: txHash,
    });

    let resultJson: string;
    if (typeof this.wasmModule.generate_stark_proof_with_hash === 'function') {
      resultJson = this.wasmModule.generate_stark_proof_with_hash(witnessJson, hashChoice);
    } else if (hashChoice === 'rescue' && typeof this.wasmModule.generate_stark_proof === 'function') {
      resultJson = this.wasmModule.generate_stark_proof(witnessJson);
    } else {
      throw new Error('The loaded WASM module does not support the requested hash choice.');
    }

    const result = JSON.parse(resultJson) as {
      proof: Hex;
      pub_inputs: number[];
      id_com: Hex;
    };
    const publicInputs = result.pub_inputs.map(BigInt);
    const encodedSignature = encodeSignature(result.proof, publicInputs);

    return {
      proof: result.proof,
      publicInputs,
      idCom: result.id_com,
      hashChoice,
      encodedSignature,
    };
  }
}
