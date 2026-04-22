import { decodeAbiParameters } from 'viem';
import { describe, expect, it, vi } from 'vitest';
import { computeTxHash, encodeSignature } from '../src/encoding.js';
import { ZkAceProver } from '../src/prover.js';
import type { ZkAceWitness } from '../src/types.js';

const witness: ZkAceWitness = {
  rev: '0x1111111111111111',
  salt: '0x2222222222222222',
  algId: 1n,
  domain: 42161n,
  index: 0n,
  nonce: 7n,
};

describe('encodeSignature', () => {
  it('encodes the STARK proof payload expected by the account', () => {
    const proof = '0x1234';
    const publicInputs = Array.from({ length: 17 }, (_, i) => BigInt(i + 1));

    const encoded = encodeSignature(proof, publicInputs);
    const [decodedProof, decodedInputs] = decodeAbiParameters(
      [{ type: 'bytes' }, { type: 'uint64[17]' }],
      encoded
    );

    expect(decodedProof).toBe(proof);
    expect(decodedInputs.map(BigInt)).toEqual(publicInputs);
  });
});

describe('ZkAceProver', () => {
  it('defaults new proofs to Poseidon2', async () => {
    const generate = vi.fn((witnessJson: string, hashChoice: string) =>
      JSON.stringify({
        proof: '0xdeadbeef',
        pub_inputs: Array.from({ length: 17 }, (_, i) => i),
        id_com: '0x' + '11'.repeat(32),
      })
    );

    const prover = new ZkAceProver();
    await prover.init({ generate_stark_proof_with_hash: generate });

    const result = await prover.generateProof(witness, '0x1234');
    const [witnessJson, hashChoice] = generate.mock.calls[0];

    expect(hashChoice).toBe('poseidon2');
    expect(JSON.parse(witnessJson).tx_hash).toBe(computeTxHash('0x1234'));
    expect(result.hashChoice).toBe('poseidon2');
    expect(result.idCom).toBe('0x' + '11'.repeat(32));
    expect(result.publicInputs).toEqual(Array.from({ length: 17 }, (_, i) => BigInt(i)));
  });

  it('uses the legacy Rescue export when needed', async () => {
    const generate = vi.fn((witnessJson: string) =>
      JSON.stringify({
        proof: '0xcafe',
        pub_inputs: Array.from({ length: 17 }, (_, i) => i + 10),
        id_com: '0x' + '22'.repeat(32),
      })
    );

    const prover = new ZkAceProver();
    await prover.init({ generate_stark_proof: generate });

    const result = await prover.generateProof({ ...witness, hashChoice: 'rescue' }, '0xabcd');

    expect(generate).toHaveBeenCalledTimes(1);
    expect(result.hashChoice).toBe('rescue');
  });

  it('rejects Poseidon2 when the loaded WASM only supports Rescue', async () => {
    const prover = new ZkAceProver();
    await prover.init({ generate_stark_proof: vi.fn() });

    await expect(prover.generateProof(witness, '0xabcd')).rejects.toThrow(
      'does not support the requested hash choice'
    );
  });
});
