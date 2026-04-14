use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use zk_ace_circuit::circuit::ZkAceCircuit;
use zk_ace_circuit::types::{ZkAcePublicInputs, ZkAceWitness};

/// Generate a Groth16 proof for a ZK-ACE authorization statement.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    witness: ZkAceWitness<Fr>,
    public_inputs: ZkAcePublicInputs<Fr>,
    rng: &mut R,
) -> Proof<Bn254> {
    let circuit = ZkAceCircuit::new(witness, public_inputs);
    Groth16::<Bn254>::prove(pk, circuit, rng).expect("Proof generation should not fail with valid witness")
}

/// Extract the public input vector in the order expected by the verifier.
/// Order: [id_com, tx_hash, domain, target, rp_com]
pub fn public_inputs_to_vec(pi: &ZkAcePublicInputs<Fr>) -> Vec<Fr> {
    vec![pi.id_com, pi.tx_hash, pi.domain, pi.target, pi.rp_com]
}
