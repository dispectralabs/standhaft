//! standhaft ZK guest — verifies an ML-DSA-44 signature INSIDE the zkVM.
//!
//! Inputs  : public_key (1312B), message_digest (32B), signature (2420B),
//!           expected_commitment (32B) — written by the host in this order.
//! Commits : commitment (32B) = keccak256(public_key), message_digest (32B).
//!
//! Security invariant: the commitment is re-derived from the PUBLIC KEY INSIDE the
//! circuit, so the on-chain contract binding `keccak256(pk) == vault.commitment`
//! is carried into the proof. A signature can therefore NEVER be attributed to a
//! different commitment, and no signature is ever revealed on-chain.

use ml_dsa::{KeyInit, MlDsa44, Signature, Verifier, VerifyingKey};
use sha3::{Digest, Keccak256};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let pk = sp1_zkvm::io::read::<Vec<u8>>();
    let msg: [u8; 32] = sp1_zkvm::io::read();
    let sig = sp1_zkvm::io::read::<Vec<u8>>();
    let expected_commitment: [u8; 32] = sp1_zkvm::io::read();

    let vk = VerifyingKey::<MlDsa44>::new_from_slice(&pk).expect("pk length");

    let mut hasher = Keccak256::new();
    hasher.update(&pk);
    let commitment: [u8; 32] = hasher.finalize().into();
    assert_eq!(commitment, expected_commitment, "commitment mismatch");

    let sig = Signature::<MlDsa44>::try_from(&sig[..]).expect("sig length");
    assert!(
        vk.verify(&msg, &sig).is_ok(),
        "invalid ML-DSA-44 signature"
    );

    sp1_zkvm::io::commit(&commitment);
    sp1_zkvm::io::commit(&msg);
}
