//! Roundtrip + tamper tests against the ml-dsa 0.1.1 API.

use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa44, Signature, Signer, SigningKey, Verifier,
};
use sha3::{Digest, Keccak256};

#[test]
fn keygen_sign_verify_roundtrip() {
    let sk = SigningKey::<MlDsa44>::generate();
    let vk = sk.verifying_key();

    let msg = [42u8; 32]; // a 32-byte digest
    let sig = sk.sign(&msg);

    assert!(vk.verify(&msg, &sig).is_ok());
}

#[test]
fn tampered_message_fails() {
    let sk = SigningKey::<MlDsa44>::generate();
    let vk = sk.verifying_key();

    let msg = [1u8; 32];
    let sig = sk.sign(&msg);

    let mut other = msg;
    other[0] ^= 0x01;
    assert!(vk.verify(&other, &sig).is_err());
}

#[test]
fn sizes_match_fips204() {
    let sk = SigningKey::<MlDsa44>::generate();
    let vk = sk.verifying_key();

    // seed-based serialization in this crate
    assert_eq!(sk.to_bytes().as_slice().len(), 32);
    assert_eq!(vk.encode().as_slice().len(), 1312);

    let msg = [7u8; 32];
    let sig = sk.sign(&msg);
    assert_eq!(sig.encode().as_slice().len(), 2420);
}

#[test]
fn seed_roundtrip_same_public_key() {
    let sk = SigningKey::<MlDsa44>::generate();
    let pk1 = sk.verifying_key().encode();

    let seed = sk.to_bytes();
    let sk2 = SigningKey::<MlDsa44>::new_from_slice(seed.as_slice()).expect("seed import");
    let pk2 = sk2.verifying_key().encode();

    assert_eq!(pk1.as_slice(), pk2.as_slice());
}

#[test]
fn signature_encode_decode_roundtrip() {
    let sk = SigningKey::<MlDsa44>::generate();
    let vk = sk.verifying_key();

    let msg = [9u8; 32];
    let sig = sk.sign(&msg);

    let bytes = sig.encode();
    let sig2 = Signature::<MlDsa44>::try_from(bytes.as_slice()).expect("sig decode");
    assert!(vk.verify(&msg, &sig2).is_ok());
}

#[test]
fn commitment_is_stable_keccak_of_pk() {
    let sk = SigningKey::<MlDsa44>::generate();
    let pk = sk.verifying_key().encode();

    let mut h = Keccak256::new();
    h.update(pk.as_slice());
    let c1 = h.finalize();

    let mut h = Keccak256::new();
    h.update(pk.as_slice());
    let c2 = h.finalize();

    assert_eq!(c1, c2);
    assert_eq!(c1.len(), 32);
}
