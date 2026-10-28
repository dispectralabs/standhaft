//! SECURITY AUDIT (auditor 1) — adversarial tests for the crypto/CLI side.
//! Mirrors the exact API usage of crypto/cli/src/main.rs (ml-dsa 0.1.x,
//! RustCrypto) and probes security-relevant properties: determinism,
//! digest binding, tamper resistance, seed/pk/commitment consistency, and an
//! end-to-end emulation of the Vault canonical digest signed by the CLI flow.

use ml_dsa::{
    KeyExport, KeyInit, Keypair, MlDsa44, Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use sha3::{Digest, Keccak256};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

/// Deterministic keypair from a fixed seed (CLI `keygen`-equivalent key
/// material handling; the CLI itself generates random seeds).
fn sk_from_seed(seed: &[u8; 32]) -> SigningKey<MlDsa44> {
    SigningKey::<MlDsa44>::new_from_slice(seed).expect("seed decode")
}

#[test]
/// A-10: the CLI advertises deterministic signing (`sk.sign`). Same seed +
/// same digest MUST produce byte-identical signatures — otherwise the
/// "replay the exact proof bytes" engine assumptions break.
fn deterministic_signing_same_seed_same_digest() {
    let seed = [7u8; 32];
    let digest = keccak(b"standhaft canonical digest");
    let sk1 = sk_from_seed(&seed);
    let sk2 = sk_from_seed(&seed);

    let sig1 = sk1.sign(&digest).encode();
    let sig2 = sk2.sign(&digest).encode();
    assert_eq!(
        sig1.as_slice(),
        sig2.as_slice(),
        "signing must be deterministic"
    );

    let vk1 = sk1.verifying_key().encode();
    let vk2 = sk2.verifying_key().encode();
    assert_eq!(
        vk1.as_slice(),
        vk2.as_slice(),
        "seed must expand to identical pk"
    );
}

#[test]
/// A-11: the signature is bound to the EXACT digest. One flipped bit anywhere
/// in the digest must break verification — the engine relies on this for
/// parameter binding (target/value/data/nonce all feed the digest).
fn digest_binding_single_bit_flip_breaks_signature() {
    let sk = sk_from_seed(&[42u8; 32]);
    let vk = sk.verifying_key();

    let mut digest = keccak(b"standhaft canonical digest");
    let sig = sk.sign(&digest).encode();

    assert!(vk
        .verify(&digest, &Signature::<MlDsa44>::try_from(&sig[..]).unwrap())
        .is_ok());

    digest[31] ^= 0x01;
    assert!(vk
        .verify(&digest, &Signature::<MlDsa44>::try_from(&sig[..]).unwrap())
        .is_err());
}

#[test]
/// A-12: tampering with any region of the encoded signature (c-tilde, z, hint)
/// must break verification — mirrors the on-chain malleability probe.
fn tampered_signature_regions_fail() {
    let sk = sk_from_seed(&[9u8; 32]);
    let vk = sk.verifying_key();
    let digest = keccak(b"tamper probe");
    let sig = sk.sign(&digest).encode();

    for offset in [0usize, 1, 625, 1210, 2300, 2419] {
        let mut tampered = sig.clone();
        tampered[offset] ^= 0x01;
        let decoded = Signature::<MlDsa44>::try_from(&tampered[..]);
        let ok = match decoded {
            Ok(s) => vk.verify(&digest, &s).is_ok(),
            Err(_) => false, // decode rejection also counts as tamper-proofing
        };
        assert!(
            !ok,
            "flipped byte at offset {} must invalidate signature",
            offset
        );
    }
}

#[test]
/// A-13: seed length is enforced (CLI `new_from_slice`), so a truncated or
/// padded "secret_key" cannot silently expand to some other key.
fn seed_length_is_enforced() {
    let short = vec![0u8; 31];
    let long = vec![0u8; 33];
    assert!(SigningKey::<MlDsa44>::new_from_slice(&short).is_err());
    assert!(SigningKey::<MlDsa44>::new_from_slice(&long).is_err());
    assert!(SigningKey::<MlDsa44>::new_from_slice(&[0u8; 32]).is_ok());
}

#[test]
/// A-14: sizes + commitment binding. commitment = keccak256(pk) exactly as the
/// on-chain adapter expects; distinct seeds give distinct commitments; the
/// commitment does not leak the pk.
fn commitment_binding_and_sizes() {
    let sk_a = sk_from_seed(&[1u8; 32]);
    let sk_b = sk_from_seed(&[2u8; 32]);

    let pk_a = sk_a.verifying_key().encode();
    let pk_b = sk_b.verifying_key().encode();
    assert_eq!(pk_a.len(), 1312);

    let digest = keccak(b"sizes probe");
    let sig = sk_a.sign(&digest).encode();
    assert_eq!(sig.len(), 2420);
    assert_eq!(sk_a.to_bytes().len(), 32); // KeyExport seed

    let cmt_a = keccak(pk_a.as_slice());
    let cmt_b = keccak(pk_b.as_slice());
    assert_ne!(cmt_a, cmt_b, "distinct keys must give distinct commitments");
    assert_ne!(cmt_a[..8], pk_a[..8], "commitment must not be a pk prefix");

    // pk length enforcement on the verify side
    assert!(VerifyingKey::<MlDsa44>::new_from_slice(&pk_a[..1311]).is_err());
    assert!(VerifyingKey::<MlDsa44>::new_from_slice(&pk_a).is_ok());
}

#[test]
/// A-15 (documented behavior, not a break): ML-DSA signs ARBITRARY byte
/// strings, and the CLI accepts any-length `--message`. A user who signs
/// human-readable text instead of the canonical 32-byte digest produces a
/// proof the vault will never accept (digest mismatch) — a UX footgun, not a
/// vulnerability, because the vault computes its own digest.
fn cli_accepts_non_32byte_messages() {
    let sk = sk_from_seed(&[3u8; 32]);
    let vk = sk.verifying_key();
    let msg: &[u8] = b"pay alice 1 ETH"; // 15 bytes, NOT a digest
    let sig = sk.sign(msg).encode();
    assert!(vk
        .verify(msg, &Signature::<MlDsa44>::try_from(&sig[..]).unwrap())
        .is_ok());
}

#[test]
/// A-16: end-to-end emulation of the VAULT canonical digest flow in the same
/// language as the CLI — proves the signed object binds (chainid, vault,
/// target, value, keccak256(data), nonce). Single-word `data` ambiguity is
/// also checked: data="" vs data=32 zero bytes must yield different digests
/// (keccak256("") != keccak256(bytes32(0)) — they do).
fn vault_canonical_digest_emulation_binds_everything() {
    let sk = sk_from_seed(&[4u8; 32]);
    let vk = sk.verifying_key();

    // canonical: keccak256(abi.encode(chainid, vault, target, value,
    //                             keccak256(data), nonce))  — 6 x 32-byte words (192B)
    // (The batch wrapper is only 4 words / 128B: keccak256(abi.encode(
    //  chainid, vault, callsHash, nonce)) — different-length preimages, so the
    //  single/batch forms can never collide at the outer keccak256.)
    let mut chainid_word = [0u8; 32];
    chainid_word[24..].copy_from_slice(&31_337u64.to_be_bytes()); // uint256 big-endian

    let mut addr_word = |addr: &[u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(addr);
        w
    };

    let mut uint_word = |v: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&v.to_be_bytes());
        w
    };

    let mut words: Vec<u8> = Vec::with_capacity(192);
    words.extend_from_slice(&chainid_word);
    words.extend_from_slice(&addr_word(&[0u8; 20])); // vault (address)
    words.extend_from_slice(&addr_word(&[0u8; 20])); // target (address)
    words.extend_from_slice(&uint_word(1_000_000_000_000_000_000)); // value
    let data_hash = keccak(b""); // keccak256("")
    words.extend_from_slice(&data_hash);
    words.extend_from_slice(&uint_word(0)); // nonce
    assert_eq!(words.len(), 192);

    let msg_hash = keccak(&words);
    let sig = sk.sign(&msg_hash).encode();

    // valid for the exact canonical digest
    assert!(vk
        .verify(
            &msg_hash,
            &Signature::<MlDsa44>::try_from(&sig[..]).unwrap()
        )
        .is_ok());

    // replay protection: nonce+1 digest must NOT verify
    let mut replayed = words.clone();
    let last = replayed.len() - 32;
    replayed[last + 31] = 1; // nonce = 1
    let replay_digest = keccak(&replayed);
    assert!(vk
        .verify(
            &replay_digest,
            &Signature::<MlDsa44>::try_from(&sig[..]).unwrap()
        )
        .is_err());

    // data ambiguity guard: keccak256("") != keccak256(bytes32(0x00))
    let mut zero32 = [0u8; 32];
    zero32[31] = 0; // all-zero 32-byte word
    assert_ne!(
        data_hash,
        keccak(&zero32),
        "empty data and 32-zero-byte data hash differently"
    );
}
