//! standhaft-cli — ML-DSA-44 (FIPS 204) keygen / sign / verify
//!
//! ml-dsa 0.1.1 (RustCrypto) API:
//!   - SigningKey serializes as a 32-byte SEED (`to_bytes`, `new_from_slice`)
//!   - VerifyingKey (public key) = 1312 bytes (`encode`, `new_from_slice`)
//!   - Signature = 2420 bytes (`encode`/`decode` via SignatureEncoding)
//!   - commitment = keccak256(public_key) — what the on-chain vault stores
//!
//! Message convention: sign a 32-byte digest (the vault's msgHash).
//! Solidity verifier checks ML-DSA.Verify(pk, M, sigma) with M = that digest.

use clap::{Parser, Subcommand};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa44, Signature, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use serde_json::json;
use sha3::{Digest, Keccak256};

const SEED_LEN: usize = 32;
const PK_LEN: usize = 1312;
const SIG_LEN: usize = 2420;

#[derive(Parser)]
#[command(
    name = "standhaft",
    version,
    about = "Post-quantum vault CLI — ML-DSA-44 (FIPS 204)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new ML-DSA-44 keypair. Prints JSON:
    /// { algorithm, public_key, secret_key(seed), commitment, sizes }
    Keygen,
    /// Sign a message (hex). Pass the 32-byte msgHash the vault will verify.
    Sign {
        #[arg(long, help = "secret key seed (hex, 32 bytes)")]
        secret_key: String,
        #[arg(long, help = "message to sign (hex); 32-byte digest recommended")]
        message: String,
    },
    /// Verify signature (hex) against public key (hex) and message (hex).
    /// Prints JSON: { valid: true|false }
    Verify {
        #[arg(long, help = "public key (hex, 1312 bytes)")]
        public_key: String,
        #[arg(long)]
        message: String,
        #[arg(long, help = "signature (hex, 2420 bytes)")]
        signature: String,
    },
    /// Compute keccak256 commitment of a public key (hex).
    Commitment {
        #[arg(long, help = "public key (hex)")]
        public_key: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Keygen => cmd_keygen(),
        Cmd::Sign { secret_key, message } => cmd_sign(&secret_key, &message),
        Cmd::Verify { public_key, message, signature } => {
            cmd_verify(&public_key, &message, &signature)
        }
        Cmd::Commitment { public_key } => cmd_commitment(&public_key),
    };
    match result {
        Ok(out) => println!("{}", serde_json::to_string_pretty(&out).expect("json")),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn decode_hex(label: &str, s: &str, expect: Option<usize>) -> Result<Vec<u8>, String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("{label}: invalid hex: {e}"))?;
    if let Some(n) = expect {
        if v.len() != n {
            return Err(format!("{label}: expected {n} bytes, got {}", v.len()));
        }
    }
    Ok(v)
}

fn keccak(data: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn cmd_keygen() -> Result<serde_json::Value, String> {
    let sk = SigningKey::<MlDsa44>::generate();
    let vk = sk.verifying_key();

    let seed = sk.to_bytes(); // KeyExport -> Seed ([u8; 32])
    let pk = vk.encode(); // EncodedVerifyingKey ([u8; 1312])
    debug_assert_eq!(seed.as_slice().len(), SEED_LEN);
    debug_assert_eq!(pk.as_slice().len(), PK_LEN);

    Ok(json!({
        "algorithm": "ML-DSA-44",
        "public_key": hex::encode(pk.as_slice()),
        "secret_key": hex::encode(seed.as_slice()),
        "secret_key_note": "32-byte seed; expands to FIPS 204 sk",
        "commitment": keccak(pk.as_slice()),
        "sizes": { "public_key": pk.as_slice().len(), "secret_seed": seed.as_slice().len() }
    }))
}

fn cmd_sign(secret_key_hex: &str, message_hex: &str) -> Result<serde_json::Value, String> {
    let seed_bytes = decode_hex("secret_key", secret_key_hex, Some(SEED_LEN))?;
    let msg = decode_hex("message", message_hex, None)?;

    let sk = SigningKey::<MlDsa44>::new_from_slice(&seed_bytes)
        .map_err(|_| "secret_key: decode failed (wrong length)")?;
    let vk = sk.verifying_key();

    let sig = sk.sign(&msg); // Signer trait (deterministic)
    let sig_enc = sig.encode();
    debug_assert_eq!(sig_enc.as_slice().len(), SIG_LEN);

    let pk = vk.encode();
    Ok(json!({
        "message": hex::encode(&msg),
        "signature": hex::encode(sig_enc.as_slice()),
        "public_key": hex::encode(pk.as_slice()),
        "commitment": keccak(pk.as_slice())
    }))
}

fn cmd_verify(
    public_key_hex: &str,
    message_hex: &str,
    signature_hex: &str,
) -> Result<serde_json::Value, String> {
    let pk_bytes = decode_hex("public_key", public_key_hex, Some(PK_LEN))?;
    let msg = decode_hex("message", message_hex, None)?;
    let sig_bytes = decode_hex("signature", signature_hex, Some(SIG_LEN))?;

    let vk = VerifyingKey::<MlDsa44>::new_from_slice(&pk_bytes)
        .map_err(|_| "public_key: decode failed (wrong length)")?;
    let sig = Signature::<MlDsa44>::try_from(&sig_bytes[..])
        .map_err(|_| "signature: decode failed (wrong length)")?;

    let valid = vk.verify(&msg, &sig).is_ok();
    Ok(json!({
        "valid": valid,
        "message": hex::encode(&msg),
        "commitment": keccak(&pk_bytes)
    }))
}

fn cmd_commitment(public_key_hex: &str) -> Result<serde_json::Value, String> {
    let pk_bytes = decode_hex("public_key", public_key_hex, None)?;
    Ok(json!({
        "commitment": keccak(&pk_bytes),
        "length": pk_bytes.len()
    }))
}
