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
//!
//! Exit codes:
//!   0  success (for `verify`: signature valid)
//!   1  hard error (malformed input, I/O)
//!   2  `verify`: well-formed signature that FAILS verification (`"valid": false`
//!      is still printed on stdout) — so `standhaft verify … && relay` gates safely
//!      (audit2 finding A2-01).

use clap::{Parser, Subcommand};
use ml_dsa::{
    Generate, KeyExport, KeyInit, Keypair, MlDsa44, Signature, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::io::Read as _;
use std::path::PathBuf;
use zeroize::Zeroize;

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
    /// NOTE: the secret seed is printed in plaintext stdout — store encrypted.
    Keygen,
    /// Sign a message (hex). Pass the 32-byte msgHash the vault will verify.
    Sign {
        /// Secret key seed (hex, 32 bytes). [DEPRECATED input path: argv seeds are
        /// visible in `ps` output and shell history — prefer --secret-key-stdin or
        /// --secret-key-file]
        #[arg(long, conflicts_with_all = ["secret_key_stdin", "secret_key_file"])]
        secret_key: Option<String>,
        /// Read the seed (hex) from stdin instead of argv.
        #[arg(long, conflicts_with_all = ["secret_key", "secret_key_file"])]
        secret_key_stdin: bool,
        /// Read the seed (hex) from a file (keep the file mode 0600).
        #[arg(long, conflicts_with_all = ["secret_key", "secret_key_stdin"])]
        secret_key_file: Option<PathBuf>,
        #[arg(long, help = "message to sign (hex); 32-byte digest recommended")]
        message: String,
    },
    /// Verify signature (hex) against public key (hex) and message (hex).
    /// Prints JSON { valid: true|false }.
    /// Exit code 0 = valid; exit code 2 = well-formed but INVALID.
    /// Exit code 1 = hard error (malformed input).
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
        Cmd::Sign {
            secret_key,
            secret_key_stdin,
            secret_key_file,
            message,
        } => resolve_secret(secret_key, secret_key_stdin, secret_key_file.as_deref())
            .and_then(|seed_hex| cmd_sign(&seed_hex, &message)),
        Cmd::Verify {
            public_key,
            message,
            signature,
        } => cmd_verify(&public_key, &message, &signature),
        Cmd::Commitment { public_key } => cmd_commitment(&public_key),
    };
    match result {
        Ok((out, code)) => {
            println!("{}", serde_json::to_string_pretty(&out).expect("json"));
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Resolves the signing seed from exactly one source (audit2 finding A2-02:
/// argv seeds leak via `ps` and shell history — stdin/file are the safe paths).
fn resolve_secret(
    argv: Option<String>,
    use_stdin: bool,
    file: Option<&std::path::Path>,
) -> Result<String, String> {
    let provided =
        usize::from(argv.is_some()) + usize::from(use_stdin) + usize::from(file.is_some());
    if provided > 1 {
        return Err(
            "provide only ONE of --secret-key / --secret-key-stdin / --secret-key-file".into(),
        );
    }
    if use_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        return Ok(buf);
    }
    if let Some(path) = file {
        return std::fs::read_to_string(path).map_err(|e| format!("secret-key-file: {e}"));
    }
    if let Some(s) = argv {
        eprintln!(
            "warning: seed passed via argv — it is visible in `ps` output and shell history; \
             prefer --secret-key-stdin or --secret-key-file"
        );
        return Ok(s);
    }
    Err("no secret key source: use --secret-key-stdin or --secret-key-file (argv form is deprecated)".into())
}

fn decode_hex(label: &str, s: &str, expect: Option<usize>) -> Result<Vec<u8>, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    let v = hex::decode(t).map_err(|e| format!("{label}: invalid hex: {e}"))?;
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

fn cmd_keygen() -> Result<(serde_json::Value, i32), String> {
    eprintln!(
        "note: the secret seed appears in the JSON output — store it encrypted and never share it"
    );
    let sk = SigningKey::<MlDsa44>::generate();
    let vk = sk.verifying_key();

    let seed = sk.to_bytes(); // KeyExport -> Seed ([u8; 32])
    let pk = vk.encode(); // EncodedVerifyingKey ([u8; 1312])
    debug_assert_eq!(seed.as_slice().len(), SEED_LEN);
    debug_assert_eq!(pk.as_slice().len(), PK_LEN);

    Ok((
        json!({
            "algorithm": "ML-DSA-44",
            "public_key": hex::encode(pk.as_slice()),
            "secret_key": hex::encode(seed.as_slice()),
            "secret_key_note": "32-byte seed; expands to FIPS 204 sk",
            "commitment": keccak(pk.as_slice()),
            "sizes": { "public_key": pk.as_slice().len(), "secret_seed": seed.as_slice().len() }
        }),
        0,
    ))
}

fn cmd_sign(seed_hex: &str, message_hex: &str) -> Result<(serde_json::Value, i32), String> {
    let mut seed_bytes = decode_hex("secret_key", seed_hex, Some(SEED_LEN))?;
    let msg = decode_hex("message", message_hex, None)?;
    if msg.len() != 32 {
        eprintln!(
            "note: message is {} bytes — vault digests are 32 bytes; this signature \
             will only verify on-chain if the digest was 32 bytes",
            msg.len()
        );
    }

    let sk = SigningKey::<MlDsa44>::new_from_slice(&seed_bytes)
        .map_err(|_| "secret_key: decode failed (wrong length)")?;
    seed_bytes.zeroize(); // audit2 A2-02: wipe the decoded seed copy after use
    let vk = sk.verifying_key();

    let sig = sk.sign(&msg); // Signer trait (deterministic)
    let sig_enc = sig.encode();
    debug_assert_eq!(sig_enc.as_slice().len(), SIG_LEN);

    let pk = vk.encode();
    Ok((
        json!({
            "message": hex::encode(&msg),
            "signature": hex::encode(sig_enc.as_slice()),
            "public_key": hex::encode(pk.as_slice()),
            "commitment": keccak(pk.as_slice())
        }),
        0,
    ))
}

fn cmd_verify(
    public_key_hex: &str,
    message_hex: &str,
    signature_hex: &str,
) -> Result<(serde_json::Value, i32), String> {
    let pk_bytes = decode_hex("public_key", public_key_hex, Some(PK_LEN))?;
    let msg = decode_hex("message", message_hex, None)?;
    let sig_bytes = decode_hex("signature", signature_hex, Some(SIG_LEN))?;

    let vk = VerifyingKey::<MlDsa44>::new_from_slice(&pk_bytes)
        .map_err(|_| "public_key: decode failed (wrong length)")?;
    let sig = Signature::<MlDsa44>::try_from(&sig_bytes[..])
        .map_err(|_| "signature: decode failed (wrong length)")?;

    let valid = vk.verify(&msg, &sig).is_ok();
    let code = i32::from(!valid) * 2; // audit2 A2-01: non-zero exit on invalid
    Ok((
        json!({
            "valid": valid,
            "message": hex::encode(&msg),
            "commitment": keccak(&pk_bytes)
        }),
        code,
    ))
}

fn cmd_commitment(public_key_hex: &str) -> Result<(serde_json::Value, i32), String> {
    let pk_bytes = decode_hex("public_key", public_key_hex, None)?;
    Ok((
        json!({
            "commitment": keccak(&pk_bytes),
            "length": pk_bytes.len()
        }),
        0,
    ))
}
