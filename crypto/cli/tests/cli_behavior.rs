//! audit2 — behavioral tests for the standhaft-cli BINARY (black-box, via CARGO_BIN_EXE).
//!
//! Complements tests/roundtrip.rs (library-level FIPS 204 semantics) by exercising the
//! actual CLI surface: determinism, hex parsing edge cases, length validation, exit
//! codes, and the seed-as-secret_key convention. All assertions are documented
//! behaviors of crypto/cli/src/main.rs as audited on 2026-10-28.

use std::process::{Command, Output};

const CLI: &str = env!("CARGO_BIN_EXE_standhaft-cli");

/// Seed produced by `standhaft-cli keygen` during the audit session.
/// Same seed as the fresh vectors embedded in test/audit2/Audit2Fixtures.sol.
const SEED: &str = "a010dd8d487b52c4acc230a14c5bde24fe5e2051fba7d776972195f49864587a";
/// The commitment of the key derived from SEED as reported by the CLI and asserted
/// equal to keccak256(PK) inside
/// test/audit2/FreshVectorAudit.t.sol::test_commitment_cli_equals_solidity_keccak256.
const CMT: &str = "57d8782a147423d513be111b7be7c517c0fbb71333bac624d2f2f25aba3e56ff";

fn run(args: &[&str]) -> Output {
    Command::new(CLI).args(args).output().expect("spawn cli")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json_field(out: &Output, field: &str) -> String {
    // minimal extraction: "field": "value"
    let s = stdout(out);
    let pat = format!("\"{field}\": \"");
    let start = s.find(&pat).expect("field present") + pat.len();
    let end = s[start..].find('"').expect("closing quote") + start;
    s[start..end].to_string()
}

/// NOTE: PK above was hand-truncated for brevity; reconstruct the real one from the
/// CLI itself so tests never depend on a mis-transcribed constant.
fn real_pk() -> String {
    let msg = [0x11u8; 32];
    let out = run(&["sign", "--secret-key", SEED, "--message", &hex(msg)]);
    assert!(out.status.success());
    json_field(&out, "public_key")
}

fn hex(b: [u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[test]
fn signing_is_deterministic_same_seed_same_message() {
    let msg = [0xA7u8; 32];
    let m = hex(msg);
    let a = run(&["sign", "--secret-key", SEED, "--message", &m]);
    let b = run(&["sign", "--secret-key", SEED, "--message", &m]);
    assert!(a.status.success() && b.status.success());
    assert_eq!(
        stdout(&a),
        stdout(&b),
        "same seed + message must give identical output"
    );
}

#[test]
fn sign_0x_prefix_is_equivalent_to_bare_hex() {
    let msg = [0x33u8; 32];
    let m = hex(msg);
    let a = run(&["sign", "--secret-key", SEED, "--message", &m]);
    let b = run(&[
        "sign",
        "--secret-key",
        &format!("0x{SEED}"),
        "--message",
        &format!("0x{m}"),
    ]);
    assert_eq!(stdout(&a), stdout(&b), "0x prefix must not change results");
}

#[test]
fn uppercase_0X_prefix_is_accepted_like_lowercase() {
    // REMEDIATED (audit2 A2-07): the "0X" prefix is now stripped case-insensitively,
    // matching `cast`-style input expectations. Clean success, never a panic.
    let msg = [0x44u8; 32];
    let m = hex(msg);
    let out = run(&[
        "sign",
        "--secret-key",
        &format!("0X{SEED}"),
        "--message",
        &m,
    ]);
    assert!(out.status.success(), "got: {}", stderr(&out));
    assert!(stdout(&out).contains("\"valid\"") || stdout(&out).contains("signature"));
}

#[test]
fn odd_length_hex_is_rejected_gracefully() {
    let out = run(&["sign", "--secret-key", &SEED[..63], "--message", "abcd"]);
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("invalid hex"));
}

#[test]
fn empty_secret_key_is_length_error_not_panic() {
    let msg = [0x00u8; 32];
    let out = run(&["sign", "--secret-key", "", "--message", &hex(msg)]);
    assert!(!out.status.success());
    let e = stderr(&out);
    assert!(e.contains("expected 32 bytes, got 0"), "got: {e}");
}

#[test]
fn wrong_length_secret_key_is_length_error() {
    let msg = [0x01u8; 32];
    let out = run(&["sign", "--secret-key", "aabb", "--message", &hex(msg)]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected 32 bytes, got 2"));
}

#[test]
fn verify_rejects_wrong_length_public_key_gracefully() {
    let msg = [0x02u8; 32];
    let out = run(&[
        "verify",
        "--public-key",
        "aabb",
        "--message",
        &hex(msg),
        "--signature",
        &"ab".repeat(2420),
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected 1312 bytes, got 2"));
}

#[test]
fn verify_rejects_wrong_length_signature_gracefully() {
    let msg = [0x03u8; 32];
    let pk = real_pk();
    let out = run(&[
        "verify",
        "--public-key",
        &pk,
        "--message",
        &hex(msg),
        "--signature",
        "deadbeef",
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("expected 2420 bytes, got 4"));
}

#[test]
fn verify_invalid_but_wellformed_signature_exits_2_with_valid_false_json() {
    // REMEDIATED (audit2 A2-01): a signature that DECODES fine but fails FIPS 204
    // verification now exits 2, so `standhaft verify … && relay` gates correctly.
    // The JSON "valid" field is still printed on stdout for programmatic use.
    let msg = [0x04u8; 32];
    let m = hex(msg);
    let good = run(&["sign", "--secret-key", SEED, "--message", &m]);
    let sig = json_field(&good, "signature");
    let pk = real_pk();

    // flip one byte of the signature — still a well-formed encoding, wrong math
    let mut raw = hex::decode(&sig).expect("sig hex");
    raw[10] ^= 0x40;
    let bad_sig: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let out = run(&[
        "verify",
        "--public-key",
        &pk,
        "--message",
        &m,
        "--signature",
        &bad_sig,
    ]);
    assert_eq!(out.status.code(), Some(2), "invalid signature exits 2");
    assert!(stdout(&out).contains("\"valid\": false"));
}

#[test]
fn verify_structurally_malformed_signature_errors_out_instead() {
    // Contrast with the test above: a 2420-byte blob that fails signature DECODE
    // (e.g. all-zero blob) is a hard error (exit 1), not valid:false.
    let msg = [0x05u8; 32];
    let pk = real_pk();
    let zeros = "00".repeat(2420);
    let out = run(&[
        "verify",
        "--public-key",
        &pk,
        "--message",
        &hex(msg),
        "--signature",
        &zeros,
    ]);
    assert!(
        !out.status.success(),
        "structurally invalid signature is a hard error"
    );
    assert!(
        stderr(&out).contains("signature: decode failed"),
        "got: {}",
        stderr(&out)
    );
}

#[test]
fn commitment_subcommand_agrees_with_keccak_and_solidity_constant() {
    let pk = real_pk();
    // The full PK must equal the one embedded in the Solidity fixtures
    // (test/audit2/Audit2Fixtures.sol::PK) — same seed, same crate determinism.
    let cmt_out = run(&["commitment", "--public-key", &pk]);
    let cmt = json_field(&cmt_out, "commitment");
    assert_eq!(
        cmt, CMT,
        "CLI commitment must equal the audit-fixed commitment constant"
    );

    // Independent keccak256 via the sha3 crate (same primitive the Solidity side uses
    // via keccak256 opcode) — catches any transcription error.
    use sha3::{Digest, Keccak256};
    let pk_bytes = hex::decode(&pk).expect("pk hex");
    let mut h = Keccak256::new();
    h.update(&pk_bytes);
    assert_eq!(hex::encode(h.finalize()), CMT);
}

#[test]
fn sign_accepts_non_32_byte_messages_documents_laxness() {
    // DOCUMENTED (audit2): the CLI signs ANY byte length. A user who passes the raw
    // preimage (e.g. the 6-word abi.encode blob) instead of its 32-byte digest gets a
    // signature the vault will REJECT — silently, at sign time. No warning today.
    let out = run(&["sign", "--secret-key", SEED, "--message", "aabbcc"]);
    assert!(
        out.status.success(),
        "signing 3 bytes succeeds (no length convention enforced)"
    );
    let out_empty = run(&["sign", "--secret-key", SEED, "--message", ""]);
    assert!(
        out_empty.status.success(),
        "signing the EMPTY message also succeeds"
    );
}

#[test]
fn whitespace_around_hex_is_tolerated() {
    let msg = [0x55u8; 32];
    let padded = format!("  {}  ", hex(msg));
    let a = run(&["sign", "--secret-key", SEED, "--message", &padded]);
    let b = run(&["sign", "--secret-key", SEED, "--message", &hex(msg)]);
    assert!(a.status.success());
    assert_eq!(
        stdout(&a),
        stdout(&b),
        "trim() should make padded input equivalent"
    );
}

#[test]
fn keygen_shapes_and_commitment_self_consistency() {
    let out = run(&["keygen"]);
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("ML-DSA-44"));
    assert!(
        s.contains("32-byte seed"),
        "must keep the secret_key_note disambiguation"
    );
    let seed = json_field(&out, "secret_key");
    let pk = json_field(&out, "public_key");
    let cmt = json_field(&out, "commitment");
    assert_eq!(
        seed.len(),
        64,
        "secret_key is the 32-byte SEED, not the 2560-byte FIPS 204 sk"
    );
    assert_eq!(pk.len(), 1312 * 2);
    assert_eq!(hex::decode(&seed).expect("seed hex").len(), 32);
    assert_eq!(hex::decode(&pk).expect("pk hex").len(), 1312);

    // commitment self-consistency: keccak(pk) via the commitment subcommand
    let cmt2_out = run(&["commitment", "--public-key", &pk]);
    assert_eq!(json_field(&cmt2_out, "commitment"), cmt);
}
