//! standhaft host — generates zk proofs for ML-DSA-44 signatures (SP1 v6.9).
//!
//! Flow: CLI signature artifacts (from standhaft-cli) → SP1Stdin → guest verifies
//! the ML-DSA-44 signature inside the zkVM → proof commits (commitment, msgHash).
//!
//! Modes:
//!   execute  — run the guest, report cycle count (no proof)
//!   core     — STARK core proof + local verification (fastest proof)
//!   groth16  — Groth16-wrapped proof, bytes ready for an on-chain SP1 verifier
//!
//! Artifacts written to --out-dir:
//!   zk_proof.bin         proof bytes (on-chain SP1Verifier input)
//!   zk_public_values.bin committed values: commitment(32) || msgHash(32)
//!   zk_vkey.bin          SP1 verifying key bytes (pin keccak256(this) on-chain)
//!   zk_report.json       summary

use clap::Parser;
use serde_json::json;
use sha3::{Digest, Keccak256};
use sp1_sdk::prelude::*;
use sp1_sdk::{HashableKey, ProverClient};

const ELF: Elf = include_elf!("standhaft-guest");

#[derive(Parser)]
#[command(name = "standhaft-prover", about = "SP1 prover for ML-DSA-44 vault proofs")]
struct Args {
    /// proof mode: execute | core | groth16
    #[arg(long, default_value = "core")]
    mode: String,
    /// ML-DSA-44 public key (hex, 1312 bytes)
    #[arg(long)]
    pk: String,
    /// message digest that was signed (hex, 32 bytes) — the vault's msgHash
    #[arg(long)]
    msg: String,
    /// ML-DSA-44 signature (hex, 2420 bytes)
    #[arg(long)]
    sig: String,
    /// output directory
    #[arg(long, default_value = "zk-artifacts")]
    out_dir: String,
}

fn strip0x(s: &str) -> String {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    t.to_string()
}

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    sp1_sdk::utils::setup_logger();

    let pk = hex::decode(strip0x(&args.pk)).expect("pk hex");
    let msg = hex::decode(strip0x(&args.msg)).expect("msg hex");
    let sig = hex::decode(strip0x(&args.sig)).expect("sig hex");
    assert_eq!(pk.len(), 1312, "pk must be 1312 bytes (ML-DSA-44)");
    assert_eq!(msg.len(), 32, "msg must be 32 bytes");
    assert_eq!(sig.len(), 2420, "sig must be 2420 bytes (ML-DSA-44)");

    let commitment = keccak(&pk);

    let msg_arr: [u8; 32] = msg.clone().try_into().expect("msg must be 32 bytes");
    let mut stdin = SP1Stdin::new();
    stdin.write(&pk);
    stdin.write(&msg_arr);
    stdin.write(&sig);
    stdin.write(&commitment);
    stdin.write(&pk);
    stdin.write(&msg);
    stdin.write(&sig);
    stdin.write(&commitment);

    let client = ProverClient::from_env().await;
    std::fs::create_dir_all(&args.out_dir).expect("mkdir");

    match args.mode.as_str() {
        "execute" => {
            let (_, report) = client.execute(ELF, stdin).await.unwrap();
            println!(
                "[execute] cycles: {}",
                report.total_instruction_count()
            );
            let out = json!({
                "mode": "execute",
                "cycles": report.total_instruction_count(),
                "commitment": hex::encode(commitment),
            });
            std::fs::write(format!("{}/zk_report.json", args.out_dir),
                serde_json::to_string_pretty(&out).unwrap()).unwrap();
        }
        "core" | "groth16" => {
            let pkey = client.setup(ELF).await.unwrap();
            let vk = pkey.verifying_key();
            let start = std::time::Instant::now();
            let mut proof = if args.mode == "core" {
                client.prove(&pkey, stdin).core().await.unwrap()
            } else {
                client.prove(&pkey, stdin).groth16().await.unwrap()
            };
            println!("[prove] elapsed: {:?}", start.elapsed());

            client
                .verify(&proof, pkey.verifying_key(), None)
                .expect("local verification failed");
            println!("[verify] OK (local)");

            let pv = proof.public_values.to_vec();
            // SP1 v6 publicValues = committed(64B) || exit_code(4B) || end_pc(4B) = 72B
            assert_eq!(pv.len(), 64, "public values = commitment(32) || msgHash(32)");
            assert_eq!(&pv[..32], &commitment, "committed commitment mismatch");
            assert_eq!(&pv[32..64], &msg, "committed msgHash mismatch");

            let vk_digest: [u8; 32] = vk.bytes32_raw();
            let vk_bytes = vk_digest.to_vec();
            let vkey_digest = vk_digest;

            std::fs::write(format!("{}/zk_proof.bin", args.out_dir), proof.bytes()).unwrap();
            std::fs::write(format!("{}/zk_public_values.bin", args.out_dir), &pv).unwrap();
            std::fs::write(format!("{}/zk_vkey.bin", args.out_dir), &vk_bytes).unwrap();

            println!("[vk-prefix] 0x{}", hex::encode(&proof.bytes()[..4]));
            println!(
                "[artifacts] proof: {} B | publicValues: {} B | vkey: {} B",
                proof.bytes().len(), pv.len(), vk_bytes.len()
            );
            println!(
                "[pin] keccak256(vkey) = {} ← deploy ZKVerifier with this",
                hex::encode(vkey_digest)
            );

            let out = json!({
                "mode": args.mode,
                "proof_bytes": proof.bytes().len(),
                "public_values": hex::encode(&pv),
                "vkey_digest": hex::encode(vkey_digest),
                "commitment": hex::encode(commitment),
                "elapsed": format!("{:?}", start.elapsed()),
            });
            std::fs::write(format!("{}/zk_report.json", args.out_dir),
                serde_json::to_string_pretty(&out).unwrap()).unwrap();
        }
        m => panic!("unknown mode: {m}"),
    }
}
