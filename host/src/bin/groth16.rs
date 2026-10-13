//! Faz 0 - zincir ustu asamasi: groth16 sarmali kanit uretir,
//! proof/public_values/vkey hash'ini hex dosya olarak yazar.
//! Kontrat tarafi bu dosyalari anvil'de SP1Verifier'a verip gas olcecek.

use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const ELF: Elf = include_elf!("standhaft-guest");

fn to_hex_file(path: &str, bytes: &[u8]) {
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    std::fs::write(path, hex).expect("hex yazilamadi");
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let n = 1_000u32;
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    let client = ProverClient::from_env().await;
    let pk = client.setup(ELF).await.unwrap();

    println!("[groth16] sarma basliyor...");
    let start = std::time::Instant::now();
    let proof = client.prove(&pk, stdin).groth16().await.unwrap();
    println!("[groth16] elapsed: {:?}", start.elapsed());

    let vk_hash: String = pk.verifying_key().bytes32();
    to_hex_file("groth16_proof.hex", &proof.bytes());
    to_hex_file("groth16_public_values.hex", &proof.public_values.to_vec());
    std::fs::write("groth16_vkey_hash.hex", &vk_hash).expect("vkey yazilamadi");

    println!("[save] groth16_proof.hex / groth16_public_values.hex / groth16_vkey_hash.hex");
    println!("FAZ0_GROTH16_OK");
}
