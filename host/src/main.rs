//! Faz 0 host: guest'i derlenmis ELF ile calistirir, kanit uretir, lokal dogrular.
//! Akis: execute (cycle sayisi) -> core prove (sure) -> local verify -> kaniti diske yaz.

use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const ELF: Elf = include_elf!("standhaft-guest");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let n = 1_000u32;
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    let client = ProverClient::from_env().await;

    // 1. Salt calistirma: dongu maliyetini olc.
    let (_, report) = client.execute(ELF, stdin.clone()).await.unwrap();
    println!(
        "[execute] cycles: {}",
        report.total_instruction_count()
    );

    // 2. Core proof uretimi (CPU) + sure.
    let pk = client.setup(ELF).await.unwrap();
    let start = std::time::Instant::now();
    let mut proof = client.prove(&pk, stdin.clone()).core().await.unwrap();
    println!("[prove] elapsed: {:?}", start.elapsed());

    // 3. Lokal dogrulama.
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("local verification failed");
    println!("[verify] OK");

    // 4. Kaniti diske yaz (on-chain dogrulama adimi icin).
    proof.save("proof-faz0.bin").expect("proof save failed");
    println!("[save] proof-faz0.bin yazildi");

    println!("FAZ0_PIPE_OK");
}
