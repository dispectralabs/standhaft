#!/usr/bin/env bash
# groth16 run + log + mem izleme
set -u
export PATH="/root/.cargo/bin:/root/.sp1/bin:/root/.foundry/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
cd /mnt/c/Users/sedat/Desktop/Workspace/standhaft/host
echo "=== RAM durum ==="
free -h | sed -n '2p'
echo "=== RUN BASLANGIC: $(date) ==="
cargo run --release --bin groth16 > /tmp/groth16_run.log 2>&1
echo "exit code: $?"
echo "=== LOG SONU ==="
tail -15 /tmp/groth16_run.log
echo "=== RAM bitis ==="
free -h | sed -n '2p'
