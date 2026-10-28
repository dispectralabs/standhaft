#!/usr/bin/env bash
# Standhaft Faz 0 - kutu bootstrap'i (Ubuntu 24.04, root olarak calistir)
# Kullanim: bash vm_bootstrap.sh
# Bugun (2026-10-13) WSL'de tek tek yasadigimiz tum puruzlerin otomatik hali.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH="/root/.cargo/bin:/root/.sp1/bin:/root/.foundry/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "=== 1/6 apt paketleri ==="
apt-get update -qq
apt-get install -y -qq build-essential curl git pkg-config libssl-dev \
  protobuf-compiler libclang-dev clang golang-go jq

echo "=== 2/6 Rust (yoksa) ==="
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
cargo --version

echo "=== 3/6 SP1 v6.9.0 (sp1up atlanir: nightly kanali bozuk) ==="
mkdir -p /root/.sp1/bin
curl -L -sS -o /tmp/cargo_prove.tar.gz \
  https://github.com/succinctlabs/sp1/releases/download/v6.9.0/cargo_prove_v6.9.0_linux_amd64.tar.gz
tar -xzC /root/.sp1/bin -f /tmp/cargo_prove.tar.gz

echo "=== 4/6 RISC-V toolchain ==="
cargo prove install-toolchain

echo "=== 5/6 Foundry (anvil/forge) ==="
curl -L https://foundry.paradigm.xyz | bash >/dev/null 2>&1
foundryup

echo "=== 6/6 silinen gnark reposu icin fork redirect ==="
git config --global url."https://github.com/polytope-labs/gnark-ignition-verifier".insteadOf \
  "https://github.com/consensys/gnark-ignition-verifier"

echo "=== DOGRULAMA ==="
cargo prove --version
anvil --version | head -1
go version
protoc --version
echo "BOOTSTRAP_OK"
