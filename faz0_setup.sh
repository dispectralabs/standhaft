#!/usr/bin/env bash
# Faz 0 setup inside WSL Ubuntu (run as root)
# Installs: SP1 toolchain (cargo-prove + RISC-V) and Foundry (anvil)
set -uo pipefail

export PATH="/root/.cargo/bin:/root/.sp1/bin:/root/.foundry/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "=== 0. Rust durumu ==="
cargo --version || exit 1

echo "=== 1. SP1 installer calisiyor ==="
curl -L https://sp1.succinct.xyz/sp1up | bash
SP1_EXIT=$?
echo "sp1up exit: $SP1_EXIT"

echo "=== 2. cargo-prove dogrulama ==="
/root/.sp1/bin/cargo-prove --version || echo "CARGO_PROVE_YOK"

echo "=== 3. Foundry kurulumu ==="
curl -L https://foundry.paradigm.xyz | bash
/root/.foundry/bin/foundryup
anvil --version | head -1 || echo "ANVIL_YOK"

echo "=== BITTI ==="
