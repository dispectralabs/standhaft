#!/usr/bin/env bash
# SP1 v6.9.0 direct install (bypass broken sp1up nightly channel)
set -uo pipefail

export PATH="/root/.cargo/bin:/root/.sp1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "=== 1. cargo-prove v6.9.0 indiriliyor ==="
curl -L -sS -o /tmp/cargo_prove.tar.gz \
  https://github.com/succinctlabs/sp1/releases/download/v6.9.0/cargo_prove_v6.9.0_linux_amd64.tar.gz \
  && echo "indirildi: $(du -h /tmp/cargo_prove.tar.gz | cut -f1)"

echo "=== 2. aciliyor ==="
mkdir -p /root/.sp1/bin
tar -xzC /root/.sp1/bin -f /tmp/cargo_prove.tar.gz && echo "tar OK"
ls -la /root/.sp1/bin

echo "=== 3. surum kontrolu ==="
cargo prove --version

echo "=== 4. RISC-V toolchain kuruluyor (buyuk indirme) ==="
cargo prove install-toolchain 2>&1 | tail -3

echo "=== 5. toolchain kontrolu ==="
/root/.cargo/bin/rustup toolchain list | grep -i succinct || echo "TOOLCHAIN_YOK"

echo "=== BITTI ==="
