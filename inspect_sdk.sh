#!/usr/bin/env bash
# sp1-sdk 6.9.0 kaynak incelemesi: ProverClient nerede, hangi feature'da?
set -u
D="/root/.cargo/registry/src"
R="$(ls -d $D/*/sp1-sdk-6.9.0 2>/dev/null | head -1)"
echo "DIR: $R"
if [ -z "$R" ]; then echo "KAYNAK BULUNAMADI"; exit 1; fi
echo "=== lib.rs pub exports ==="
grep -n "pub use\|pub mod" "$R/src/lib.rs" | head -40
echo "=== prelude ==="
cat "$R/src/prelude.rs" 2>/dev/null | head -40
echo "=== features ==="
sed -n '/\[features\]/,/^\[/p' "$R/Cargo.toml" | head -30
