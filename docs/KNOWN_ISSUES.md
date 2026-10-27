# standhaft — known issues & deliberate gaps

Status: **engine skeleton, fully tested (46/46 green), unaudited.**
Nothing here holds real funds until the audit gate below clears.

## Security / production gates

- [ ] **No third-party audit.** `Vault`, `StandhaftAccount`, `MldsaVerifier` must be
      audited before any mainnet value. `MockVerifier` and `PaymasterSkeleton` are
      explicitly NOT production code.
- [ ] **PaymasterSkeleton is accept-all** (only maxCost cap + EntryPoint deposit checks).
      Real sponsor policy (who, how much, quotas, refunds in postOp) is unwritten.
- [ ] **ML-DSA verify = full path (~5.8M gas)**. Skale's KeyFactory precompute fast-path
      (already vendored in lib/mldsa-solidity) can cut this substantially — wiring is TODO.
- [ ] **ZK path not wired.** `docs/ARCHITECTURE.md` describes the target (signature never
      on-chain). Today's direct path reveals the ML-DSA public key + signature in calldata —
      quantum-safe (no key derivation even for quantum attackers) but leaves an HNDL
      paper trail by design.
- [ ] **Key management UX is unwritten**: PQ secret key backup/recovery (32-byte seed via
      RustCrypto; hardware/passkey/social recovery later).
- [ ] **Forge `--ffi` live test absent**: static Rust fixture is embedded (Fixtures.sol);
      a live `cargo run` → sign → verify loop against Anvil is the next integration step.

## Known limitations

- `Vault.execute` reverts on target-call failure and does NOT advance nonce (deliberate:
  the operator may retry with the same proof). CallFailed bubbles target returndata.
- `Vault.executeBatch` is all-or-nothing (atomic). No per-call success mode yet.
- `StandhaftAccount` inherits BaseAccount execute/executeBatch (EntryPoint-gated) —
  no batch proof scheme beyond EP nonce management.
- Gas: Vault execute adds ~40k overhead on top of the verifier cost; measured in
  `test_gas_direct_verification` (5.77M on local solc 0.8.37 via_ir, subject to change).
- pq-verifier-interface & mldsa-solidity pinned at main/v1.0.0 (commit-pinned in lib/).
- account-abstraction pinned v0.8.0 (EntryPoint 0x4337084d9e255ff0702461cf8895ce9e3b5ff108
  is the canonical mainnet v0.8 address).
