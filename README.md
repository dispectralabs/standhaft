# standhaft — post-quantum vault engine

**The safe whose lock is never on-chain.**

ERC-4337 / EIP-7702-era smart accounts secured by NIST post-quantum
signatures (ML-DSA-44, FIPS 204) instead of ECDSA — quantum computers
cannot derive the signing key, even from exposed material.

## Architecture

```
          Ahmet's device                       relay (anyone)
  ┌──────────────────────────┐
  │ PQ key (never leaves)    │   imza      ┌──────────┐  kanıt   ┌──────────┐
  │ ML-DSA-44 (FIPS 204)     │ ──────────► │ prover / │ ───────► │ EntryPoint│
  └──────────────────────────┘             │  CLI     │          │  v0.8    │
                                           └──────────┘          └────┬─────┘
                                                                       │ validateUserOp
                                                                       ▼
                                             ┌─────────────────────────────────┐
                                             │ StandhaftAccount / Vault        │
                                             │ stores: keccak256(PQ pubkey)    │
                                             │ checks: IVaultVerifier proof    │
                                             │ moves:  funds → target          │
                                             └─────────────────────────────────┘
```

- The chain only ever sees `keccak256(PQ_public_key)` (commitment) plus a proof.
- No admin, no upgrade, no owner key: **only a valid PQ proof moves funds**.
- Relaying is permissionless — proof, not caller, is the authorization.

## Components

| Path | What |
|---|---|
| `src/engine/Vault.sol` | Direct-mode safe: commitment + nonce + execute/executeBatch |
| `src/engine/VaultFactory.sol` | CREATE2 counterfactual vaults |
| `src/ep/StandhaftAccount.sol` | ERC-4337 v0.8 account (`validateUserOp` → proof) |
| `src/ep/PaymasterSkeleton.sol` | Gas sponsorship skeleton (cap enforced; policy TODO) |
| `src/verifier/MldsaVerifier.sol` | ML-DSA-44 adapter (Skale FIPS 204 core, ACVP-tested) |
| `src/verifier/MockVerifier.sol` | Fast test double |
| `crypto/cli/` | Rust CLI: `keygen` / `sign` / `verify` (RustCrypto ml-dsa) |

## Run tests

```bash
forge test            # 46 tests: unit + e2e + fuzz + invariants
forge test --match-test test_real_rust_signature_verifies_onchain -vv
                      # cross-language: Rust-signed → Solidity-verified
cargo test --manifest-path crypto/Cargo.toml   # 6 tests: FIPS 204 semantics
```

## Generate a key & signature (CLI)

```bash
cargo run --manifest-path crypto/Cargo.toml -- keygen > keys.json
cargo run --manifest-path crypto/Cargo.toml -- \
  sign --secret-key <seed-hex> --message <msgHash-hex> > sig.json
```

## Deploy

```bash
forge script script/Deploy.s.sol --broadcast --rpc-url $RPC
```

## Docs

- `docs/ARCHITECTURE.md` — full flow, message preimages, ZK roadmap
- `docs/KNOWN_ISSUES.md` — honest list of what is missing before audit/mainnet

## Status

46/46 forge tests green · 6/6 cargo tests green · **unaudited — no mainnet value yet**
