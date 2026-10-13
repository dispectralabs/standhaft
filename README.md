# Standhaft

**The steadfast vault.** A post-quantum smart-account wallet for Ethereum.

Standhaft is an ERC-4337 account whose spend authority is a NIST-standardized
post-quantum signature (**ML-DSA-65**, FIPS 204), verified on-chain via a
succinct zkVM proof. **ECDSA has zero authority over the account.**
Ethereum itself remains unchanged.

> **Status: Phase 0 — feasibility PoC.** Nothing in this repository is
> production-ready. Do not deploy anything.

## Why

Every ECDSA public key revealed on-chain today is a key that a future
cryptographically-relevant quantum computer can forge signatures for.
Funds controlled by EOAs and ECDSA multisigs are exposed retroactively.
Standhaft moves custody behind a lock quantum cannot break — without
waiting for an Ethereum protocol change.

## Architecture (locked)

| Component | Decision |
|---|---|
| Spend authority | ML-DSA-65 signature only (ECDSA authority matrix: empty) |
| On-chain verification | zkVM proof inside ERC-4337 `validateUserOp` (target ~250-300k gas) |
| Account base | Audited eth-infinitism SimpleAccount |
| Key custody | Browser extension, isolated process, encrypted, passkey-unlock. Keys never leave the client |
| Dashboard | Keyless web app — composes operations, cannot sign |
| Rotation | Current PQ key OR guardian threshold (2/3); timelocked |
| Gas | Paymaster model; the vault pays its own gas |
| Standard | Production-grade from day 1; audit-ready layers only |

Details: [`docs/architecture.md`](docs/architecture.md).

## Repository layout

```
docs/                 charter, architecture, roadmap, security
guest/                (Phase 0) zkVM guest program: ML-DSA-65 verification
host/                 (Phase 0) proof host, benchmarks, go/kill report
contracts/            (Phase 1) 4337 account + proof verifier
crates/signer-core/   (Phase 1) abstract signer interface (extension/HSM/mobile)
app/                  (Phase 2) web dashboard (keyless)
ext/                  (Phase 2) browser extension (key holder)
```

## Roadmap

Phase 0 (now): prove or kill ML-DSA-65-in-zkVM. See
[`docs/roadmap.md`](docs/roadmap.md) for phases and go/kill criteria.

## Security

Pre-audit, private development. See [`SECURITY.md`](SECURITY.md).

## License

All rights reserved until public release. License decided before any public artifact.
