# Architecture — Locked Decisions (v0.1)

Agreed with the founder. Any change to this document requires an explicit
decision, never silent drift.

## 1. Authority model

- **ECDSA authority matrix: EMPTY.** No operation — including key rotation —
  may ever be authorized by any ECDSA key. There is no wooden back door.
- Sole spend authority: an **ML-DSA-65 signature** over the operation,
  presented on-chain as a zkVM proof certificate.
- Deposits are permissionless; receiving requires no signature authority.

## 2. Signature scheme

- **ML-DSA-65** (FIPS 204; formerly Dilithium3), security level ~AES-192.
- Mandatory validation at every layer: FIPS 204 KAT vectors **and** a
  PQClean/PQClean-bindings cross-check. A result is "correct" only when all
  three agree (`ml-dsa` crate, PQClean, NIST vectors).

## 3. Account standard

- **ERC-4337** smart account based on audited eth-infinitism SimpleAccount.
- `validateUserOp` verifies the zk proof. Phase 0 measures real gas; design
  target ~250-300k, acceptable band defined in the roadmap go/kill gate.

## 4. Key custody

- Keys are generated on the user's device and live in a **browser extension**
  (isolated process), encrypted at rest, unlocked by passkey/passphrase.
- The web dashboard is **keyless by construction**: it composes and monitors
  operations; it cannot sign. Compromise of the web layer is phishing
  surface, not key compromise — the extension approval screen is the last line.
- The signer interface is abstract: extension / HSM / mobile attach to the
  same `signer-core`.

## 5. Prover trust model

- The prover **cannot forge** — proof validity is mathematical. It can only
  censor or delay (availability risk, not integrity risk).
- v1: hosted prover. v2 target: client-side proving inside the extension.

## 6. Rotation, guardians, timelocks

- Rotation is authorized by the **current PQ key OR a guardian threshold
  (2-of-3)**. This circularity is the design: whoever cannot sign cannot
  change the lock.
- Rotation and large transfers are **timelocked** (24-48h) with a visible
  cancel window; spending limits are configurable on-chain.
- Loss scenarios:
  - device lost, backup exists → restore + revoke old key;
  - key suspected → immediate rotation;
  - key actively abused → timelock + guardian race;
  - key and backup lost → guardians re-key.

## 7. Gas

- Paymaster model: the vault pays its own gas from an on-chain deposit.
  Users never need MetaMask or ETH outside the vault.

## 8. Engineering standard

- Production-grade from day 1. No demo-quality code, no "fix later".
- Every layer ships audit-ready: tests, threat model, documentation.
- Guest (zkVM) code is in audit scope — a guest bug equals signature forgery.

## 9. Product sequence

One core, three skins, strictly in order:
**institutional vault → Safe PQ module → consumer wallet.**
Later, sequenced (one at a time): multi-chain deployment, off-chain PQ
signing SDK (document/firmware).

## Key flow

```
SETUP (once)
  extension generates ML-DSA keypair on device
  -> encrypted at rest, passkey unlock
  -> user backs up once
  -> vault address derived (plain Ethereum address)

DEPOSIT (permissionless)
  any source (CEX / EOA / another contract) -> vault address

SPEND
  dashboard composes operation
  -> extension approval screen (human-readable summary)
  -> ML-DSA signature produced in RAM
  -> prover: signature + operation -> zk proof (off-chain)
  -> relayer submits proof + UserOp
  -> contract verifies proof (~250-300k gas) -> operation executes
  -> user sees: one approval screen

RECOVERY
  rotate (PQ sig or guardians) / timelock cancel / guardian re-key
```

## Open decisions

Tracked in [`roadmap.md`](roadmap.md) gates: zkVM selection (SP1 vs
RISC Zero, measured in Phase 0), backup format, timelock defaults,
chain sequencing, guardian UX defaults, project-facing naming of surfaces.
