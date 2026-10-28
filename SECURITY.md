# Security Policy

**Status: pre-audit, private development. Nothing in this repository is safe
to deploy.**

## Scope

`contracts/`, `guest/`, `crates/` (as they come into existence). Guest (zkVM)
code is first-class audit scope: a guest implementation bug equals signature
forgery capability.

## Reporting

- Contact: `security@dispectra.cloud` (PGP key published before any beta).
- Coordinated disclosure; researchers credited after the audit cycle.

## Hard rules enforced by design

1. ECDSA authority matrix is empty — no ECDSA key can authorize anything,
   including rotation.
2. Private keys never leave the client. The hosted prover receives
   signatures, never keys, and cannot forge.
3. Rotation and large transfers are timelocked with cancel windows.
4. Validation correctness requires three-way agreement: implementation,
   PQClean reference, FIPS 204 KAT vectors.

## Threat model

See [`docs/architecture.md`](docs/architecture.md) §5 (prover trust),
§6 (rotation/guardians/timelocks) and §4 (key custody). The full threat
model document is a Phase 1 deliverable and a precondition for audit.
