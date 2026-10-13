# Roadmap

## Phase 0 — Feasibility PoC (weeks 1-2) — **current**

Goal: kill or confirm the single risky assumption — proving ML-DSA-65
verification inside a zkVM at acceptable cost. Everything else is downstream
of this answer.

Work:
1. SP1 pipeline proof: hello-world guest → proof → on-chain verify (anvil).
2. ML-DSA-65 in the guest: `ml-dsa` crate, validated against FIPS 204 KAT
   vectors and PQClean reference outputs (three-way agreement rule).
3. Measurements: prove time per signature, proof size, verification gas.
4. Go/kill report with numbers.

Exit criteria:
- **Go:** verification gas in the ~200-400k band AND prove time acceptable
  for interactive UX (seconds; kill-review above ~1-2 minutes).
- **Kill:** revise architecture (signature scheme / proof strategy); decision
  documented before any further build.

## Phase 1 — Core (weeks 3-8)

- ERC-4337 account: ZK-certified `validateUserOp`, rotation, guardians,
  timelocks, spending limits.
- Prover service (API) with availability commitments.
- `signer-core` Rust crate (abstract signer interface).
- Audit-ready discipline: test suites, threat model docs, CI.

## Phase 2 — Product surface (weeks 6-12, overlaps Phase 1)

- Browser extension: encrypted key store, approval UX (Chromium first).
- Web dashboard: portfolio, operation composer, policy management,
  timelock queue, read-only inspector.
- Paymaster / relayer.

## Phase 3 — Hardening & GTM (continuous)

- External audit — contracts **and** guest code in scope.
- Testnet beta → mainnet.
- Parallel: EF academic grant, TÜBİTAK, public pilot applications.

## Sequenced doors (post-core, one at a time)

1. Safe PQ module
2. Multi-chain deployment (L2s — same verifier)
3. Consumer wallet skin
4. Off-chain PQ signing SDK (document/firmware)

## Gate discipline

No phase starts before the previous gate's exit criteria are met and the
report is reviewed. The founder approves every phase transition.
