# standhaft — architecture

## The one-sentence model

Kasa bedava, mühür paralı: the vault contract holds funds and only opens
for a valid ML-DSA proof; the relay/courier layer is permissionless.

## Roles

| Role | Who | Trust requirement |
|---|---|---|
| Vault (contract) | on-chain | none — code + math only |
| Relay (courier) | anyone (user's EOA, bundler, us) | none for custody; availability only |
| Prover (workshop) | us today; permissionless later | proof forgery is mathematically impossible |
| PQ key holder | user device | the ONLY secret that matters |

## Canonical message preimages (must match off-chain signers)

Single call:
```
msgHash = keccak256(abi.encode(
    block.chainid, address(vault), target, value, keccak256(data), nonce))
```
Batch:
```
hi       = keccak256(abi.encode(t_i, v_i, keccak256(d_i)))
callsHash= keccak256(abi.encodePacked(h0..hn))
msgHash  = keccak256(abi.encode(chainid, vault, callsHash, nonce))
```
ERC-4337 mode: the digest is `EntryPoint.getUserOpHash(userOp)` (EP v0.8 semantics,
includes chainid + EP address).

## Verification paths

1. **Direct (implemented)** — proof = `pk(1312) || sig(2420)`;
   adapter binds `keccak256(pk) == commitment`, then runs FIPS 204 verify
   (Skale MLDSA.sol, ACVP-tested, ~5.8M gas on local benchmarks).
2. **ZK (roadmap)** — proof = ZK statement "I know a valid ML-DSA signature by the key
   whose commitment is C over M". Signature AND public key never appear on-chain →
   zero HNDL paper trail. Fits ERC-4337 without protocol changes.

## Why hiding the PQ public key is optional-but-valuable

Unlike ECDSA, an exposed ML-DSA public key cannot be inverted into the private key —
not even by a quantum computer. Hiding it (ZK path) additionally kills
harvest-now-decrypt-later record-keeping and adds privacy; it is moat, not necessity.

## Invariants asserted by tests

- No state change without verifier-accepted proof (fuzz + invariant runner).
- `commitment` and `verifier` are immutable.
- Nonce is monotonic and bound inside every signed digest (replay-proof).
- Balance conservation across random deposits/executions (ghost accounting).
- Account: execute paths are EntryPoint-gated; prefund flows to EP.
- Paymaster: sponsor cap enforced; our custom error surfaces wrapped as AA33.

## Threat matrix (subset)

| Threat | Result |
|---|---|
| Quantum adversary harvests chain | only commitments + (direct path) PQ pk/sigs — no key derivation possible (lattice problem) |
| Relay/prover turns malicious | cannot forge proofs; worst case censorship (use another relay) |
| User's gas EOA broken by quantum | holds dust only; vault untouched |
| Contract admin compromise | no admin exists |
