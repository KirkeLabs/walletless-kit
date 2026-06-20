# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/);
versioning: [SemVer](https://semver.org/).

## [0.2.0] — 2026-06-20

Verifiable-trust release: make every result independently checkable against a
published spec, and close the draw-fairness gap with real drand verification.
Backwards-compatible — all 0.1.0 APIs are unchanged; everything below is additive.

### Added

- **Independent, zero-dependency verifier** (`@kirkelabs/walletless-kit/verify`) —
  `verifyDrawProof`, `verifyBundle`, `bundleProof`. Re-derives a draw / receipt
  chain / trail from scratch with only `node:crypto`, so a result can be checked
  without trusting the producing code (runs in a browser / offline). `bundleProof`
  packs a draw + entries + seed source + receipts + trail into one portable,
  self-verifying artifact (`walletless-proof/v1`).
- **Proof format spec** (`SPEC.md`) + frozen conformance vectors
  (`test/vectors.json`) — a second implementation that reproduces them interoperates.
- **RFC 6962 consistency proofs** (`consistencyProof`, `verifyConsistencyProof`,
  `trailConsistencyProof`, `verifyTrailConsistency`) — prove an audit log only ever
  grew between two anchored roots (provably append-only history).
- **Entrant inclusion proofs** for draws (`entryProof`, `verifyEntryProof`) — a
  participant verifies "my entry was counted" against the published `entriesRoot`
  without seeing the rest of the field.
- **Non-manipulable drand randomness** (`drandSeed`, `drandRoundAt`,
  `fetchDrandRound`) — commit a future drand round before entries close; enforces
  the `randomness == SHA256(signature)` binding (SHA-256 only).
- **Real BLS verification of drand beacons** (`@kirkelabs/walletless-kit/drand-bls`:
  `makeDrandVerifier`, `verifyDrandBeacon`, `DRAND_QUICKNET_SCHEME`,
  `DRAND_DEFAULT_SCHEME`) — proves a seed is a genuine League-of-Entropy threshold
  signature (quicknet + legacy chained). Cross-checked against live beacon rounds
  frozen in `test/drand-vectors.json`. Backed by `@noble/curves` as an **optional
  peer dependency**, exposed only at the subpath, so the core entrypoint and the
  verifier stay dependency-free.
- **Ledger conservation invariants** (`Ledger.conservation`,
  `Ledger.assertConservation`) — allocations + fees can never exceed inflow.
- **`canonicalJson`** exported — the deterministic JSON primitive shared by the kit.

### Changed

- `audit.js` now sources its Merkle math from a new zero-dependency `src/merkle.js`
  core; the Merkle roots are byte-for-byte identical (frozen vectors unchanged).
- `fetchDrandRound` / `drandSeed` now carry `previousSignature` (needed for chained
  beacon verification).
- Test suite expanded from 47 to 85 passing; lint and `npm audit` clean.

## [0.1.0] — 2026-06-20

- Initial release. A walletless web-architecture toolkit built on
  `@kirkelabs/open-agent-access-core` and `@kirkelabs/oaa-agent-kit`.
- **Onboarding** (`createEphemeralAccount`, `rotateAccount`, `expireAccount`,
  `isExpired`) — tightly-scoped, round-relative auto-expiring custodial accounts,
  authority-bounded via an oaa-agent-kit mandate.
- **Identity** (`OtpIdentity`) — email/SMS OTP adapter: CSPRNG codes, single-use,
  expiring, rate-limited, lockout, constant-time compare; stores only keyed
  (peppered) pseudonymous contact references.
- **Receipts** (`buildOrderReceipt`, `deterministicOrderId`, `attestOnChain`) —
  hash-chained, signed, non-PII receipts with compact, size- and network-bound
  on-chain attestation; x402-charged actions reuse oaa-agent-kit `payAndFetch`.
- **Audit** (`createTrail`, `append`, `merkleRoot`, `anchor`, `verifyTrail`) —
  append-only hash-chained events + an RFC 6962-style domain-separated Merkle root,
  periodically anchored on-chain; tamper/removal is detectable.
- **Ledger** (`createLedger`, `reconciliationSheet`) — three segregated append-only
  books (inflow/charity/escrow), integer-only money, immutable snapshots, and a
  human-readable per-draw reconciliation sheet.
- **Draw** (`runDraw`, `publishDrawProof`, `blockHashSeed`/`vrfSeed`/`beaconSeed`) —
  deterministic, recomputable winner selection (seeded Fisher–Yates, rejection
  sampling, no `Math.random`), with a commit step and honest seed-manipulability docs.
  Ships a frozen test vector.
- **Privacy** (`hashPii`, `pseudonymRef`, `eraseSubject`) — keyed hashing and
  random, erasable references; PII off-chain only.
- CLI (`walletless init|keygen|draw|reconcile|verify|help`), a TestNet raffle
  example, README, SECURITY, and LEGAL (gambling + AML + data-protection). MIT.

> ⚠ Some modules are **EXPERIMENTAL · UNAUDITED**. TestNet by default; obtain an
> independent audit before holding material value or processing real personal data.
