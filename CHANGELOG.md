# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/);
versioning: [SemVer](https://semver.org/).

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
