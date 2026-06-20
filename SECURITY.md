# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@kirkelabs.com**.
Do **not** open a public issue for vulnerabilities that affect funds or personal data.

We aim to acknowledge reports within a few business days.

## Scope & threat model

This package handles **custodial keys, money flows, and personal data**, so its
trust boundaries matter. Highlights (full notes in the README "Guardrails" section
and [LEGAL.md](./LEGAL.md)):

- **Ephemeral custodial keys** are server-held, tightly-scoped, and auto-expiring.
  They are **dev/TestNet-grade**; production custody requires your own KMS/HSM and an
  independent audit. Secret keys are never logged, serialized into receipts/events,
  or written on-chain.
- **On-chain data is non-PII** — receipts and anchors only. Personal data lives
  off-chain (encrypted, erasable). Hashed contact references are *pseudonymous*, not
  anonymous, and remain personal data under data-protection law.
- **Draw fairness equals the chosen public seed.** Block-hash seeds are
  validator-manipulable; use the commit step and prefer a VRF / randomness beacon for
  high-value or regulated draws. This is transparency tooling, not a fairness
  guarantee.
- The stateful/experimental parts are labelled **EXPERIMENTAL · UNAUDITED**. Always
  start on TestNet; obtain an independent audit before holding material value or
  processing real personal data.

## Supported versions

Pre-1.0: only the latest published version receives security fixes.
