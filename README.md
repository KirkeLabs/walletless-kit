# @kirkelabs/walletless-kit

[![License: MIT](https://img.shields.io/badge/license-MIT-00dc94?style=flat)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-00dc94?style=flat)](https://nodejs.org)
[![Algorand](https://img.shields.io/badge/Algorand-TestNet%20by%20default-00dc94?style=flat)](https://algorand.co)

**Walletless web architecture: onboard users with no wallet, prove what happened with receipts (not personal data), keep a tamper-evident audit trail and clean money trails, and run a draw anyone can recompute.** Charity prize-draws are the flagship example; every module is reusable for any walletless commerce flow.

```bash
npm i @kirkelabs/walletless-kit
npx walletless init my-raffle
```

> ⚠️ **Experimental developer tooling, provided "as is."** It handles **custodial keys, money, and personal data**, and prize draws are **regulated**. This is *transparency tooling, not legal compliance*. Read **[Guardrails](#guardrails)** and **[LEGAL.md](./LEGAL.md)** before using real funds or real personal data. Nothing here is financial or legal advice. TestNet by default.

Built on [`@kirkelabs/open-agent-access-core`](https://www.npmjs.com/package/@kirkelabs/open-agent-access-core) (proof/receipt spine) and [`@kirkelabs/oaa-agent-kit`](https://www.npmjs.com/package/@kirkelabs/oaa-agent-kit) (Algorand spend/identity/x402). The only new cryptographic primitive here is the Merkle root in `audit.js`.

## What's in the box

| Module | What it does |
|--------|--------------|
| **onboarding** | `createEphemeralAccount` / `rotateAccount` / `expireAccount` / `isExpired` — tightly-scoped, **round-relative auto-expiring** custodial accounts; authority bounded by an oaa-agent-kit mandate. |
| **identity** | `OtpIdentity` — email/SMS OTP: CSPRNG codes, single-use, expiring, rate-limited, lockout, constant-time compare; stores only **keyed (peppered) pseudonymous** contact refs. |
| **receipt** | `buildOrderReceipt` / `deterministicOrderId` / `signReceipt` / `verifyReceiptChain` / `attestOnChain` — hash-chained, signed, **non-PII** receipts; only the receipt *hash* goes on-chain. x402 actions via `chargeForAction`. |
| **audit** | `createTrail` / `append` / `merkleRoot` / `merkleProof` / `verifyMerkleProof` / `anchor` / `verifyTrail` — append-only hash-chained events + an **RFC 6962** Merkle root, periodically anchored on-chain. |
| **ledger** | `createLedger` — three segregated append-only books (inflow / charity / escrow), **integer-only money**, immutable snapshots, and a per-draw `reconciliationSheet`. |
| **draw** | `runDraw` / `publishDrawProof` / `verifyDraw` + `commitSeedSource` / `blockHashSeed` / `vrfSeed` / `beaconSeed` — deterministic, recomputable winner selection (no `Math.random`). |
| **privacy** | `hashPii` / `pseudonymRef` / `eraseSubject` / `assertNoPii` — keyed hashing and random, **erasable** references; PII stays off-chain. |

## Quickstart

```js
import {
  createLedger, OtpIdentity, buildOrderReceipt, createTrail, append,
  runDraw, publishDrawProof, verifyDraw,
} from '@kirkelabs/walletless-kit';

// 1) Identity-lite: OTP, storing only a keyed pseudonymous ref (never the email).
const id = new OtpIdentity({ pepper: process.env.PEPPER, send: sendEmail });
await id.issueChallenge('alice@example.com');
const { ok, contactRef } = await id.verifyChallenge('alice@example.com', code);

// 2) A non-PII order receipt, hash-chained and (optionally) signed.
const receipt = buildOrderReceipt({ orderId: 'o1', action: 'buy_ticket', quantity: 1, price: '1000000', agent: contactRef });

// 3) A tamper-evident audit trail.
let trail = createTrail();
trail = append(trail, { type: 'ticket_sold', orderId: 'o1' });

// 4) Segregated money books.
const ledger = createLedger();
ledger.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'ticket', txRef: 'tx1' });

// 5) A verifiable draw — anyone can recompute the winner from the proof.
const entries = [contactRef /* … */];
const proof = publishDrawProof({ entries, seed: committedSeed, winners: 1 });
console.log(verifyDraw(proof, entries).ok); // true
```

Run the full on-chain flow on TestNet: [`examples/raffle.js`](./examples/raffle.js).

## CLI

```bash
walletless init [dir]                              # scaffold a starter raffle (ships a .gitignore)
walletless keygen --out owner.json                 # dev account, written 0600 (never printed)
walletless draw --entries entries.json --seed <s>  # run + print a recomputable draw proof
walletless reconcile --ledger ledger.json          # print a reconciliation sheet
walletless verify --proof proof.json --entries entries.json   # recompute a draw / audit trail
walletless help
```

## Guardrails

These are non-negotiable; the modules enforce or document them.

- **TestNet by default.** MainNet is an explicit, cautioned opt-in.
- **Custodial keys are sensitive.** Ephemeral account keys are server-held, tightly-scoped, and auto-expiring — and **dev/TestNet-grade**. JS cannot wipe key memory; production custody needs your own **KMS/HSM** and an independent audit. Secret keys are never logged, serialized into receipts/events/snapshots, or written on-chain.
- **Personal data stays off-chain.** The chain holds only non-identifying references. **Hashed contact refs are pseudonymous, not anonymous** — still personal data; use the keyed (peppered) hashing provided, never bare hashes. For erasable references, `pseudonymRef` gives a **random, deletable** on-chain ref so `eraseSubject` truly unlinks the subject.
- **Draw fairness equals the seed — no more.** A block-hash seed is **manipulable** (a block producer can withhold/grind a block). Use `commitSeedSource` to announce the exact future round **before entries close**, and prefer a **VRF / drand beacon** for anything of value. Winner selection is a deterministic, recomputable function of `(seed, entries)` with rejection sampling — there is **no `Math.random`**. Don't call a draw "provably fair" beyond what your seed guarantees.
- **Money is integer microALGO.** Never floats (they drift and break reconciliation). Ledger books are append-only with immutable snapshots.
- **Regulated use.** Prize draws/lotteries are regulated; custodial money handling implies AML/custody duties; processing entrant data makes you a **GDPR data controller**. This package ships transparency tooling, **not** legal compliance — you own licensing, the **free-entry route**, and **age/geo gating**. See **[LEGAL.md](./LEGAL.md)**.
- **Anything experimental is labelled EXPERIMENTAL · UNAUDITED.** Get an independent audit before holding material value or processing real personal data.

## Supply chain

Pinned dependency floors + committed lockfile; CI runs lint, tests, and `npm audit` on Node 20 & 22 with least-privilege permissions and SHA-pinned actions; `release.yml` publishes with **npm provenance** via OIDC. Report security issues to **security@kirkelabs.com** ([SECURITY.md](./SECURITY.md)).

## Licence

[MIT](./LICENSE) © 2026 Kirke Labs — [www.kirkelabs.com](https://www.kirkelabs.com)
