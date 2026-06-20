# Legal, regulatory & acceptable-use notice

`@kirkelabs/walletless-kit` is free, open-source developer software (MIT). It provides
**transparency and bookkeeping tooling** for walletless commerce and prize-draws — it
does **not** provide legal, regulatory, financial, or compliance services, and using it
does not make your activity lawful. This notice is **not legal advice**; if you operate
in any regulated context, take your own advice. You, the operator, are solely
responsible for compliance with all applicable laws in every jurisdiction you serve.

## Nature of the software

A toolkit of independent modules: ephemeral custodial onboarding, receipt-only on-chain
proofs, a tamper-evident audit trail, segregated money ledgers, a verifiable draw, and
privacy/erasure helpers. Kirke Labs operates no servers in your flow, holds no funds, and
holds no keys or personal data. Everything runs in **your** infrastructure under **your**
control.

## 1. Prize draws, raffles & lotteries (gambling law)

Prize draws, raffles, sweepstakes, and lotteries are **heavily regulated** and the rules
differ by country, state, and province (e.g. the UK Gambling Act 2005 and the Gambling
Commission; US state lottery/raffle statutes; varied EU regimes). **This package ships
transparency tooling, not legal compliance.** In particular, **you** are responsible for:

- obtaining any **licence/registration/exempt-lottery** status you need;
- providing a genuine **free-entry route** of equal standing where required;
- **age and geographic gating** (excluding minors and prohibited jurisdictions);
- prize fulfilment, terms & conditions, advertising rules, and record-keeping;
- handling and protecting entrant funds appropriately.

A "verifiable" or "recomputable" draw means the winner can be re-derived from a published
seed — it is **not** a representation that your draw is lawful, nor a substitute for
licensing. **Draw fairness is exactly as strong as the public seed you choose** (see the
README): block-hash seeds are validator-manipulable; use the commit step and prefer a VRF
or randomness beacon for anything of value. Do not describe a draw as "provably fair"
beyond what the chosen seed actually guarantees.

## 2. Money handling, custody & AML

The kit can hold value in **ephemeral custodial accounts** and **segregated escrow/charity
ledgers**. Holding or transmitting other people's money may make you a regulated entity
(money transmission / e-money / payment services) and typically triggers **AML/CFT and
sanctions** obligations (KYC, screening, record-keeping). The custodial keys are
**dev/TestNet-grade**: production custody requires your own KMS/HSM, segregated trust
accounts, reconciliation controls, and an independent audit. The kit performs **no** KYC,
sanctions screening, or licensing checks — those are yours. It transacts in the native
Algorand coin (ALGO) only and is **TestNet by default**; MainNet is an explicit,
cautioned opt-in.

## 3. Personal data & privacy (GDPR / data protection)

If you process entrants' contact details or other personal data, **you are the data
controller**. The kit keeps personal data **off-chain** (you encrypt and can erase it) and
places only **non-identifying references** on-chain. Two honest limits:

- **Hashed contact references are pseudonymous, not anonymous** — they remain *personal
  data*. Use the keyed (peppered) hashing provided, never bare hashes of low-entropy
  values like emails or phone numbers.
- **The blockchain is immutable.** "Erasure" works only because on-chain data is designed
  to be non-identifying and unlinkable once the off-chain record (and any random reference
  mapping) is deleted. Do **not** put personal data on-chain; if you do, it cannot be
  erased. You remain responsible for lawful basis, retention, subject-access, and erasure.

## No warranty; experimental

Provided **"as is", without warranty** (see [LICENSE](./LICENSE)). Modules — and especially
anything labelled **EXPERIMENTAL · UNAUDITED** — are not guaranteed fit for any purpose.
Crypto-assets are volatile and largely unregulated. **You may lose funds and you bear all
compliance risk.** Nothing here is financial, legal, or investment advice.

## Jurisdiction

Published globally as open source; **not targeted at any jurisdiction** and not an offer to
provide any regulated service. You determine whether your use is lawful where you operate.

## Reporting

Security issues: **security@kirkelabs.com** (please do not open public issues for
vulnerabilities affecting funds or personal data).
