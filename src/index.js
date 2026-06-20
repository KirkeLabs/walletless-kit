/**
 * @kirkelabs/walletless-kit — public API.
 *
 * A walletless web-architecture toolkit: ephemeral custodial onboarding,
 * receipt-only on-chain proofs, a tamper-evident audit trail, segregated money
 * ledgers, a verifiable recomputable draw, and privacy/erasure helpers. Built on
 * @kirkelabs/open-agent-access-core and @kirkelabs/oaa-agent-kit. MIT.
 *
 * TestNet by default. Some modules are EXPERIMENTAL · UNAUDITED — see LEGAL.md.
 */

// Convenience: re-export the Algod client + algosdk from oaa-agent-kit so callers
// need only one import for the chain client.
export { getAlgod, algosdk } from '@kirkelabs/oaa-agent-kit';

export {
  hashPii,
  hashEquals,
  pseudonymRef,
  eraseSubject,
  assertNoPii,
} from './privacy.js';

export {
  createTrail,
  append,
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  consistencyProof,
  verifyConsistencyProof,
  trailConsistencyProof,
  verifyTrailConsistency,
  trailHash,
  trailRoot,
  verifyTrail,
  anchor,
} from './audit.js';

// Zero-dependency canonical JSON (the hashing primitive the whole kit shares).
export { canonicalJson } from './merkle.js';

// Independent, dependency-free verifier + portable proof bundle. `verifyDrawProof`
// re-derives a draw without trusting draw.js; `verifyBundle` checks a whole
// artifact. See SPEC.md and test/vectors.json (the conformance suite).
export { bundleProof, verifyBundle, verifyDrawProof, BUNDLE_VERSION } from './verify.js';

// NOTE: real BLS verification of drand beacons (`makeDrandVerifier`,
// `verifyDrandBeacon`, `DRAND_QUICKNET_SCHEME`, …) is intentionally NOT re-exported
// here. It needs the OPTIONAL peer dependency `@noble/curves`, so it lives only at
// the `@kirkelabs/walletless-kit/drand-bls` subpath — keeping this core entrypoint
// (and the zero-dependency verifier) free of pairing-crypto. Import it explicitly:
//   import { makeDrandVerifier } from '@kirkelabs/walletless-kit/drand-bls';

export {
  createEphemeralAccount,
  isExpired,
  expireAccount,
  rotateAccount,
} from './onboarding.js';

export { OtpIdentity } from './identity.js';

export {
  buildOrderReceipt,
  deterministicOrderId,
  signReceipt,
  verifyReceiptChain,
  attestOnChain,
  chargeForAction,
} from './receipt.js';

export { Ledger, createLedger } from './ledger.js';

export {
  runDraw,
  publishDrawProof,
  verifyDraw,
  entryProof,
  verifyEntryProof,
  commitSeedSource,
  blockHashSeed,
  vrfSeed,
  beaconSeed,
  drandSeed,
  drandRoundAt,
  fetchDrandRound,
  DRAND_QUICKNET,
} from './draw.js';
