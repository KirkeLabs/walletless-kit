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
  trailHash,
  trailRoot,
  verifyTrail,
  anchor,
} from './audit.js';

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
  commitSeedSource,
  blockHashSeed,
  vrfSeed,
  beaconSeed,
} from './draw.js';
