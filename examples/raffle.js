/**
 * examples/raffle.js — a full walletless charity prize-draw on Algorand TestNet.
 *
 * Flow: ephemeral guest account -> OTP (stub) -> non-PII order receipts +
 * on-chain attestation -> audit trail + on-chain anchor -> a draw seeded by a
 * TestNet block hash -> reconciliation sheet -> verify recomputes the winner.
 *
 * Run:  OPERATOR_MNEMONIC="..."  node examples/raffle.js
 * (Fund the operator on TestNet: https://bank.testnet.algorand.network/)
 *
 * ⚠ Demo only. Prize draws are regulated and a block-hash seed is manipulable —
 * see the README guardrails and LEGAL.md. TestNet by default.
 */

import {
  getAlgod,
  createEphemeralAccount,
  isExpired,
  OtpIdentity,
  buildOrderReceipt,
  deterministicOrderId,
  attestOnChain,
  createTrail,
  append,
  trailRoot,
  anchor,
  createLedger,
  publishDrawProof,
  verifyDraw,
  blockHashSeed,
} from '@kirkelabs/walletless-kit';
import { LocalOwnerSigner } from '@kirkelabs/oaa-agent-kit';

const mnemonic = process.env.OPERATOR_MNEMONIC;
if (!mnemonic) throw new Error('Set OPERATOR_MNEMONIC (a funded TestNet account).');

const algod = getAlgod({ network: 'algorand-testnet' });
const operator = new LocalOwnerSigner({ mnemonic });
const PEPPER = process.env.PEPPER || 'demo-pepper-at-least-16-chars';
const log = (...a) => console.log(...a);

log('Operator:', operator.address);
const sp = await algod.getTransactionParams().do();
log('Current round ~', Number(sp.firstValid), '\n');

// 1) Ephemeral custodial guest account (round-relative expiry).
const guest = await createEphemeralAccount({ algod, ttlRounds: 10_000, scope: { perTxMicroAlgos: 1_000_000 } });
log('[1] Ephemeral guest account:', guest.address);
log('    expiresRound', guest.expiryRound, '| expired now?', isExpired(guest, Number(sp.firstValid)));

// 2) Identity-lite: OTP (we capture the code instead of emailing it).
const codes = {};
const id = new OtpIdentity({ pepper: PEPPER, send: async (c, code) => (codes[c] = code) });
const entrants = ['alice@example.com', 'bob@example.com', 'carol@example.com'];
const refs = [];
for (const e of entrants) {
  await id.issueChallenge(e);
  const v = await id.verifyChallenge(e, codes[e]);
  refs.push(v.contactRef);
}
log('\n[2] OTP-verified', refs.length, 'entrants (stored as keyed refs, not emails)');

// 3) Non-PII order receipts (hash-chained) + attest the latest hash on-chain.
const ledger = createLedger();
let trail = createTrail();
let prevHash = null;
let lastReceipt = null;
refs.forEach((ref, i) => {
  const orderId = deterministicOrderId({ ref, item: 'raffle-ticket', n: i });
  const receipt = buildOrderReceipt({ orderId, action: 'buy_ticket', quantity: 1, price: '1000000', agent: ref, previousHash: prevHash });
  prevHash = receipt.receiptHash;
  lastReceipt = receipt;
  ledger.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'ticket', ref: orderId });
  trail = append(trail, { type: 'ticket_sold', orderId, eventId: `evt_${i}` });
});
const att = await attestOnChain(algod, operator, lastReceipt);
log('\n[3] Receipts chained; latest hash attested on-chain in round', att.confirmedRound);
log('    txid', att.txid);

// 4) Audit trail -> Merkle root -> on-chain anchor.
const root = trailRoot(trail);
const anc = await anchor(algod, operator, root);
log('\n[4] Audit Merkle root', root.slice(0, 16) + '… anchored in round', anc.confirmedRound);

// 5) Allocate fee + charity in segregated books.
ledger.post({ book: 'inflow', amountMicro: 100_000, kind: 'fee' });
ledger.post({ book: 'charity', amountMicro: 2_500_000, ref: operator.address, kind: 'charity_payout', txRef: att.txid });

// 6) Draw, seeded by a recent TestNet block hash (committed in advance in production).
const seedRound = Number(sp.firstValid) - 5; // a confirmed round
const seed = await blockHashSeed(algod, seedRound);
log('\n[5] Seed from TestNet block', seedRound, '(⚠ manipulable — commit in advance / use VRF for value)');
const proof = publishDrawProof({ entries: refs, seed: seed.value, winners: 1 });
log('    Winner ref:', proof.winners[0]);

// 7) Reconciliation sheet + independent verification.
const sheet = ledger.reconciliationSheet('demo-draw-1', { winnerProofLink: `algo:${anc.txid}` });
log('\n[6] Reconciliation:', JSON.stringify(sheet.charity), '| net', sheet.netMicroAlgos, 'µALGO');
log('[7] verifyDraw recomputes the winner:', verifyDraw(proof, refs).ok);

log('\n✅ Walletless raffle complete on TestNet: ephemeral onboarding → OTP → receipts+attestation → audit anchor → verifiable draw → reconciliation.');
