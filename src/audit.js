/**
 * audit.js — a tamper-evident audit trail.
 *
 * Two layers, both built on @kirkelabs/open-agent-access-core:
 *   1. An append-only HASH-CHAINED event log (each event commits to the previous
 *      one's hash) — editing or removing any event breaks the chain. This is
 *      core's `appendAccessEvent` / `verifyAccessEventTrail`.
 *   2. A MERKLE ROOT over the events — a single 32-byte commitment you can anchor
 *      on-chain cheaply and use for inclusion proofs.
 *
 * The Merkle construction is the only new cryptographic primitive in this package,
 * so it is built defensively (see `merkleRoot`).
 */

import algosdk from 'algosdk';
import {
  appendAccessEvent,
  verifyAccessEventTrail,
  hashAccessEvents,
} from '@kirkelabs/open-agent-access-core';
// The Merkle math lives in the zero-dependency `merkle.js` core so the standalone
// verifier (`verify.js`) and any second implementation can reproduce these exact
// roots without pulling in algosdk or oaa-core.
import {
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  consistencyProof,
  verifyConsistencyProof,
} from './merkle.js';

export { merkleRoot, merkleProof, verifyMerkleProof, consistencyProof, verifyConsistencyProof };

/**
 * Consistency proof that the first `oldSize` events of `trail` (an earlier,
 * already-anchored state) are a verbatim prefix of the trail as it stands now —
 * i.e. the operator only APPENDED and never rewrote history. This is the RFC 6962
 * append-only guarantee; pair it with the on-chain anchors from `anchor()`:
 * anchor the root at size m, later anchor the root at size n, and anyone can prove
 * the m→n transition was append-only with `verifyTrailConsistency`.
 * @returns {{oldSize:number,newSize:number,proof:string[]}}
 */
export function trailConsistencyProof(trail, oldSize) {
  return consistencyProof(trail?.events ?? [], oldSize);
}

/** Verify a trail consistency proof between two anchored roots. Never throws. */
export function verifyTrailConsistency(args) {
  return verifyConsistencyProof(args);
}

/** A fresh empty trail. */
export function createTrail() {
  return { events: [] };
}

/**
 * Append an event to the trail (hash-chained via core). Returns a NEW trail.
 * Pass deterministic `eventId`/`timestamp` in `input` if you need reproducibility.
 */
export function append(trail, input) {
  const events = appendAccessEvent(trail?.events ?? [], input ?? {});
  return { events };
}

/** sha256 commitment over the event hashes (cheap integrity digest). */
export function trailHash(trail) {
  return hashAccessEvents(trail?.events ?? []);
}

/** Merkle root over the trail's events. */
export function trailRoot(trail) {
  return merkleRoot(trail?.events ?? []);
}

/**
 * Verify the trail end-to-end. Robust to malformed input (never throws). Reports
 * whether the hash-chain is intact and returns the current Merkle root.
 * @returns {{ok:boolean, count:number, errors:string[], root:string|null}}
 */
export function verifyTrail(trail) {
  try {
    const events = Array.isArray(trail) ? trail : trail?.events;
    if (!Array.isArray(events)) return { ok: false, count: 0, errors: ['not_a_trail'], root: null };
    const res = verifyAccessEventTrail(events);
    return {
      ok: res.valid,
      count: res.count,
      errors: res.errors,
      root: res.valid ? merkleRoot(events) : null,
    };
  } catch (e) {
    return { ok: false, count: 0, errors: [`verify_error:${e.message}`], root: null };
  }
}

/**
 * Anchor a Merkle root on-chain as a compact, NON-PII checkpoint: a 0-amount
 * self-payment whose note is `walletless-anchor:v1:<root>`. Network-bound (the
 * transaction carries the node's genesis hash) and size-bounded (note ≤ 1 KB).
 *
 * @param {algosdk.Algodv2} algod
 * @param {{address:string, signTxns:Function}} signer e.g. an oaa-agent-kit LocalOwnerSigner
 * @param {string} root hex Merkle root
 * @returns {Promise<{txid:string, confirmedRound:number, root:string}>}
 */
export async function anchor(algod, signer, root) {
  if (!/^[0-9a-f]{2,128}$/i.test(String(root)))
    throw new Error('anchor: root must be a hex string');
  const note = new TextEncoder().encode(`walletless-anchor:v1:${root}`);
  if (note.length > 1024) throw new Error('anchor: note exceeds 1KB');
  const sp = await algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: signer.address,
    receiver: signer.address, // self-payment: moves nothing, just records the note
    amount: 0,
    note,
    suggestedParams: sp,
  });
  const [signed] = await signer.signTxns([txn]);
  const { txid } = await algod.sendRawTransaction(signed).do();
  const res = await algosdk.waitForConfirmation(algod, txid, 10);
  return {
    txid,
    confirmedRound: Number(res.confirmedRound ?? res['confirmed-round']),
    root: String(root),
  };
}
