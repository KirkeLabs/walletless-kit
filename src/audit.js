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

import { createHash } from 'node:crypto';
import algosdk from 'algosdk';
import {
  appendAccessEvent,
  verifyAccessEventTrail,
  hashAccessEvents,
  canonicalizeJson,
} from '@kirkelabs/open-agent-access-core';

const MAX_LEAVES = 1_000_000; // DoS bound
// RFC 6962 domain-separation tags: leaves and internal nodes are hashed in
// DIFFERENT domains so a leaf can never be reinterpreted as an internal node
// (which would otherwise enable second-preimage forgery of the root).
const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

function sha256(...bufs) {
  const h = createHash('sha256');
  for (const b of bufs) h.update(b);
  return h.digest();
}
/** Injective leaf encoding via canonical JSON, then domain-tagged hash. */
function leafHash(item) {
  return sha256(LEAF, Buffer.from(canonicalizeJson(item), 'utf8'));
}

/**
 * Deterministic Merkle root (hex) over an ordered list of items.
 *
 * Defensive choices:
 *  - Domain separation: leaf = H(0x00‖data), node = H(0x01‖left‖right).
 *  - A lone (odd) node is PROMOTED to the next level unchanged — it is NOT
 *    duplicated (duplicating the last node is the Bitcoin CVE-2012-2459
 *    ambiguity, where two different trees share a root).
 *  - Empty list → H("") (RFC 6962 empty-tree root). Single item → its leaf hash.
 */
export function merkleRoot(items) {
  if (!Array.isArray(items)) throw new Error('merkleRoot: items must be an array');
  if (items.length > MAX_LEAVES) throw new Error('merkleRoot: too many leaves');
  if (items.length === 0) return sha256(Buffer.alloc(0)).toString('hex');
  let level = items.map(leafHash);
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? sha256(NODE, level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0].toString('hex');
}

/**
 * Inclusion proof for the item at `index`. Returns the sibling hashes (hex) and
 * their side, which `verifyMerkleProof` replays to recompute the root.
 */
export function merkleProof(items, index) {
  if (!Array.isArray(items) || index < 0 || index >= items.length)
    throw new Error('merkleProof: index out of range');
  let level = items.map(leafHash);
  let idx = index;
  const path = [];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(sha256(NODE, level[i], level[i + 1]));
        if (i === idx) path.push({ side: 'right', hash: level[i + 1].toString('hex') });
        else if (i + 1 === idx) path.push({ side: 'left', hash: level[i].toString('hex') });
      } else {
        next.push(level[i]); // promoted; no sibling recorded for the lone node
      }
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return { index, leaf: leafHash(items[index]).toString('hex'), path };
}

/** Verify an inclusion proof against an expected root. */
export function verifyMerkleProof({ leaf, path, root }) {
  try {
    let acc = Buffer.from(String(leaf), 'hex');
    for (const step of path || []) {
      const sib = Buffer.from(String(step.hash), 'hex');
      acc = step.side === 'left' ? sha256(NODE, sib, acc) : sha256(NODE, acc, sib);
    }
    return { ok: acc.toString('hex') === String(root) };
  } catch (e) {
    return { ok: false, reason: `verify_error:${e.message}` };
  }
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
