/**
 * privacy.js — keep personal data OFF-chain and make erasure real.
 *
 * Design rules (see LEGAL.md, data-protection section):
 *   - Personal data (email/phone/name) lives off-chain, encrypted and deletable.
 *   - The chain holds only NON-identifying references.
 *   - Contact references are KEYED (HMAC with a per-deployment pepper), never a
 *     bare hash — a raw SHA-256 of an email/phone is brute-forceable because the
 *     input space is small/enumerable. A keyed hash is pseudonymous; it is still
 *     personal data under GDPR, but not trivially reversible.
 *   - For references that must survive on-chain yet remain erasable, prefer a
 *     RANDOM nonce (`pseudonymRef`) stored off-chain over a deterministic hash of
 *     the PII: deleting the off-chain mapping then makes the on-chain ref
 *     unlinkable. A deterministic PII hash would stay linkable to anyone who
 *     re-encounters the same PII, defeating erasure.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Keyed, pseudonymous reference for a contact value (email/phone/etc).
 * Stable for a given (pepper, value) so you can de-duplicate entrants, but not
 * reversible without the pepper. NOT anonymous — still personal data.
 * @param {string} value e.g. an email or phone number
 * @param {string} pepper a secret, per-deployment key (keep out of the repo/chain)
 * @returns {string} hex HMAC-SHA256
 */
export function hashPii(value, pepper) {
  if (typeof value !== 'string' || value.length === 0)
    throw new Error('hashPii: value must be a non-empty string');
  if (typeof pepper !== 'string' || pepper.length < 16)
    throw new Error('hashPii: pepper must be a secret string of at least 16 chars');
  return createHmac('sha256', pepper).update(value, 'utf8').digest('hex');
}

/** Constant-time comparison of two contact hashes (avoid timing side-channels). */
export function hashEquals(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * A subject record that maps a RANDOM, erasable on-chain reference to off-chain
 * PII. Put `ref` on-chain (it is just a random nonce); keep `contactHash` and the
 * encrypted PII in your off-chain store. `eraseSubject` deletes everything off
 * chain, after which `ref` is permanently unlinkable.
 *
 * @param {object} opts
 * @param {string} opts.contact   raw contact value (NOT stored as-is)
 * @param {string} opts.pepper    secret keyed-hash pepper
 * @returns {{ ref: string, contactHash: string, createdRef: true }}
 */
export function pseudonymRef({ contact, pepper }) {
  const contactHash = hashPii(contact, pepper);
  // Random 16-byte nonce — independent of the PII, so erasing the off-chain map
  // makes it unlinkable. This is what (optionally) goes on-chain.
  const ref = randomBytes(16).toString('hex');
  return { ref, contactHash, createdRef: true };
}

/**
 * Erase a subject from an off-chain store. Removes the encrypted PII and the
 * ref->contact mapping so any on-chain `ref` becomes unlinkable. On-chain
 * receipts/anchors (which hold no PII) intentionally remain.
 *
 * @param {Map|object} store a Map (or plain object) keyed by `ref`
 * @param {string} ref the random reference to erase
 * @returns {{ erased: boolean, ref: string }}
 */
export function eraseSubject(store, ref) {
  if (ref == null) throw new Error('eraseSubject: ref is required');
  let erased = false;
  if (store instanceof Map) {
    erased = store.delete(ref);
  } else if (store && typeof store === 'object') {
    if (Object.prototype.hasOwnProperty.call(store, ref)) {
      delete store[ref];
      erased = true;
    }
  } else {
    throw new Error('eraseSubject: store must be a Map or object');
  }
  return { erased, ref };
}

/** Assert an object carries no obvious PII before it is written on-chain. */
const PII_KEYS = /^(email|phone|name|firstname|lastname|address|dob|ip|contact)$/i;
export function assertNoPii(obj, path = '$') {
  if (obj == null || typeof obj !== 'object') return true;
  for (const [k, v] of Object.entries(obj)) {
    if (PII_KEYS.test(k))
      throw new Error(`assertNoPii: possible PII field "${k}" at ${path} must not go on-chain`);
    if (v && typeof v === 'object') assertNoPii(v, `${path}.${k}`);
  }
  return true;
}
