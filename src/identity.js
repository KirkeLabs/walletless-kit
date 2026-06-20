/**
 * identity.js — identity-lite (email/SMS OTP) without storing raw contact data.
 *
 * Hardening (see SECURITY.md / LEGAL.md):
 *   - OTP codes are generated with a CSPRNG (`crypto.randomInt`), never Math.random.
 *   - Single-use, time-bound (expiry), rate-limited (core InMemoryRateLimiter),
 *     and locked out after N failed attempts.
 *   - Codes are compared in constant time and only their KEYED hash is stored —
 *     never the raw code.
 *   - Contacts are stored only as KEYED (peppered) hashes — pseudonymous, still
 *     personal data under GDPR; never the raw email/phone.
 *   - Failures are generic (anti-enumeration): a caller cannot tell whether a
 *     given contact has an outstanding challenge.
 */

import { createHmac, randomInt } from 'node:crypto';
import { InMemoryRateLimiter } from '@kirkelabs/open-agent-access-core';
import { hashPii, hashEquals } from './privacy.js';

export class OtpIdentity {
  /**
   * @param {object} opts
   * @param {string}   opts.pepper       secret keyed-hash pepper (>= 16 chars)
   * @param {Function} [opts.send]       async (contact, code) => deliver out-of-band
   * @param {number}   [opts.codeLength] digits (default 6)
   * @param {number}   [opts.ttlMs]      code validity (default 5 min)
   * @param {number}   [opts.maxAttempts] failures before lockout (default 5)
   * @param {object}   [opts.rateLimit]  { requests, window } e.g. {requests:5, window:'10m'}
   */
  constructor({
    pepper,
    send,
    codeLength = 6,
    ttlMs = 5 * 60_000,
    maxAttempts = 5,
    rateLimit = { requests: 5, window: '10m' },
  } = {}) {
    if (typeof pepper !== 'string' || pepper.length < 16)
      throw new Error('OtpIdentity: pepper must be a secret string of >= 16 chars');
    this._pepper = pepper;
    this._send = send;
    this._codeLength = codeLength;
    this._ttlMs = ttlMs;
    this._maxAttempts = maxAttempts;
    this._rateLimit = rateLimit;
    this._rl = new InMemoryRateLimiter();
    this._challenges = new Map(); // contactHash -> { codeHash, expiresAt, attempts, used }
  }

  /** Keyed, pseudonymous reference for a contact (what you store/de-dup on). */
  contactRef(contact) {
    return hashPii(contact, this._pepper);
  }

  _codeHash(code) {
    return createHmac('sha256', this._pepper).update(`otp:${code}`, 'utf8').digest('hex');
  }

  /**
   * Issue a fresh OTP for a contact and deliver it via `send`. Does NOT return the
   * code. Rate-limited per contact.
   * @returns {Promise<{sent:boolean, contactRef:string, expiresAt?:number, reason?:string, retryAfter?:number}>}
   */
  async issueChallenge(contact, { now = Date.now() } = {}) {
    const contactRef = this.contactRef(contact);
    const rl = this._rl.check(`otp-issue:${contactRef}`, this._rateLimit, now);
    if (!rl.allowed)
      return { sent: false, contactRef, reason: 'rate_limited', retryAfter: rl.retryAfter };

    // CSPRNG numeric code, zero-padded to codeLength.
    const max = 10 ** this._codeLength;
    const code = String(randomInt(0, max)).padStart(this._codeLength, '0');
    const expiresAt = now + this._ttlMs;
    this._challenges.set(contactRef, {
      codeHash: this._codeHash(code),
      expiresAt,
      attempts: 0,
      used: false,
    });
    if (typeof this._send === 'function') await this._send(contact, code);
    return { sent: true, contactRef, expiresAt };
  }

  /**
   * Verify a submitted code. Single-use, expiring, attempt-limited, constant-time.
   * Returns a GENERIC failure (anti-enumeration) on any invalid/expired/missing case.
   * @returns {Promise<{ok:boolean, contactRef:string, reason?:string, retryAfter?:number}>}
   */
  async verifyChallenge(contact, code, { now = Date.now() } = {}) {
    const contactRef = this.contactRef(contact);
    const rl = this._rl.check(`otp-verify:${contactRef}`, this._rateLimit, now);
    if (!rl.allowed)
      return { ok: false, contactRef, reason: 'rate_limited', retryAfter: rl.retryAfter };

    const ch = this._challenges.get(contactRef);
    if (!ch || ch.used || now > ch.expiresAt)
      return { ok: false, contactRef, reason: 'invalid_or_expired' };
    if (ch.attempts >= this._maxAttempts)
      return { ok: false, contactRef, reason: 'locked_out' };

    ch.attempts += 1;
    const match = hashEquals(this._codeHash(String(code)), ch.codeHash);
    if (!match) {
      const locked = ch.attempts >= this._maxAttempts;
      return { ok: false, contactRef, reason: locked ? 'locked_out' : 'invalid_or_expired' };
    }
    ch.used = true; // single-use: consume the challenge on success
    return { ok: true, contactRef };
  }
}
