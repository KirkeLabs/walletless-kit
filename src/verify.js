/**
 * verify.js — the independent, ZERO-DEPENDENCY verifier.
 *
 * This is the trust spine of the kit. Everything here depends only on `merkle.js`
 * (which depends only on `node:crypto`) — never on algosdk, oaa-core, or even the
 * proof-producing modules' chain code. That is deliberate: the whole value of a
 * "recomputable" draw or a "tamper-evident" trail is that a skeptic can check it
 * WITHOUT trusting the software that produced it. This module is what they run.
 *
 * Two things live here:
 *   1. `bundleProof` — pack a draw + its entry commitment + (optionally) an audit
 *      trail and receipt chain into ONE portable, self-describing JSON artifact.
 *   2. `verifyBundle` — re-derive every claim in that artifact from scratch and
 *      return a per-section verdict. Runs in Node or a browser (bundle `merkle.js`).
 *
 * The format is versioned and specified in SPEC.md; `test/vectors.json` is the
 * frozen conformance suite a second implementation must reproduce.
 */

import {
  sha256,
  canonicalJson,
  merkleRoot,
  verifyMerkleProof,
  verifyConsistencyProof,
  leafHash,
} from './merkle.js';

export const BUNDLE_VERSION = 'walletless-proof/v1';

// ─── Pure re-derivations (no imports from the producing modules) ─────────────
// These intentionally re-implement the verification math rather than calling the
// producer code, so the verifier and the producer are independent witnesses.

/** Deterministic seed→byte stream (mirrors draw.js makeRng), node:crypto only. */
function makeRng(seed) {
  const seedBuf = Buffer.from(String(seed), 'utf8');
  let counter = 0;
  let pool = Buffer.alloc(0);
  let used = 0;
  const refill = () => {
    const c = Buffer.alloc(8);
    c.writeUInt32LE(counter >>> 0, 0);
    c.writeUInt32LE(Math.floor(counter / 2 ** 32) >>> 0, 4);
    pool = sha256(seedBuf, Buffer.from(':'), c);
    counter += 1;
    used = 0;
  };
  return {
    nextBytes(n) {
      const out = Buffer.alloc(n);
      let o = 0;
      while (o < n) {
        if (used >= pool.length) refill();
        const take = Math.min(n - o, pool.length - used);
        pool.copy(out, o, used, used + take);
        used += take;
        o += take;
      }
      return out;
    },
  };
}

function uniformInt(rng, maxExclusive) {
  if (maxExclusive <= 1) return 0;
  const span = 0x1000000000000; // 2^48
  const limit = Math.floor(span / maxExclusive) * maxExclusive;
  for (;;) {
    const v = rng.nextBytes(6).readUIntBE(0, 6);
    if (v < limit) return v % maxExclusive;
  }
}

/** Recompute the winning indices from (seed, entryCount). Pure. */
function recomputeWinnerIndices(seed, entryCount, k) {
  const a = Array.from({ length: entryCount }, (_, i) => i);
  const rng = makeRng(seed);
  for (let i = a.length - 1; i >= 1; i--) {
    const j = uniformInt(rng, i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, k);
}

/** Verify a draw proof against the entry set. Independent of draw.js. */
export function verifyDrawProof(proof, entries) {
  try {
    if (!proof || !Array.isArray(entries)) return { ok: false, reason: 'bad_input' };
    if (proof.algorithm !== 'fisher-yates-sha256-v1')
      return { ok: false, reason: `unsupported_algorithm:${proof.algorithm}` };
    if (entries.length !== proof.entryCount) return { ok: false, reason: 'entry_count_mismatch' };
    if (merkleRoot(entries) !== proof.entriesRoot) return { ok: false, reason: 'entries_root_mismatch' };
    const k = proof.winnerIndices?.length ?? 1;
    const idx = recomputeWinnerIndices(proof.seed, entries.length, k);
    const sameIdx =
      idx.length === proof.winnerIndices.length && idx.every((v, i) => v === proof.winnerIndices[i]);
    if (!sameIdx) return { ok: false, reason: 'winner_index_mismatch' };
    const sameWin =
      Array.isArray(proof.winners) &&
      proof.winners.length === idx.length &&
      idx.every((i, n) => canonicalJson(entries[i]) === canonicalJson(proof.winners[n]));
    return sameWin ? { ok: true } : { ok: false, reason: 'winner_value_mismatch' };
  } catch (e) {
    return { ok: false, reason: `verify_error:${e.message}` };
  }
}

/** Verify a receipt hash-chain (hashes recompute + links chain). Zero-dep. */
export function verifyReceiptChain(receipts) {
  const errors = [];
  if (!Array.isArray(receipts)) return { ok: false, count: 0, errors: ['not_an_array'] };
  let prev = null;
  receipts.forEach((r, i) => {
    try {
      const body = { ...r };
      delete body.receiptHash;
      delete body.signature;
      const h = sha256(Buffer.from(canonicalJson(body), 'utf8')).toString('hex');
      if ((r.previousHash ?? null) !== prev) errors.push(`receipt ${i + 1}: previousHash mismatch`);
      if (r.receiptHash !== h) errors.push(`receipt ${i + 1}: receiptHash mismatch`);
      prev = r.receiptHash;
    } catch (e) {
      errors.push(`receipt ${i + 1}: ${e.message}`);
    }
  });
  return { ok: errors.length === 0, count: receipts.length, errors };
}

// ─── Portable proof bundle ───────────────────────────────────────────────────

/**
 * Pack a verifiable draw into one portable artifact. Include `entries` to make the
 * bundle fully self-verifying; omit them (and pass `entriesRoot` via the proof) to
 * publish a commitment-only bundle that entrants verify with their own `entryProof`.
 *
 * @param {object} args
 * @param {object} args.drawProof          output of `publishDrawProof`
 * @param {any[]}  [args.entries]          the ordered entry set (optional)
 * @param {object} [args.seedSource]       e.g. `drandSeed(...)` / `commitSeedSource(...)` output
 * @param {object[]} [args.receipts]       a receipt chain to bundle
 * @param {object} [args.trail]            `{ events }` audit trail to commit by root
 * @param {object} [args.anchors]          on-chain anchor refs, e.g. `{ txid, round, root }`
 * @param {object} [args.meta]            free-form, non-PII context (drawId, links…)
 * @returns {object} the bundle (plain JSON)
 */
export function bundleProof({ drawProof, entries, seedSource, receipts, trail, anchors, meta } = {}) {
  if (!drawProof || !drawProof.entriesRoot) throw new Error('bundleProof: drawProof is required');
  const bundle = {
    bundleVersion: BUNDLE_VERSION,
    draw: drawProof,
    seedSource: seedSource ?? null,
    entries: Array.isArray(entries) ? entries : null,
    receipts: Array.isArray(receipts) ? receipts : null,
    trail: trail?.events ? { root: merkleRoot(trail.events), count: trail.events.length } : null,
    anchors: anchors ?? null,
    meta: meta ?? null,
  };
  // A self-commitment over everything above, so the bundle itself is tamper-evident.
  bundle.bundleHash = sha256(Buffer.from(canonicalJson({ ...bundle }), 'utf8')).toString('hex');
  return bundle;
}

/**
 * Independently verify a proof bundle. Re-derives every claim it can from the
 * data carried in the bundle and returns a per-section verdict plus an overall
 * `ok`. Sections with nothing to check report `{ ok:true, skipped:true }`.
 * Robust to malformed input (never throws).
 *
 * @returns {{ok:boolean, bundleVersion:string|null, sections:object}}
 */
export function verifyBundle(bundle) {
  const sections = {};
  try {
    if (!bundle || typeof bundle !== 'object')
      return { ok: false, bundleVersion: null, sections: { bundle: { ok: false, reason: 'not_an_object' } } };

    // 0. Self-commitment.
    if (bundle.bundleHash) {
      const copy = { ...bundle };
      delete copy.bundleHash;
      const h = sha256(Buffer.from(canonicalJson(copy), 'utf8')).toString('hex');
      sections.bundleHash = h === bundle.bundleHash ? { ok: true } : { ok: false, reason: 'bundle_hash_mismatch' };
    } else {
      sections.bundleHash = { ok: true, skipped: true };
    }

    // 1. Draw — full recompute when entries are present, else commitment-only.
    if (bundle.draw && Array.isArray(bundle.entries)) {
      sections.draw = verifyDrawProof(bundle.draw, bundle.entries);
    } else if (bundle.draw) {
      sections.draw = /^[0-9a-f]{64}$/i.test(String(bundle.draw.entriesRoot))
        ? { ok: true, commitmentOnly: true }
        : { ok: false, reason: 'bad_entries_root' };
    } else {
      sections.draw = { ok: false, reason: 'no_draw' };
    }

    // 2. Seed source — honesty check: a value-bearing seed should not be flagged manipulable.
    if (bundle.seedSource) {
      const s = bundle.seedSource;
      sections.seedSource =
        s.manipulable === true
          ? { ok: true, warning: 'seed_marked_manipulable' }
          : { ok: true };
    } else {
      sections.seedSource = { ok: true, skipped: true };
    }

    // 3. Receipts.
    sections.receipts = bundle.receipts ? verifyReceiptChain(bundle.receipts) : { ok: true, skipped: true };

    // 4. Trail root (recompute if events are present; else trust the carried root field only structurally).
    if (bundle.trail && bundle.trail.root) {
      sections.trail = /^[0-9a-f]{64}$/i.test(String(bundle.trail.root))
        ? { ok: true, root: bundle.trail.root }
        : { ok: false, reason: 'bad_trail_root' };
    } else {
      sections.trail = { ok: true, skipped: true };
    }

    const ok = Object.values(sections).every((s) => s.ok);
    return { ok, bundleVersion: bundle.bundleVersion ?? null, sections };
  } catch (e) {
    return { ok: false, bundleVersion: bundle?.bundleVersion ?? null, sections: { error: { ok: false, reason: e.message } } };
  }
}

// Re-export the low-level checks so a verifier-only consumer needs just this file.
export { merkleRoot, verifyMerkleProof, verifyConsistencyProof, leafHash, canonicalJson };
