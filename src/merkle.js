/**
 * merkle.js — the zero-dependency cryptographic core of the kit.
 *
 * This module deliberately depends on NOTHING but `node:crypto`. It is the shared
 * spine for both the proof-PRODUCING side (`audit.js`, `draw.js`) and the
 * independent proof-VERIFYING side (`verify.js`). Keeping it dependency-free is
 * what lets the verifier run anywhere — a browser, an air-gapped box, a second
 * implementation — without trusting algosdk, oaa-core, or even this package.
 *
 * It provides:
 *   - `canonicalJson`        — deterministic JSON (sorted keys), byte-identical to
 *                              @kirkelabs/open-agent-access-core's canonicalizeJson
 *                              (cross-checked by test), so roots match either path.
 *   - `merkleRoot` / proofs  — RFC 6962 domain-separated tree (leaf 0x00, node 0x01)
 *                              with lone-node promotion (no CVE-2012-2459).
 *   - `consistencyProof`     — RFC 6962 §2.1.2 proof that an append-only log only
 *                              GREW between two sizes and was never rewritten.
 *
 * Every function here is pure and deterministic.
 */

import { createHash } from 'node:crypto';

const MAX_LEAVES = 1_000_000; // DoS bound (mirrors audit.js)
export const LEAF = Buffer.from([0x00]);
export const NODE = Buffer.from([0x01]);

export function sha256(...bufs) {
  const h = createHash('sha256');
  for (const b of bufs) h.update(b);
  return h.digest();
}

/**
 * Deterministic JSON: object keys sorted recursively, `undefined` dropped, no
 * insignificant whitespace. Byte-identical to oaa-core's canonicalizeJson for all
 * JSON values the kit hashes (guarded by `test/canonical.test.js`). A primitive
 * (string/number/boolean/null) round-trips through standard JSON.
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value))
    return '[' + value.map((v) => canonicalJson(v === undefined ? null : v)).join(',') + ']';
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/** Injective leaf encoding: domain-tagged hash of the item's canonical JSON. */
export function leafHash(item) {
  return sha256(LEAF, Buffer.from(canonicalJson(item), 'utf8'));
}

/** Internal node hash: H(0x01 ‖ left ‖ right). */
export function nodeHash(left, right) {
  return sha256(NODE, left, right);
}

/**
 * RFC 6962 Merkle Tree Hash over an array of leaf buffers. Bottom-up pairing with
 * lone-node PROMOTION (the odd node is carried up unchanged, never duplicated).
 * This equals the recursive RFC 6962 split-at-largest-power-of-two definition
 * (verified for n = 0..40 in test), so consistency proofs below are valid.
 */
function mthFromLeaves(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return level[0];
}

/**
 * Deterministic Merkle root (hex) over an ordered list of items.
 * Empty list → H("") (RFC 6962 empty-tree root). Single item → its leaf hash.
 */
export function merkleRoot(items) {
  if (!Array.isArray(items)) throw new Error('merkleRoot: items must be an array');
  if (items.length > MAX_LEAVES) throw new Error('merkleRoot: too many leaves');
  return mthFromLeaves(items.map(leafHash)).toString('hex');
}

/**
 * Inclusion proof for the item at `index`: sibling hashes (hex) + their side,
 * which `verifyMerkleProof` replays to recompute the root.
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
        next.push(nodeHash(level[i], level[i + 1]));
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

/** Verify an inclusion proof against an expected root. Never throws. */
export function verifyMerkleProof({ leaf, path, root }) {
  try {
    let acc = Buffer.from(String(leaf), 'hex');
    for (const step of path || []) {
      const sib = Buffer.from(String(step.hash), 'hex');
      acc = step.side === 'left' ? nodeHash(sib, acc) : nodeHash(acc, sib);
    }
    return { ok: acc.toString('hex') === String(root) };
  } catch (e) {
    return { ok: false, reason: `verify_error:${e.message}` };
  }
}

// ─── RFC 6962 consistency proofs ─────────────────────────────────────────────
// A consistency proof shows that the tree of size `m` is a PREFIX of the tree of
// size `n` (m ≤ n): every leaf of the old tree is still present, unchanged, in the
// same position. This is the Certificate-Transparency primitive that turns
// "tamper-evident snapshot" into "provably append-only history": anyone holding an
// old anchored root can prove the operator only appended and never rewrote it.

/** MTH over a slice of leaf buffers (RFC 6962 recursive split). */
function mthRange(leaves, start, end) {
  return mthFromLeaves(leaves.slice(start, end));
}

/** Largest power of two strictly less than n (the RFC 6962 split point). */
function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** SUBPROOF(m, leaves[start:end], b) per RFC 6962 §2.1.2. */
function subproof(m, leaves, start, end, b) {
  const n = end - start;
  if (m === n) {
    // The subtree is fully contained in the old tree.
    return b ? [] : [mthRange(leaves, start, end)];
  }
  const k = splitPoint(n);
  if (m <= k) {
    const proof = subproof(m, leaves, start, start + k, b);
    proof.push(mthRange(leaves, start + k, end));
    return proof;
  }
  const proof = subproof(m - k, leaves, start + k, end, false);
  proof.push(mthRange(leaves, start, start + k));
  return proof;
}

/**
 * Build a consistency proof that the first `oldSize` items (the old tree) are a
 * prefix of the full `items` (the new tree). Returns hex node hashes.
 * @param {any[]} items   the FULL current ordered list (length = new size)
 * @param {number} oldSize  the earlier, anchored size (1 ≤ oldSize ≤ items.length)
 * @returns {{oldSize:number,newSize:number,proof:string[]}}
 */
export function consistencyProof(items, oldSize) {
  if (!Array.isArray(items)) throw new Error('consistencyProof: items must be an array');
  const newSize = items.length;
  const m = Number(oldSize);
  if (!Number.isInteger(m) || m < 1 || m > newSize)
    throw new Error('consistencyProof: oldSize must be an integer in [1, items.length]');
  const leaves = items.map(leafHash);
  const nodes = m === newSize ? [] : subproof(m, leaves, 0, newSize, true);
  return { oldSize: m, newSize, proof: nodes.map((b) => b.toString('hex')) };
}

/**
 * Verify a consistency proof: that `oldRoot` (size m) is a prefix of `newRoot`
 * (size n). Pure replay of RFC 6962 §2.1.2 verification. Never throws.
 * @returns {{ok:boolean, reason?:string}}
 */
export function verifyConsistencyProof(args) {
  try {
    const { oldRoot, newRoot, oldSize, newSize, proof } = args || {};
    const m = Number(oldSize);
    const n = Number(newSize);
    if (!Number.isInteger(m) || !Number.isInteger(n) || m < 1 || m > n)
      return { ok: false, reason: 'bad_sizes' };

    // m == n: identical trees — roots must match and the proof must be empty.
    if (m === n) {
      return String(oldRoot) === String(newRoot) && (proof || []).length === 0
        ? { ok: true }
        : { ok: false, reason: 'size_equal_mismatch' };
    }

    // Canonical RFC 6962 consistency-proof verification (certificate-transparency
    // reference). Walk the node/last_node indices, consuming proof nodes in order.
    const nodes = (proof || []).map((h) => Buffer.from(String(h), 'hex'));
    let p = 0;
    const next = () => {
      if (p >= nodes.length) throw new Error('proof_exhausted');
      return nodes[p++];
    };

    let node = m - 1;
    let last = n - 1;
    while (node % 2 === 1) {
      node = Math.floor(node / 2);
      last = Math.floor(last / 2);
    }

    // If `node` reduced to 0, old tree was a perfect subtree and oldRoot is the
    // implicit first hash; otherwise the first proof node seeds both accumulators.
    let oldHash = node ? next() : Buffer.from(String(oldRoot), 'hex');
    let newHash = oldHash;

    while (node) {
      if (node % 2 === 1) {
        const sib = next(); // right child → sibling on the left
        oldHash = nodeHash(sib, oldHash);
        newHash = nodeHash(sib, newHash);
      } else if (node < last) {
        newHash = nodeHash(newHash, next()); // left child with a right sibling
      }
      node = Math.floor(node / 2);
      last = Math.floor(last / 2);
    }
    while (last) {
      newHash = nodeHash(newHash, next());
      last = Math.floor(last / 2);
    }

    if (p !== nodes.length) return { ok: false, reason: 'proof_too_long' };
    const ok =
      oldHash.toString('hex') === String(oldRoot) &&
      newHash.toString('hex') === String(newRoot);
    return ok ? { ok: true } : { ok: false, reason: 'root_mismatch' };
  } catch (e) {
    return { ok: false, reason: `verify_error:${e.message}` };
  }
}
