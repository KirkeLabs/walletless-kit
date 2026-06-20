import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createTrail,
  append,
  merkleRoot,
  merkleProof,
  verifyMerkleProof,
  verifyTrail,
} from '../src/index.js';

// FROZEN test vectors — these MUST NOT change without a deliberate, documented
// reason (a change means the Merkle construction changed).
const THREE = [
  { i: 0, v: 'a' },
  { i: 1, v: 'b' },
  { i: 2, v: 'c' },
];

test('merkleRoot frozen vectors (empty / single / three)', () => {
  assert.equal(
    merkleRoot([]),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
  assert.equal(
    merkleRoot([{ i: 0 }]),
    'd829edd0713a1bb05e3cd0616924a4c5bde21e36e537149a20239edafa8825f1',
  );
  assert.equal(
    merkleRoot(THREE),
    'ad9038016cbac0607a9d55697fc95fb4ba2479957c19b7442c0381136d984ccb',
  );
});

test('merkleRoot is stable and order-sensitive; any edit changes the root', () => {
  assert.equal(merkleRoot(THREE), merkleRoot(THREE)); // deterministic
  assert.notEqual(merkleRoot(THREE), merkleRoot([THREE[1], THREE[0], THREE[2]])); // order matters
  const edited = [THREE[0], { i: 1, v: 'B' }, THREE[2]];
  assert.notEqual(merkleRoot(THREE), merkleRoot(edited)); // tamper detected
});

test('domain separation: a 2-leaf root is not forgeable as a single leaf', () => {
  // If leaves and internal nodes shared a hash domain, an attacker could present
  // the concatenation of two leaves as one leaf and match the root. With RFC-6962
  // tagging (leaf 0x00, node 0x01) the 2-leaf root differs from any single-leaf root.
  const twoLeaf = merkleRoot([{ i: 0 }, { i: 1 }]);
  assert.notEqual(twoLeaf, merkleRoot([{ i: 0 }]));
  assert.notEqual(twoLeaf, merkleRoot([twoLeaf]));
  assert.match(twoLeaf, /^[0-9a-f]{64}$/);
});

test('inclusion proofs verify and fail closed on tampering', () => {
  const root = merkleRoot(THREE);
  for (let i = 0; i < THREE.length; i++) {
    const p = merkleProof(THREE, i);
    assert.equal(verifyMerkleProof({ leaf: p.leaf, path: p.path, root }).ok, true);
  }
  // wrong root -> rejected; corrupt leaf -> rejected
  const p1 = merkleProof(THREE, 1);
  assert.equal(verifyMerkleProof({ leaf: p1.leaf, path: p1.path, root: 'deadbeef' }).ok, false);
  assert.equal(
    verifyMerkleProof({ leaf: '00'.repeat(32), path: p1.path, root }).ok,
    false,
  );
});

// Deterministic events (explicit eventId/timestamp) so the trail is reproducible.
const ev = (eventId, type, t) => ({ eventId, type, orderId: 'o1', timestamp: t });
function deterministicTrail() {
  let tr = createTrail();
  tr = append(tr, ev('e1', 'order_created', '2026-01-01T00:00:00.000Z'));
  tr = append(tr, ev('e2', 'payment_received', '2026-01-01T00:00:01.000Z'));
  tr = append(tr, ev('e3', 'entry_recorded', '2026-01-01T00:00:02.000Z'));
  return tr;
}

test('verifyTrail accepts an intact hash-chained trail and returns a root', () => {
  const r = verifyTrail(deterministicTrail());
  assert.equal(r.ok, true);
  assert.equal(r.count, 3);
  assert.match(r.root, /^[0-9a-f]{64}$/);
});

test('verifyTrail detects an EDITED event', () => {
  const tr = deterministicTrail();
  tr.events[1] = { ...tr.events[1], type: 'tampered' }; // hash no longer matches
  const r = verifyTrail(tr);
  assert.equal(r.ok, false);
  assert.ok(r.errors.length > 0);
});

test('verifyTrail detects a REMOVED event', () => {
  const tr = deterministicTrail();
  const r = verifyTrail({ events: tr.events.slice(1) }); // drop the first event
  assert.equal(r.ok, false);
});

test('verifyTrail is robust to malformed input (never throws)', () => {
  for (const bad of [null, undefined, 42, 'x', {}, { events: 'no' }, { events: [null] }]) {
    const r = verifyTrail(bad);
    assert.equal(typeof r.ok, 'boolean');
    assert.equal(r.ok, false);
  }
});
