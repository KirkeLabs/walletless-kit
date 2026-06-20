import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  merkleRoot,
  consistencyProof,
  verifyConsistencyProof,
  trailConsistencyProof,
  verifyTrailConsistency,
  createTrail,
  append,
} from '../src/index.js';

const items = (n) => Array.from({ length: n }, (_, i) => ({ i, v: `x${i}` }));

test('consistency proofs verify for every (m, n) with 1 ≤ m ≤ n ≤ 64', () => {
  for (let n = 1; n <= 64; n++) {
    const all = items(n);
    const newRoot = merkleRoot(all);
    for (let m = 1; m <= n; m++) {
      const oldRoot = merkleRoot(all.slice(0, m));
      const { oldSize, newSize, proof } = consistencyProof(all, m);
      const r = verifyConsistencyProof({ oldRoot, newRoot, oldSize, newSize, proof });
      assert.equal(r.ok, true, `m=${m} n=${n}: ${r.reason}`);
    }
  }
});

test('consistency proof fails closed on a REWRITTEN prefix', () => {
  const all = items(10);
  const newRoot = merkleRoot(all);
  const { oldSize, newSize, proof } = consistencyProof(all, 5);
  // an old root over a tampered prefix must not verify as a prefix of newRoot
  const tampered = merkleRoot([{ i: 0 }, { i: 99 }, { i: 2 }, { i: 3 }, { i: 4 }]);
  assert.equal(
    verifyConsistencyProof({ oldRoot: tampered, newRoot, oldSize, newSize, proof }).ok,
    false,
  );
});

test('consistency proof fails on truncated / extended / wrong-root proofs', () => {
  const all = items(11);
  const newRoot = merkleRoot(all);
  const oldRoot = merkleRoot(all.slice(0, 4));
  const { oldSize, newSize, proof } = consistencyProof(all, 4);
  assert.equal(verifyConsistencyProof({ oldRoot, newRoot, oldSize, newSize, proof }).ok, true);
  assert.equal(
    verifyConsistencyProof({ oldRoot, newRoot, oldSize, newSize, proof: proof.slice(0, -1) }).ok,
    false,
  );
  assert.equal(
    verifyConsistencyProof({ oldRoot, newRoot, oldSize, newSize, proof: [...proof, '00'.repeat(32)] }).ok,
    false,
  );
  assert.equal(
    verifyConsistencyProof({ oldRoot, newRoot: 'deadbeef', oldSize, newSize, proof }).ok,
    false,
  );
});

test('verifyConsistencyProof is robust to malformed input (never throws)', () => {
  for (const bad of [null, undefined, {}, { oldSize: 0, newSize: 1 }, { oldSize: 5, newSize: 3 }]) {
    const r = verifyConsistencyProof(bad);
    assert.equal(typeof r.ok, 'boolean');
    assert.equal(r.ok, false);
  }
});

test('trail consistency proves an append-only audit log', () => {
  const ev = (id, t) => ({ eventId: id, type: 'x', timestamp: t });
  let tr = createTrail();
  tr = append(tr, ev('e1', '2026-01-01T00:00:00.000Z'));
  tr = append(tr, ev('e2', '2026-01-01T00:00:01.000Z'));
  const oldRoot = merkleRoot(tr.events);
  const oldSize = tr.events.length;
  tr = append(tr, ev('e3', '2026-01-01T00:00:02.000Z'));
  tr = append(tr, ev('e4', '2026-01-01T00:00:03.000Z'));
  const newRoot = merkleRoot(tr.events);
  const cp = trailConsistencyProof(tr, oldSize);
  assert.equal(verifyTrailConsistency({ oldRoot, newRoot, ...cp }).ok, true);
});
