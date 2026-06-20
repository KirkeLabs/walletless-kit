import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDraw, publishDrawProof, verifyDraw, commitSeedSource } from '../src/index.js';

const ENTRIES = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi'];
const SEED = 'block:64520000:deadbeefcafe';

// FROZEN test vector — recomputing this draw must always yield these winners.
test('frozen vector: a fixed seed + entries recompute the exact same winners', () => {
  const r = runDraw({ entries: ENTRIES, seed: SEED, winners: 3 });
  assert.deepEqual(r.winners, ['carol', 'grace', 'heidi']);
  assert.deepEqual(r.winnerIndices, [2, 6, 7]);
  assert.equal(runDraw({ entries: ENTRIES, seed: SEED, winners: 1 }).winners[0], 'carol');
});

test('runDraw is deterministic and seed-sensitive', () => {
  const a = runDraw({ entries: ENTRIES, seed: SEED, winners: 3 });
  const b = runDraw({ entries: ENTRIES, seed: SEED, winners: 3 });
  assert.deepEqual(a.winnerIndices, b.winnerIndices);
  const c = runDraw({ entries: ENTRIES, seed: SEED + 'x', winners: 3 });
  assert.notDeepEqual(a.winnerIndices, c.winnerIndices);
});

test('publishDrawProof + verifyDraw round-trip; tampering fails', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: SEED, winners: 3 });
  assert.equal(verifyDraw(proof, ENTRIES).ok, true);
  // tamper the entry set -> entriesRoot mismatch
  assert.equal(verifyDraw(proof, [...ENTRIES, 'mallory']).reason, 'entries_root_mismatch');
  // tamper the winners -> winner mismatch
  assert.equal(verifyDraw({ ...proof, winnerIndices: [0, 1, 2] }, ENTRIES).ok, false);
});

test('verifyDraw is robust to malformed input', () => {
  for (const [p, e] of [
    [null, ENTRIES],
    [{}, ENTRIES],
    [publishDrawProof({ entries: ENTRIES, seed: SEED }), null],
  ]) {
    assert.equal(verifyDraw(p, e).ok, false);
  }
});

test('runDraw validates inputs', () => {
  assert.throws(() => runDraw({ entries: [], seed: SEED }), /non-empty/);
  assert.throws(() => runDraw({ entries: ENTRIES, seed: '' }), /seed/);
  assert.throws(() => runDraw({ entries: ENTRIES, seed: SEED, winners: 0 }), /winners/);
  assert.throws(() => runDraw({ entries: ENTRIES, seed: SEED, winners: 99 }), /winners/);
});

test('selection is approximately uniform (no obvious modulo bias)', () => {
  // Each of 4 entries should win roughly 1/4 of 4000 single-winner draws.
  const e = ['a', 'b', 'c', 'd'];
  const counts = { a: 0, b: 0, c: 0, d: 0 };
  for (let i = 0; i < 4000; i++) counts[runDraw({ entries: e, seed: `s${i}`, winners: 1 }).winners[0]]++;
  for (const k of e) assert.ok(counts[k] > 800 && counts[k] < 1200, `${k}=${counts[k]} not ~1000`);
});

test('commitSeedSource records the future round (commit-before-reveal)', () => {
  const c = commitSeedSource({ round: 64_530_000, committedAtRound: 64_520_000 });
  assert.equal(c.round, 64_530_000);
  assert.equal(c.source, 'algorand-block');
  assert.match(c.note, /knowable only after/);
});
