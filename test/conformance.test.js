import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  merkleRoot,
  consistencyProof,
  verifyConsistencyProof,
  publishDrawProof,
  verifyDrawProof,
  verifyEntryProof,
} from '../src/index.js';

// The frozen conformance suite (SPEC.md §Conformance). A second implementation
// MUST reproduce every value here byte-for-byte; if THIS implementation drifts
// from the published vectors, that is a breaking format change and must be
// deliberate (bump bundleVersion + regenerate vectors).
const V = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url)));

test('merkle root matches frozen vector', () => {
  assert.equal(merkleRoot(V.merkle.items), V.merkle.root);
  assert.equal(merkleRoot([]), V.merkle.empty);
});

test('consistency proof matches frozen vector and verifies', () => {
  const cp = consistencyProof(V.consistency.items, V.consistency.oldSize);
  assert.deepEqual(cp.proof, V.consistency.proof);
  assert.equal(cp.newSize, V.consistency.newSize);
  assert.equal(
    verifyConsistencyProof({
      oldRoot: V.consistency.oldRoot,
      newRoot: V.consistency.newRoot,
      oldSize: V.consistency.oldSize,
      newSize: V.consistency.newSize,
      proof: V.consistency.proof,
    }).ok,
    true,
  );
});

test('draw proof matches frozen vector (winners + indices + root)', () => {
  const p = publishDrawProof({ entries: V.draw.entries, seed: V.draw.seed, winners: V.draw.winners.length });
  assert.equal(p.entriesRoot, V.draw.entriesRoot);
  assert.deepEqual(p.winnerIndices, V.draw.winnerIndices);
  assert.deepEqual(p.winners, V.draw.winners);
  assert.equal(verifyDrawProof(V.draw, V.draw.entries).ok, true);
});

test('entrant inclusion proof matches frozen vector and verifies', () => {
  assert.equal(
    verifyEntryProof({
      entry: V.entryInclusion.entry,
      leaf: V.entryInclusion.leaf,
      path: V.entryInclusion.path,
      entriesRoot: V.draw.entriesRoot,
    }).ok,
    true,
  );
});

test('drand binding vector: randomness == SHA256(signature)', () => {
  const got = createHash('sha256').update(Buffer.from(V.drand.signature, 'hex')).digest('hex');
  assert.equal(got, V.drand.randomness);
});
