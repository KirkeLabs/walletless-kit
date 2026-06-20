import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  publishDrawProof,
  entryProof,
  verifyEntryProof,
  drandSeed,
  drandRoundAt,
  fetchDrandRound,
  runDraw,
  DRAND_QUICKNET,
} from '../src/index.js';

const ENTRIES = ['refA', 'refB', 'refC', 'refD', 'refE', 'refF', 'refG'];

test('entry inclusion proof verifies for every entrant against entriesRoot', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed', winners: 2 });
  for (let i = 0; i < ENTRIES.length; i++) {
    const ep = entryProof(ENTRIES, i);
    assert.equal(
      verifyEntryProof({ entry: ep.entry, leaf: ep.leaf, path: ep.path, entriesRoot: proof.entriesRoot }).ok,
      true,
    );
  }
});

test('entry inclusion proof fails closed on wrong entry / leaf / root', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed' });
  const ep = entryProof(ENTRIES, 3);
  assert.equal(verifyEntryProof({ entry: 'refX', leaf: ep.leaf, path: ep.path, entriesRoot: proof.entriesRoot }).ok, false);
  assert.equal(verifyEntryProof({ entry: ep.entry, leaf: '00'.repeat(32), path: ep.path, entriesRoot: proof.entriesRoot }).ok, false);
  assert.equal(verifyEntryProof({ entry: ep.entry, leaf: ep.leaf, path: ep.path, entriesRoot: 'deadbeef' }).ok, false);
});

test('verifyEntryProof never throws on malformed input', () => {
  for (const bad of [null, undefined, {}, { entry: 1, leaf: 'zz', path: 'no', entriesRoot: 5 }]) {
    assert.equal(typeof verifyEntryProof(bad).ok, 'boolean');
  }
});

// drand: randomness == SHA256(signature) binding
const sig = '1a2b3c4d5e6f';
const rand = createHash('sha256').update(Buffer.from(sig, 'hex')).digest('hex');

test('drandSeed accepts a well-bound beacon and is marked non-manipulable', async () => {
  const seed = await drandSeed({ round: 1234, randomness: rand, signature: sig, chainHash: 'abc' });
  assert.equal(seed.source, 'drand');
  assert.equal(seed.value, rand);
  assert.equal(seed.manipulable, false);
  assert.equal(seed.blsVerified, false);
  // usable as a seed
  assert.equal(runDraw({ entries: ENTRIES, seed: seed.value }).winners.length, 1);
});

test('drandSeed rejects a forged randomness/signature pair', async () => {
  await assert.rejects(() => drandSeed({ round: 1234, randomness: '00'.repeat(32), signature: sig }), /does not match/);
});

test('drandSeed enforces an optional BLS verifier hook', async () => {
  const ok = await drandSeed({ round: 5, randomness: rand, signature: sig }, async () => true);
  assert.equal(ok.blsVerified, true);
  await assert.rejects(() => drandSeed({ round: 5, randomness: rand, signature: sig }, async () => false), /BLS/);
});

test('drandRoundAt computes a future round from the quicknet genesis/period', () => {
  assert.equal(drandRoundAt(DRAND_QUICKNET.genesisTime), 1);
  assert.equal(drandRoundAt(DRAND_QUICKNET.genesisTime + 30), 11); // 30s / 3s + 1
  assert.throws(() => drandRoundAt(DRAND_QUICKNET.genesisTime - 1), /before genesis/);
});

test('fetchDrandRound uses an injectable fetch (offline-testable)', async () => {
  const fakeFetch = async (url) => {
    assert.match(url, /public\/777$/);
    return { ok: true, json: async () => ({ round: 777, randomness: rand, signature: sig }) };
  };
  const b = await fetchDrandRound(777, { fetch: fakeFetch });
  assert.equal(b.round, 777);
  const seed = await drandSeed(b);
  assert.equal(seed.round, 777);
});
