import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  makeDrandVerifier,
  verifyDrandBeacon,
  DRAND_QUICKNET_SCHEME,
  DRAND_DEFAULT_SCHEME,
} from '../src/drand-bls.js';
import { drandSeed } from '../src/index.js';

// Frozen REAL drand beacon rounds (captured from api.drand.sh). These are public,
// immutable network outputs — the BLS verification below runs fully offline.
const V = JSON.parse(readFileSync(new URL('./drand-vectors.json', import.meta.url)));

test('hardcoded scheme public keys match the live network keys in the vectors', () => {
  assert.equal(DRAND_QUICKNET_SCHEME.publicKey, V.quicknet.publicKey);
  assert.equal(DRAND_DEFAULT_SCHEME.publicKey, V.defaultMainnet.publicKey);
});

test('verifyDrandBeacon validates real quicknet (unchained, G1) rounds', () => {
  for (const r of V.quicknet.rounds) {
    assert.equal(
      verifyDrandBeacon(r, { publicKey: V.quicknet.publicKey, schemeID: V.quicknet.schemeID }),
      true,
      `quicknet round ${r.round} should verify`,
    );
  }
});

test('verifyDrandBeacon validates real chained mainnet (G2) rounds', () => {
  for (const r of V.defaultMainnet.rounds) {
    assert.equal(
      verifyDrandBeacon(r, { publicKey: V.defaultMainnet.publicKey, schemeID: V.defaultMainnet.schemeID }),
      true,
      `default round ${r.round} should verify`,
    );
  }
});

test('verifyDrandBeacon rejects a wrong round, wrong sig, and forged randomness', () => {
  const [r] = V.quicknet.rounds;
  const opts = { publicKey: V.quicknet.publicKey, schemeID: V.quicknet.schemeID };
  assert.equal(verifyDrandBeacon({ ...r, round: r.round + 1 }, opts), false); // signature is for the real round
  assert.equal(verifyDrandBeacon({ ...r, signature: V.quicknet.rounds[1].signature }, opts), false);
  assert.equal(verifyDrandBeacon({ ...r, randomness: '00'.repeat(32) }, opts), false); // binding fails
});

test('verifyDrandBeacon fails closed on unknown scheme / missing key', () => {
  const [r] = V.quicknet.rounds;
  assert.equal(verifyDrandBeacon(r, { publicKey: V.quicknet.publicKey, schemeID: 'nope' }), false);
  assert.equal(verifyDrandBeacon(r, { schemeID: V.quicknet.schemeID }), false);
  assert.equal(verifyDrandBeacon(null, { publicKey: 'x', schemeID: 'y' }), false);
});

test('chained verification requires the previous signature', () => {
  const [r] = V.defaultMainnet.rounds;
  assert.equal(
    verifyDrandBeacon({ ...r, previous_signature: undefined, previousSignature: undefined }, {
      publicKey: V.defaultMainnet.publicKey,
      schemeID: V.defaultMainnet.schemeID,
    }),
    false,
  );
});

test('makeDrandVerifier returns a hook drandSeed accepts (full verified seed)', async () => {
  const verify = makeDrandVerifier(DRAND_QUICKNET_SCHEME);
  const r = V.quicknet.rounds[1];
  const seed = await drandSeed(r, verify);
  assert.equal(seed.source, 'drand');
  assert.equal(seed.value, r.randomness);
  assert.equal(seed.manipulable, false);
  assert.equal(seed.blsVerified, true);
});

test('makeDrandVerifier makes drandSeed reject a tampered beacon', async () => {
  const verify = makeDrandVerifier(DRAND_QUICKNET_SCHEME);
  // valid binding (randomness matches this signature) but signature is for a different round
  const good = V.quicknet.rounds[0];
  const other = V.quicknet.rounds[1];
  await assert.rejects(
    () => drandSeed({ round: other.round, randomness: good.randomness, signature: good.signature }, verify),
    /BLS signature verification failed/,
  );
});

test('makeDrandVerifier resolves a known scheme by id and validates key length', () => {
  assert.equal(typeof makeDrandVerifier('bls-unchained-g1-rfc9380'), 'function');
  assert.throws(() => makeDrandVerifier('unknown-scheme'), /unknown scheme/);
  assert.throws(
    () => makeDrandVerifier(DRAND_QUICKNET_SCHEME, { publicKey: 'abcd' }),
    /must be 96 bytes/,
  );
});
