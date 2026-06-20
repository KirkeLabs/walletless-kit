import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalizeJson, hashCanonicalJson } from '@kirkelabs/open-agent-access-core';
import { canonicalJson } from '../src/merkle.js';

// The zero-dep verifier can only reproduce roots if our canonicalJson is
// byte-identical to oaa-core's canonicalizeJson. This guard locks that invariant:
// if core ever changes its canonicalization, this test fails loudly.
const CASES = [
  'abc',
  '',
  123,
  0,
  1.5,
  true,
  false,
  null,
  'wörld',
  [3, 1, 2],
  { b: 1, a: 2, c: { z: 1, y: 2 } },
  { i: 0, v: 'a' },
  { x: null, y: undefined },
  [{ i: 1, v: 'b' }, { i: 0, v: 'a' }],
  { eventId: 'e1', type: 'x', nested: { q: [1, { m: 2, a: 3 }] } },
  { orderId: 'o1', action: 'buy', quantity: 1, price: '1000000' },
];

test('canonicalJson is byte-identical to oaa-core canonicalizeJson', () => {
  for (const c of CASES) {
    assert.equal(canonicalJson(c), canonicalizeJson(c), `mismatch for ${JSON.stringify(c)}`);
  }
});

test('SHA256(canonicalJson) equals oaa-core hashCanonicalJson', () => {
  for (const c of CASES) {
    const mine = createHash('sha256').update(canonicalJson(c), 'utf8').digest('hex');
    assert.equal(mine, hashCanonicalJson(c), `hash mismatch for ${JSON.stringify(c)}`);
  }
});
