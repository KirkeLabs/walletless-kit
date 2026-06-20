import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPii, hashEquals, pseudonymRef, eraseSubject, assertNoPii } from '../src/index.js';

const PEPPER = 'a-very-secret-pepper-value-123';

test('hashPii is keyed, stable, and not equal to a bare hash', () => {
  const h1 = hashPii('alice@example.com', PEPPER);
  const h2 = hashPii('alice@example.com', PEPPER);
  assert.equal(h1, h2); // stable for de-dup
  assert.notEqual(hashPii('alice@example.com', 'different-pepper-value-xyz'), h1);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test('hashPii rejects a weak/short pepper and empty value', () => {
  assert.throws(() => hashPii('a@b.com', 'short'), /pepper/);
  assert.throws(() => hashPii('', PEPPER), /value/);
});

test('hashEquals is constant-time-style and correct', () => {
  const h = hashPii('x@y.com', PEPPER);
  assert.equal(hashEquals(h, h), true);
  assert.equal(hashEquals(h, h.slice(0, -1) + '0'), false);
  assert.equal(hashEquals('a', 'ab'), false);
});

test('pseudonymRef yields a random ref independent of the PII (erasable)', () => {
  const a = pseudonymRef({ contact: 'bob@example.com', pepper: PEPPER });
  const b = pseudonymRef({ contact: 'bob@example.com', pepper: PEPPER });
  // Same contact -> same keyed hash (de-dup) but DIFFERENT random on-chain ref.
  assert.equal(a.contactHash, b.contactHash);
  assert.notEqual(a.ref, b.ref);
  assert.match(a.ref, /^[0-9a-f]{32}$/);
});

test('eraseSubject removes the off-chain mapping (Map and object)', () => {
  const m = new Map([['ref1', { contactHash: 'h' }]]);
  assert.equal(eraseSubject(m, 'ref1').erased, true);
  assert.equal(m.has('ref1'), false);
  assert.equal(eraseSubject(m, 'ref1').erased, false);

  const o = { ref2: { contactHash: 'h' } };
  assert.equal(eraseSubject(o, 'ref2').erased, true);
  assert.equal('ref2' in o, false);
});

test('assertNoPii blocks personal fields from going on-chain', () => {
  assert.equal(assertNoPii({ orderId: 'o1', amount: 5 }), true);
  assert.throws(() => assertNoPii({ orderId: 'o1', email: 'a@b.com' }), /PII/);
  assert.throws(() => assertNoPii({ buyer: { name: 'Bob' } }), /PII/);
});
