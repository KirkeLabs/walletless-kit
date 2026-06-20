import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildOrderReceipt,
  deterministicOrderId,
  verifyReceiptChain,
  signReceipt,
} from '../src/index.js';
import { createReceiptSigningKeyPair } from '@kirkelabs/open-agent-access-core';

const mk = (orderId, action, previousHash, n) =>
  buildOrderReceipt({
    orderId,
    action,
    quantity: 1,
    price: '1000000',
    agent: 'agentX',
    previousHash,
    receiptId: `r_${n}`,
    timestamp: `2026-01-01T00:00:0${n}.000Z`,
  });

test('deterministicOrderId is reproducible and clock/randomness-free', () => {
  const a = deterministicOrderId({ buyer: 'ref1', item: 'ticket', n: 1 });
  const b = deterministicOrderId({ buyer: 'ref1', item: 'ticket', n: 1 });
  assert.equal(a, b);
  assert.notEqual(a, deterministicOrderId({ buyer: 'ref1', item: 'ticket', n: 2 }));
  assert.match(a, /^ord_[0-9a-f]{24}$/);
});

test('receipts hash-chain; tampering any field breaks verification', () => {
  const r1 = mk('o1', 'buy_ticket', null, 1);
  const r2 = mk('o1', 'enter_draw', r1.receiptHash, 2);
  const chain = [r1, r2];
  assert.equal(verifyReceiptChain(chain).ok, true);

  // tamper a field on r2 (hash no longer matches)
  const tampered = [r1, { ...r2, quantity: 999 }];
  const v = verifyReceiptChain(tampered);
  assert.equal(v.ok, false);
  assert.match(v.errors.join(' '), /receiptHash mismatch/);

  // break the chain link
  const broken = [r1, { ...r2, previousHash: 'nope', receiptHash: r2.receiptHash }];
  assert.equal(verifyReceiptChain(broken).ok, false);
});

test('a signed receipt verifies and a tampered signed receipt does not', () => {
  const keys = createReceiptSigningKeyPair();
  const signed = signReceipt(mk('o2', 'buy_ticket', null, 1), {
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
  });
  assert.equal(verifyReceiptChain([signed]).ok, true);
  const bad = { ...signed, action: 'changed' };
  assert.equal(verifyReceiptChain([bad]).ok, false);
});

test('buildOrderReceipt refuses PII fields (never on-chain)', () => {
  assert.throws(
    () => buildOrderReceipt({ orderId: 'o', action: 'a', email: 'x@y.com' }),
    /PII/,
  );
});

test('verifyReceiptChain is robust to malformed input', () => {
  for (const bad of [null, 42, 'x', {}]) {
    assert.equal(verifyReceiptChain(bad).ok, false);
  }
});
