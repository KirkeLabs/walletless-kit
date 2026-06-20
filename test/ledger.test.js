import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLedger } from '../src/index.js';

test('money must be an integer microALGO — floats are rejected', () => {
  const l = createLedger();
  assert.throws(() => l.post({ book: 'inflow', amountMicro: 1.5 }), /integer/);
  assert.throws(() => l.post({ book: 'inflow', amountMicro: -1 }), /integer/);
  assert.throws(() => l.post({ book: 'nope', amountMicro: 1 }), /unknown book/);
});

test('books are segregated and balances are integer sums', () => {
  const l = createLedger();
  l.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'ticket' });
  l.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'ticket' });
  l.post({ book: 'charity', amountMicro: 1_500_000, ref: 'CHARITY_ADDR', txRef: 'tx1' });
  l.post({ book: 'escrow', amountMicro: 500_000, ref: 'prize', txRef: 'tx2' });
  assert.deepEqual(l.balances(), { inflow: 2_000_000, charity: 1_500_000, escrow: 500_000 });
});

test('snapshot is deep-frozen and cannot be mutated', () => {
  const l = createLedger();
  l.post({ book: 'inflow', amountMicro: 100, kind: 'ticket' });
  const snap = l.snapshot();
  assert.throws(() => snap.books.inflow.push({ hack: true }), TypeError);
  assert.throws(() => {
    snap.books.inflow[0].amountMicro = 999;
  }, TypeError);
  // further posts do not retro-change an existing snapshot
  l.post({ book: 'inflow', amountMicro: 100, kind: 'ticket' });
  assert.equal(snap.books.inflow.length, 1);
});

test('reconciliationSheet is deterministic and adds up', () => {
  const l = createLedger();
  l.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'ticket' });
  l.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'ticket' });
  l.post({ book: 'inflow', amountMicro: 100_000, kind: 'fee' });
  l.post({ book: 'charity', amountMicro: 1_400_000, ref: 'CH', txRef: 'tx1' });
  l.post({ book: 'escrow', amountMicro: 500_000, ref: 'prize', txRef: 'tx2' });
  const s = l.reconciliationSheet('draw-1', { winnerProofLink: 'ipfs://proof' });
  assert.equal(s.ticketsSold, 2);
  assert.equal(s.grossMicroAlgos, 2_100_000);
  assert.equal(s.feesMicroAlgos, 100_000);
  assert.equal(s.charity.totalMicroAlgos, 1_400_000);
  assert.equal(s.charity.destinations[0].address, 'CH');
  assert.equal(s.escrow.totalMicroAlgos, 500_000);
  assert.equal(s.netMicroAlgos, 2_100_000 - 100_000 - 1_400_000 - 500_000);
  assert.equal(s.winnerProofLink, 'ipfs://proof');
  // deterministic
  assert.deepEqual(s, l.reconciliationSheet('draw-1', { winnerProofLink: 'ipfs://proof' }));
});
