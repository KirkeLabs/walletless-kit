import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLedger } from '../src/index.js';

test('conservation holds when allocations + fees do not exceed inflow', () => {
  const l = createLedger();
  l.post({ book: 'inflow', amountMicro: 10_000_000, kind: 'ticket' });
  l.post({ book: 'inflow', amountMicro: 5_000_000, kind: 'ticket' });
  l.post({ book: 'charity', amountMicro: 9_000_000, kind: 'donation' });
  l.post({ book: 'escrow', amountMicro: 3_000_000, kind: 'prize' });
  l.post({ book: 'inflow', amountMicro: 1_000_000, kind: 'fee' });
  const c = l.conservation();
  assert.equal(c.balanced, true);
  assert.equal(c.inflowMicro, 16_000_000);
  assert.equal(c.feesMicro, 1_000_000);
  assert.equal(c.charityMicro, 9_000_000);
  assert.equal(c.escrowMicro, 3_000_000);
  assert.equal(c.retainedMicro, 3_000_000);
  assert.doesNotThrow(() => l.assertConservation());
});

test('conservation fails closed on over-allocation', () => {
  const l = createLedger();
  l.post({ book: 'inflow', amountMicro: 5_000_000, kind: 'ticket' });
  l.post({ book: 'charity', amountMicro: 6_000_000, kind: 'donation' }); // more than came in
  const c = l.conservation();
  assert.equal(c.balanced, false);
  assert.equal(c.retainedMicro, -1_000_000);
  assert.throws(() => l.assertConservation(), /conservation violated/);
});

test('conservation counts fee entries in any book as deductions', () => {
  const l = createLedger();
  l.post({ book: 'inflow', amountMicro: 4_000_000, kind: 'ticket' });
  l.post({ book: 'charity', amountMicro: 3_000_000, kind: 'fee' }); // a fee booked under charity
  const c = l.conservation();
  assert.equal(c.feesMicro, 3_000_000);
  assert.equal(c.charityMicro, 3_000_000);
  // inflow(4m) - fees(3m) - charity(3m) - escrow(0) = -2m
  assert.equal(c.balanced, false);
});
