import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  publishDrawProof,
  buildOrderReceipt,
  createTrail,
  append,
  bundleProof,
  verifyBundle,
  verifyDrawProof,
  BUNDLE_VERSION,
} from '../src/index.js';

const ENTRIES = ['refA', 'refB', 'refC', 'refD', 'refE'];

function chainOf(n) {
  const receipts = [];
  let prev = null;
  for (let i = 0; i < n; i++) {
    const r = buildOrderReceipt({
      orderId: `o${i}`,
      action: 'buy_ticket',
      quantity: 1,
      price: '1000000',
      receiptId: `r${i}`,
      timestamp: `2026-01-01T00:00:0${i}.000Z`,
      previousHash: prev,
    });
    receipts.push(r);
    prev = r.receiptHash;
  }
  return receipts;
}

test('verifyDrawProof independently re-derives the winners (agrees with producer)', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed-seed-v1', winners: 2 });
  assert.equal(verifyDrawProof(proof, ENTRIES).ok, true);
});

test('verifyDrawProof fails on tampered entries / seed / winners', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed-seed-v1', winners: 2 });
  assert.equal(verifyDrawProof(proof, [...ENTRIES.slice(0, 4), 'X']).ok, false);
  assert.equal(verifyDrawProof({ ...proof, seed: 'evil' }, ENTRIES).ok, false);
  assert.equal(verifyDrawProof({ ...proof, winners: ['refZ', 'refA'] }, ENTRIES).ok, false);
});

test('full bundle round-trips and verifies every section', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed-seed-v1', winners: 2 });
  let tr = createTrail();
  tr = append(tr, { eventId: 'e1', type: 'sold', timestamp: '2026-01-01T00:00:00.000Z' });
  const bundle = bundleProof({
    drawProof: proof,
    entries: ENTRIES,
    seedSource: { source: 'drand', value: 'abc', manipulable: false },
    receipts: chainOf(3),
    trail: tr,
    anchors: { txid: 'TX', round: 1, root: proof.entriesRoot },
    meta: { drawId: 'd1' },
  });
  assert.equal(bundle.bundleVersion, BUNDLE_VERSION);
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true, JSON.stringify(v.sections));
  for (const s of Object.values(v.sections)) assert.equal(s.ok, true);
});

test('commitment-only bundle verifies without entries; flags a manipulable seed', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed-seed-v1' });
  const bundle = bundleProof({ drawProof: proof, seedSource: { source: 'algorand-block-seed', manipulable: true } });
  const v = verifyBundle(bundle);
  assert.equal(v.ok, true);
  assert.equal(v.sections.draw.commitmentOnly, true);
  assert.equal(v.sections.seedSource.warning, 'seed_marked_manipulable');
});

test('tampering any bundle field is detected (self-commitment + recompute)', () => {
  const proof = publishDrawProof({ entries: ENTRIES, seed: 'committed-seed-v1', winners: 1 });
  const bundle = bundleProof({ drawProof: proof, entries: ENTRIES });
  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.draw.winners = ['refC'];
  assert.equal(verifyBundle(tampered).ok, false);
});

test('verifyBundle is robust to malformed input (never throws)', () => {
  for (const bad of [null, undefined, 42, 'x', {}, { draw: null }]) {
    assert.equal(typeof verifyBundle(bad).ok, 'boolean');
  }
});
