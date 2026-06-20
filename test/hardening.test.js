import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  merkleRoot,
  verifyTrail,
  runDraw,
  verifyDraw,
  publishDrawProof,
} from '../src/index.js';

const srcDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

test('no Math.random anywhere in src/ (randomness must be CSPRNG)', () => {
  for (const f of readdirSync(srcDir).filter((f) => f.endsWith('.js'))) {
    const code = readFileSync(join(srcDir, f), 'utf8');
    // Match the call form so prose/comments mentioning Math.random don't trip it.
    assert.equal(/Math\.random\s*\(/.test(code), false, `${f} calls Math.random`);
  }
});

// Deterministic PRNG for reproducible fuzzing.
let seed = 0x9e3779b9;
const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed / 0x7fffffff);
const pick = (a) => a[Math.floor(rnd() * a.length)];

test('fuzz: merkleRoot never throws on well-formed arrays and is deterministic', () => {
  for (let i = 0; i < 800; i++) {
    const n = Math.floor(rnd() * 12);
    const items = Array.from({ length: n }, (_, k) => ({ k, v: pick(['a', 'b', 'c', 1, null, true]) }));
    const r1 = merkleRoot(items);
    const r2 = merkleRoot(items);
    assert.match(r1, /^[0-9a-f]{64}$/);
    assert.equal(r1, r2);
  }
});

test('fuzz: verifyTrail never throws and never returns ok for junk', () => {
  for (let i = 0; i < 800; i++) {
    const junk = pick([
      null,
      undefined,
      42,
      'str',
      {},
      { events: null },
      { events: [pick([null, {}, { eventHash: 'x' }, { previousEventHash: 'y' }])] },
      [pick([null, {}, { foo: 1 }])],
    ]);
    const r = verifyTrail(junk);
    assert.equal(typeof r.ok, 'boolean');
    assert.equal(r.ok, false); // none of these are a valid hash-chained trail
  }
});

test('fuzz: runDraw winners are always a valid subset, recomputable & verifiable', () => {
  for (let i = 0; i < 600; i++) {
    const n = 1 + Math.floor(rnd() * 10);
    const entries = Array.from({ length: n }, (_, k) => `e${k}`);
    const winners = 1 + Math.floor(rnd() * n);
    const seedStr = `seed-${i}-${rnd()}`;
    const r = runDraw({ entries, seed: seedStr, winners });
    assert.equal(r.winners.length, winners);
    assert.equal(new Set(r.winnerIndices).size, winners); // distinct winners
    for (const w of r.winners) assert.ok(entries.includes(w));
    const proof = publishDrawProof({ entries, seed: seedStr, winners });
    assert.equal(verifyDraw(proof, entries).ok, true);
  }
});

test('fuzz: verifyDraw never throws on malformed proofs', () => {
  for (let i = 0; i < 400; i++) {
    const p = pick([null, {}, { entriesRoot: 'x' }, { winnerIndices: [0] }, 42, 'p']);
    const e = pick([null, [], ['a', 'b'], 'x']);
    const r = verifyDraw(p, e);
    assert.equal(typeof r.ok, 'boolean');
  }
});
