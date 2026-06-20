/**
 * draw.js — a verifiable, recomputable draw.
 *
 * The winner is a DETERMINISTIC function of (public seed, ordered entries), so
 * anyone can recompute it from the published proof. Fairness is therefore exactly
 * as strong as the seed — no more (see LEGAL.md / README):
 *   - A blockchain BLOCK HASH is manipulable: a block producer can withhold or
 *     grind a block to bias the outcome. Mitigate with `commitSeedSource` (announce
 *     the exact future round whose hash will be the seed BEFORE entries close, so
 *     the operator cannot pick a favourable one), and prefer a VRF / drand beacon
 *     for anything of value.
 *   - Randomness comes from a CSPRNG-style expansion of the seed (SHA-256 stream)
 *     with REJECTION SAMPLING (no modulo bias). There is no `Math.random` here.
 *
 * `runDraw` and `verifyDraw` are pure and recomputable; ship the frozen test
 * vector in the tests as the canonical reference.
 */

import { createHash } from 'node:crypto';
import { merkleRoot } from './audit.js';

const MAX_ENTRIES = 5_000_000;
const ALGORITHM = 'fisher-yates-sha256-v1';

function sha256(...bufs) {
  const h = createHash('sha256');
  for (const b of bufs) h.update(b);
  return h.digest();
}

/** Deterministic byte stream from a seed: SHA-256(seed ‖ ':' ‖ counterLE). */
function makeRng(seed) {
  const seedBuf = Buffer.from(String(seed), 'utf8');
  let counter = 0;
  let pool = Buffer.alloc(0);
  let used = 0;
  const refill = () => {
    const c = Buffer.alloc(8);
    c.writeUInt32LE(counter >>> 0, 0);
    c.writeUInt32LE(Math.floor(counter / 2 ** 32) >>> 0, 4);
    pool = sha256(seedBuf, Buffer.from(':'), c);
    counter += 1;
    used = 0;
  };
  return {
    nextBytes(n) {
      const out = Buffer.alloc(n);
      let o = 0;
      while (o < n) {
        if (used >= pool.length) refill();
        const take = Math.min(n - o, pool.length - used);
        pool.copy(out, o, used, used + take);
        used += take;
        o += take;
      }
      return out;
    },
  };
}

/** Uniform integer in [0, maxExclusive) via 48-bit rejection sampling (unbiased). */
function uniformInt(rng, maxExclusive) {
  if (maxExclusive <= 1) return 0;
  const span = 0x1000000000000; // 2^48
  const limit = Math.floor(span / maxExclusive) * maxExclusive;
  for (;;) {
    const v = rng.nextBytes(6).readUIntBE(0, 6);
    if (v < limit) return v % maxExclusive;
  }
}

/** Deterministic Fisher–Yates shuffle of a copy of `items`, driven by `seed`. */
function shuffle(items, seed) {
  const a = items.slice();
  const rng = makeRng(seed);
  for (let i = a.length - 1; i >= 1; i--) {
    const j = uniformInt(rng, i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Run a draw. Deterministic and recomputable.
 * @param {{entries:string[], seed:string, winners?:number, algorithm?:string}} opts
 * @returns {{winners:string[], winnerIndices:number[], algorithm:string, seed:string, entryCount:number}}
 */
export function runDraw({ entries, seed, winners = 1, algorithm = ALGORITHM }) {
  if (!Array.isArray(entries) || entries.length === 0)
    throw new Error('runDraw: entries must be a non-empty array');
  if (entries.length > MAX_ENTRIES) throw new Error('runDraw: too many entries');
  if (seed == null || String(seed).length === 0) throw new Error('runDraw: seed is required');
  if (algorithm !== ALGORITHM) throw new Error(`runDraw: unsupported algorithm ${algorithm}`);
  const k = Number(winners);
  if (!Number.isInteger(k) || k < 1 || k > entries.length)
    throw new Error('runDraw: winners must be an integer in [1, entries.length]');

  const order = shuffle(
    entries.map((_, i) => i),
    seed,
  );
  const winnerIndices = order.slice(0, k);
  return {
    winners: winnerIndices.map((i) => entries[i]),
    winnerIndices,
    algorithm,
    seed: String(seed),
    entryCount: entries.length,
  };
}

/**
 * A publishable proof: the seed, algorithm, a commitment to the exact entry set
 * (Merkle root), and the resulting winners. Anyone can recompute with `verifyDraw`.
 */
export function publishDrawProof({ entries, seed, winners = 1, algorithm = ALGORITHM }) {
  const result = runDraw({ entries, seed, winners, algorithm });
  return {
    algorithm: result.algorithm,
    seed: result.seed,
    entryCount: result.entryCount,
    entriesRoot: merkleRoot(entries), // commits to the exact ordered entry set
    winners: result.winners,
    winnerIndices: result.winnerIndices,
  };
}

/**
 * Recompute a draw from its proof + the entry set and confirm the winners match
 * and the entries match the committed root. Robust to malformed input.
 * @returns {{ok:boolean, reason?:string}}
 */
export function verifyDraw(proof, entries) {
  try {
    if (!proof || !Array.isArray(entries)) return { ok: false, reason: 'bad_input' };
    if (merkleRoot(entries) !== proof.entriesRoot) return { ok: false, reason: 'entries_root_mismatch' };
    const re = runDraw({
      entries,
      seed: proof.seed,
      winners: proof.winnerIndices?.length ?? 1,
      algorithm: proof.algorithm,
    });
    const same =
      re.winnerIndices.length === proof.winnerIndices.length &&
      re.winnerIndices.every((v, i) => v === proof.winnerIndices[i]);
    return same ? { ok: true } : { ok: false, reason: 'winner_mismatch' };
  } catch (e) {
    return { ok: false, reason: `verify_error:${e.message}` };
  }
}

// ─── Seed adapters ──────────────────────────────────────────────────────────
// Each returns { source, value, ...context }. Document manipulability honestly.

/**
 * Publish a SEED COMMITMENT *before* entries close: it names the exact future
 * round whose block hash will be the seed, so the operator cannot later pick a
 * favourable seed. Reveal the hash (via `blockHashSeed`) only after that round.
 */
export function commitSeedSource({ source = 'algorand-block', round, committedAtRound }) {
  if (!Number.isInteger(Number(round))) throw new Error('commitSeedSource: round is required');
  return {
    source,
    round: Number(round),
    committedAtRound: committedAtRound == null ? null : Number(committedAtRound),
    note: 'Seed = hash of the named round, knowable only after that round is produced.',
  };
}

/**
 * Derive a seed from an Algorand block's sortition SEED (`block.header.seed`, a
 * 32-byte VRF-derived value). ⚠ A block proposer can still influence or withhold a
 * block to bias the outcome — only use with `commitSeedSource` (commit the round
 * in advance, before entries close) and prefer a VRF/beacon for high-value draws.
 */
export async function blockHashSeed(algod, round) {
  const blk = await algod.block(Number(round)).do();
  const header = blk?.block?.header ?? blk?.block ?? blk;
  const seed = header?.seed;
  let value;
  if (seed instanceof Uint8Array || Buffer.isBuffer(seed)) value = Buffer.from(seed).toString('hex');
  else if (typeof seed === 'string') value = Buffer.from(seed, 'base64').toString('hex');
  else throw new Error(`blockHashSeed: could not read block seed for round ${round}`);
  return { source: 'algorand-block-seed', round: Number(round), value, manipulable: true };
}

/** Wrap a VRF output (you supply the verified value+proof from your VRF). */
export function vrfSeed({ value, proof, publicKey }) {
  if (!value) throw new Error('vrfSeed: value is required');
  return { source: 'vrf', value: String(value), proof: proof ?? null, publicKey: publicKey ?? null };
}

/** Wrap a public randomness-beacon value (e.g. drand). */
export function beaconSeed({ value, round, beacon = 'drand' }) {
  if (!value) throw new Error('beaconSeed: value is required');
  return { source: 'beacon', beacon, round: round == null ? null : Number(round), value: String(value) };
}
