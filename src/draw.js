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
import { merkleRoot, merkleProof, verifyMerkleProof, leafHash } from './merkle.js';

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

// ─── Entrant inclusion proofs ────────────────────────────────────────────────
// A draw proof commits to the exact entry set via `entriesRoot`. These let a
// single entrant verify "my reference was in the set that produced the winner",
// against the published root alone — WITHOUT being handed every other entrant's
// reference (which would leak the field). Answers "were my tickets counted?".

/**
 * Inclusion proof that `entries[index]` is committed by `entriesRoot`.
 * Hand the returned object (plus the public `entriesRoot`) to the entrant.
 * @returns {{entry:any, index:number, leaf:string, path:{side:string,hash:string}[]}}
 */
export function entryProof(entries, index) {
  if (!Array.isArray(entries) || index < 0 || index >= entries.length)
    throw new Error('entryProof: index out of range');
  const { leaf, path } = merkleProof(entries, index);
  return { entry: entries[index], index, leaf, path };
}

/**
 * Verify an entrant inclusion proof against the published `entriesRoot`. Checks
 * BOTH that the proof recomputes the root AND that its leaf is the hash of the
 * claimed `entry` (so the proof can't be replayed for a different value).
 * Robust to malformed input (never throws).
 * @returns {{ok:boolean, reason?:string}}
 */
export function verifyEntryProof(args) {
  try {
    const { entry, leaf, path, entriesRoot } = args || {};
    const expected = leafHash(entry).toString('hex');
    if (String(leaf) !== expected) return { ok: false, reason: 'leaf_entry_mismatch' };
    const r = verifyMerkleProof({ leaf, path, root: entriesRoot });
    return r.ok ? { ok: true } : { ok: false, reason: r.reason ?? 'root_mismatch' };
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

// ─── drand: non-manipulable public randomness ────────────────────────────────
// A drand beacon (the League of Entropy "quicknet" network) emits a fresh random
// value every `period` seconds. Each value is a BLS THRESHOLD signature: no single
// operator — including you — can predict, withhold, or grind it. Committing to a
// FUTURE drand round before entries close therefore gives a seed that is both
// unpredictable in advance and independently checkable after the fact, closing the
// "a block producer could bias the block hash" hole in `blockHashSeed`.
//
// The publicly recomputable binding is `randomness == SHA256(signature)`; this
// adapter enforces it with `node:crypto` (zero deps). Full BLS verification — that
// the signature is a valid threshold signature over the round under the network's
// public key — is stronger still; pass an async `verifySignature({round,signature,
// previous})` (e.g. backed by @noble/curves bls12_381) to enforce it too.

/** drand quicknet defaults (League of Entropy). Override for other chains. */
export const DRAND_QUICKNET = {
  chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  genesisTime: 1692803367,
  period: 3,
  url: 'https://api.drand.sh',
};

function sha256hex(hexInput) {
  return sha256(Buffer.from(String(hexInput), 'hex')).toString('hex');
}

/**
 * The drand round whose randomness will first be available at-or-after `unixTime`.
 * Use this to COMMIT a future round before entries close (publish it via
 * `commitSeedSource({ source:'drand', round })`), so the seed is fixed in advance.
 * @param {number} unixTime seconds since epoch (e.g. your entry-close time)
 * @param {{genesisTime?:number, period?:number}} [chain] defaults to quicknet
 */
export function drandRoundAt(unixTime, chain = DRAND_QUICKNET) {
  const t = Number(unixTime);
  const { genesisTime, period } = { ...DRAND_QUICKNET, ...chain };
  if (!Number.isFinite(t) || t < genesisTime) throw new Error('drandRoundAt: unixTime before genesis');
  return Math.floor((t - genesisTime) / period) + 1;
}

/**
 * Build a seed from a drand beacon value, verifying the public binding
 * `randomness == SHA256(signature)`. Pass the `{round, randomness, signature}`
 * you fetched from a drand HTTP endpoint (see `fetchDrandRound`).
 * @param {object} beacon
 * @param {number} beacon.round
 * @param {string} beacon.randomness hex
 * @param {string} beacon.signature  hex (BLS signature)
 * @param {string} [beacon.chainHash]
 * @param {(b:object)=>Promise<boolean>|boolean} [verifySignature] optional BLS check
 * @returns {Promise<{source:string, value:string, round:number, signature:string, chainHash:string|null, manipulable:false, blsVerified:boolean}>}
 */
export async function drandSeed(
  { round, randomness, signature, previousSignature = null, chainHash = null },
  verifySignature,
) {
  if (round == null || !Number.isInteger(Number(round)))
    throw new Error('drandSeed: round is required');
  if (!/^[0-9a-f]+$/i.test(String(signature ?? '')))
    throw new Error('drandSeed: signature (hex) is required');
  if (!/^[0-9a-f]{64}$/i.test(String(randomness ?? '')))
    throw new Error('drandSeed: randomness (32-byte hex) is required');
  if (sha256hex(signature) !== String(randomness).toLowerCase())
    throw new Error('drandSeed: randomness does not match SHA256(signature) — beacon value rejected');
  let blsVerified = false;
  if (typeof verifySignature === 'function') {
    blsVerified = !!(await verifySignature({
      round: Number(round),
      randomness,
      signature,
      previousSignature,
      chainHash,
    }));
    if (!blsVerified) throw new Error('drandSeed: BLS signature verification failed');
  }
  return {
    source: 'drand',
    value: String(randomness).toLowerCase(),
    round: Number(round),
    signature: String(signature),
    chainHash: chainHash == null ? null : String(chainHash),
    manipulable: false,
    blsVerified,
  };
}

/**
 * Fetch a drand round over HTTP. `fetch` is injectable (defaults to global fetch)
 * so this is testable offline and SSRF-scoped to the drand host you pass.
 * @param {number} round
 * @param {{url?:string, chainHash?:string, fetch?:Function}} [opts]
 */
export async function fetchDrandRound(round, opts = {}) {
  const { url, chainHash, fetch: f = globalThis.fetch } = { ...DRAND_QUICKNET, ...opts };
  if (typeof f !== 'function') throw new Error('fetchDrandRound: no fetch available');
  const endpoint = `${url}/${chainHash}/public/${Number(round)}`;
  const res = await f(endpoint);
  if (!res.ok) throw new Error(`fetchDrandRound: HTTP ${res.status}`);
  const body = await res.json();
  return {
    round: Number(body.round),
    randomness: body.randomness,
    signature: body.signature,
    previousSignature: body.previous_signature ?? null, // present on chained beacons
    chainHash,
  };
}
