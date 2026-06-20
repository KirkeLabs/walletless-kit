/**
 * drand-bls.js — REAL BLS verification of drand beacons.
 *
 * `draw.js`'s `drandSeed` enforces the cheap, SHA-256-only binding
 * `randomness == SHA256(signature)`. This module adds the strong guarantee: that
 * the signature is a valid League-of-Entropy THRESHOLD signature over the round
 * under the network's public key — i.e. the randomness was genuinely produced by
 * the drand network and not fabricated. With this, a drand-seeded draw is
 * non-manipulable AND its provenance is cryptographically proven, not asserted.
 *
 * It is kept in a SEPARATE module (and a separate import subpath) so the
 * zero-dependency verifier in `verify.js` stays dependency-free: pull in the
 * BLS18-381 pairing math (@noble/curves) only if and when you want this check.
 *
 * Two drand schemes are supported, matched by `schemeID`:
 *   - `bls-unchained-g1-rfc9380` (quicknet): signatures on G1, public key on G2,
 *     message = SHA256(round_be8). The recommended network for new draws.
 *   - `pedersen-bls-chained`   (legacy mainnet): signatures on G2, public key on
 *     G1, message = SHA256(previous_signature ‖ round_be8).
 *
 * Verification math is provided by @noble/curves; its default hash-to-curve DSTs
 * (`BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` / `…G2…`) match drand's exactly.
 * Cross-checked against live beacon rounds, frozen into `test/drand-vectors.json`.
 */

import { createHash } from 'node:crypto';

// @noble/curves is an OPTIONAL peer dependency: the BLS12-381 pairing math is only
// needed for this module, so the core package (receipts / audit / ledger / draw /
// the zero-dep verifier) installs nothing extra. Load it lazily and fail with a
// clear, actionable message if a consumer reaches for BLS without installing it.
let bls = null;
try {
  ({ bls12_381: bls } = await import('@noble/curves/bls12-381'));
} catch {
  bls = null;
}

function requireBls() {
  if (!bls)
    throw new Error(
      'drand BLS verification needs the optional peer dependency "@noble/curves". ' +
        'Install it to enable this check:  npm i @noble/curves',
    );
  return bls;
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

/** drand serialises the round number as an unsigned 64-bit big-endian integer. */
function roundBytes(round) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(round));
  return b;
}

/**
 * Frozen drand network parameters. Public keys are published constants; pass your
 * own `publicKey` to `makeDrandVerifier` to pin a different network.
 */
export const DRAND_QUICKNET_SCHEME = Object.freeze({
  schemeID: 'bls-unchained-g1-rfc9380',
  chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  publicKey:
    '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  genesisTime: 1692803367,
  period: 3,
});

export const DRAND_DEFAULT_SCHEME = Object.freeze({
  schemeID: 'pedersen-bls-chained',
  chainHash: '8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce',
  publicKey:
    '868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31',
  genesisTime: 1595431050,
  period: 30,
});

/** Look up a known scheme by its `schemeID`. */
function knownScheme(schemeID) {
  if (schemeID === DRAND_QUICKNET_SCHEME.schemeID) return DRAND_QUICKNET_SCHEME;
  if (schemeID === DRAND_DEFAULT_SCHEME.schemeID) return DRAND_DEFAULT_SCHEME;
  return null;
}

/**
 * Verify a single drand beacon's BLS signature (and, by default, the
 * `randomness == SHA256(signature)` binding). Returns a boolean and never throws
 * on bad beacon data — but DOES throw if the optional `@noble/curves` peer
 * dependency is not installed (so a missing library is never mistaken for an
 * invalid beacon). Selects the curve/message construction from `schemeID`.
 *
 * @param {object} beacon  `{ round, signature, randomness?, previousSignature? }` (hex)
 * @param {object} opts
 * @param {string} opts.publicKey  network public key (hex)
 * @param {string} opts.schemeID   one of the supported scheme ids
 * @param {boolean} [opts.checkRandomness=true]  also enforce randomness binding
 * @returns {boolean}
 */
export function verifyDrandBeacon(beacon, { publicKey, schemeID, checkRandomness = true } = {}) {
  const b = requireBls(); // throws a clear install error if the peer dep is absent
  try {
    const { round, signature, randomness } = beacon || {};
    // Accept either the camelCase field (from `fetchDrandRound`) or the raw
    // `previous_signature` field (straight from the drand HTTP API).
    const previousSignature = beacon?.previousSignature ?? beacon?.previous_signature ?? null;
    if (round == null || !signature || !publicKey || !schemeID) return false;

    if (checkRandomness && randomness != null) {
      if (sha256(Buffer.from(String(signature), 'hex')).toString('hex') !== String(randomness).toLowerCase())
        return false;
    }

    if (schemeID === DRAND_QUICKNET_SCHEME.schemeID) {
      // Unchained, signature on G1: message = SHA256(round_be8).
      const digest = sha256(roundBytes(round));
      const point = b.shortSignatures.hash(digest);
      return b.shortSignatures.verify(String(signature), point, String(publicKey)) === true;
    }
    if (schemeID === DRAND_DEFAULT_SCHEME.schemeID) {
      // Chained, signature on G2: message = SHA256(previous_signature ‖ round_be8).
      if (!previousSignature) return false;
      const digest = sha256(Buffer.concat([Buffer.from(String(previousSignature), 'hex'), roundBytes(round)]));
      const point = b.longSignatures.hash(digest);
      return b.longSignatures.verify(String(signature), point, String(publicKey)) === true;
    }
    return false; // unknown scheme — fail closed
  } catch {
    return false;
  }
}

/**
 * Build a `verifySignature` function for `drandSeed`. Bind it to a network and it
 * returns an async predicate `({ round, signature, randomness, previousSignature })
 * => boolean` that `drandSeed` will enforce.
 *
 *   import { drandSeed, fetchDrandRound } from '@kirkelabs/walletless-kit';
 *   import { makeDrandVerifier, DRAND_QUICKNET_SCHEME } from '@kirkelabs/walletless-kit/drand-bls';
 *
 *   const verify = makeDrandVerifier(DRAND_QUICKNET_SCHEME);
 *   const beacon = await fetchDrandRound(committedRound);     // after the round exists
 *   const seed = await drandSeed(beacon, verify);             // throws unless BLS-valid
 *   // seed.blsVerified === true
 *
 * @param {object} scheme `{ schemeID, publicKey }` (e.g. DRAND_QUICKNET_SCHEME). A
 *   bare scheme id string also works, resolving a known network's public key.
 * @param {object} [overrides] e.g. `{ publicKey }` to pin a custom network key
 */
export function makeDrandVerifier(scheme, overrides = {}) {
  const base = typeof scheme === 'string' ? knownScheme(scheme) : scheme;
  if (!base) throw new Error('makeDrandVerifier: unknown scheme — pass { schemeID, publicKey }');
  const schemeID = base.schemeID;
  const publicKey = overrides.publicKey ?? base.publicKey;
  if (!schemeID || !publicKey)
    throw new Error('makeDrandVerifier: schemeID and publicKey are required');
  // Defensive: public key length must match the scheme's group (G2=96B, G1=48B).
  const expectBytes = schemeID === DRAND_QUICKNET_SCHEME.schemeID ? 96 : 48;
  if (String(publicKey).length !== expectBytes * 2)
    throw new Error(`makeDrandVerifier: publicKey must be ${expectBytes} bytes for ${schemeID}`);
  return async (beacon) => verifyDrandBeacon(beacon, { publicKey, schemeID });
}
