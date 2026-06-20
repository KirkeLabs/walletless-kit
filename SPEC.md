# walletless-kit proof formats — `SPEC.md`

**Status:** v1 · **Scope:** the on-the-wire formats a *second implementation* must
reproduce to interoperate with `@kirkelabs/walletless-kit`. This is the contract
behind the project's core claim — *anyone can recompute the result without trusting
the software that produced it.* The frozen conformance vectors live in
[`test/vectors.json`](./test/vectors.json); a conforming implementation MUST
reproduce every hash, root, and proof there byte-for-byte.

Everything in this spec is computable with only SHA-256 and canonical JSON — no
blockchain, no network, no dependency on this package. The reference verifier
([`src/verify.js`](./src/verify.js)) depends only on
[`src/merkle.js`](./src/merkle.js), which depends only on `node:crypto`.

The key words MUST / MUST NOT / SHOULD are used per RFC 2119.

---

## 1. Canonical JSON

All hashing is over **canonical JSON**:

- Objects: keys sorted by Unicode code point (ascending), no insignificant
  whitespace, `undefined`-valued keys omitted.
- Arrays: element order preserved.
- Primitives: standard JSON encoding (`JSON.stringify` semantics); `null` kept.

This is byte-identical to `@kirkelabs/open-agent-access-core`'s `canonicalizeJson`
(cross-checked in `test/canonical.test.js`), so roots match whichever side produced
them. Reference: [`canonicalJson`](./src/merkle.js).

## 2. Merkle tree (RFC 6962)

Domain-separated, to prevent a leaf being reinterpreted as an internal node
(second-preimage forgery):

```
leaf(d)        = SHA256( 0x00 ‖ canonicalJSON(d) )
node(l, r)     = SHA256( 0x01 ‖ l ‖ r )
MTH({})        = SHA256("")            # empty tree
MTH({d0})      = leaf(d0)
MTH(D[0:n]),     n>1:
    k = largest power of two strictly less than n
    MTH = node( MTH(D[0:k]), MTH(D[k:n]) )
```

A lone (odd) node is **promoted** unchanged to the next level — never duplicated
(duplicating it is the Bitcoin CVE-2012-2459 ambiguity). The iterative
"pair-adjacent, promote-odd" construction in this kit equals the recursive
definition above for all `n` (verified `n = 0..40`).

- **Root:** lowercase hex of `MTH`.
- **Inclusion proof:** `{ index, leaf, path[] }`, each `path` step
  `{ side: "left"|"right", hash }`. Verify by folding siblings into `leaf` and
  comparing to the root. Reference: [`merkleProof` / `verifyMerkleProof`](./src/merkle.js).

## 3. Consistency proof (RFC 6962 §2.1.2)

Proves the tree of size `m` is a **prefix** of the tree of size `n` (`m ≤ n`): the
log only grew and was never rewritten. Format:

```
{ oldSize: m, newSize: n, proof: [ hex, … ] }
```

Verification (against `oldRoot`, `newRoot`) follows the certificate-transparency
reference algorithm; see [`verifyConsistencyProof`](./src/merkle.js). Pair with the
on-chain anchors (§7): anchor `oldRoot` at size `m`, later anchor `newRoot` at size
`n`, and the `m → n` transition is provably append-only.

## 4. Draw proof

Winner selection is a deterministic function of `(seed, entryCount)` — no
`Math.random`. Algorithm id `fisher-yates-sha256-v1`:

```
rng stream:  block_i = SHA256( seed ‖ ":" ‖ uint64LE(i) ), i = 0,1,2,…
uniformInt(maxExclusive):                     # unbiased, rejection-sampled
    span  = 2^48
    limit = floor(span / maxExclusive) * maxExclusive
    draw 6 bytes big-endian as v; reject while v ≥ limit; return v mod maxExclusive
shuffle:  for i = n-1 … 1:  j = uniformInt(i+1);  swap(a[i], a[j])
winners:  first k of shuffle([0..n-1]); map indices → entries
```

Proof object:

```
{ algorithm, seed, entryCount, entriesRoot, winners[], winnerIndices[] }
```

`entriesRoot` is the Merkle root (§2) over the **exact ordered entry set**.
Verify by (a) recomputing `entriesRoot` from the entries, (b) re-running the
shuffle, (c) comparing indices and mapped winners. Reference:
[`verifyDrawProof`](./src/verify.js) (independent of the producer code).

### 4.1 Entrant inclusion proof

A single entrant proves membership against `entriesRoot` alone, without seeing the
rest of the field: `{ entry, index, leaf, path }`. Verify that `leaf == leaf(entry)`
**and** the path recomputes `entriesRoot`. Reference: [`verifyEntryProof`](./src/draw.js).

## 5. Seed sources

A seed is `{ source, value, … }`. Fairness equals the seed — no more. Sources:

| `source`              | Manipulable? | Notes |
|-----------------------|--------------|-------|
| `algorand-block-seed` | **yes** (`manipulable:true`) | A proposer can withhold/grind. Only with `commitSeedSource` + low value. |
| `drand`               | no           | BLS threshold beacon. MUST satisfy `randomness == SHA256(signature)`; optionally full BLS-verified. |
| `vrf`                 | depends      | Caller supplies a verified VRF value+proof. |
| `beacon`              | depends      | Generic public beacon wrapper. |

**drand binding (verifiable with SHA-256 only):** `randomness = SHA256(signature)`,
both lowercase hex; `signature` is the BLS signature bytes. A future round committed
**before entries close** (via `commitSeedSource` / `drandRoundAt`) is unpredictable
and non-grindable. Reference: [`drandSeed`](./src/draw.js).

**drand BLS verification (full provenance):** that the signature is a valid League-
of-Entropy threshold signature — i.e. the randomness really came from the network —
is checked with BLS12-381 pairings. Message hashing per scheme:

| `schemeID` | sig group | pubkey group | message digest | hash-to-curve DST |
|---|---|---|---|---|
| `bls-unchained-g1-rfc9380` (quicknet) | G1 (48 B) | G2 (96 B) | `SHA256(round_be8)` | `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_` |
| `pedersen-bls-chained` (legacy mainnet) | G2 (96 B) | G1 (48 B) | `SHA256(previous_signature ‖ round_be8)` | `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` |

`round_be8` is the round as an unsigned 64-bit big-endian integer. This check is
**optional** and lives in a separate module/import subpath
([`src/drand-bls.js`](./src/drand-bls.js), `@kirkelabs/walletless-kit/drand-bls`).
It is backed by `@noble/curves`, declared as an **optional peer dependency** —
install it (`npm i @noble/curves`) only if you want BLS verification; the core
package and the §1–§4 / §8 verifier pull in no pairing crypto. Frozen real-beacon
vectors: [`test/drand-vectors.json`](./test/drand-vectors.json).

## 6. Receipt chain

Each receipt is non-PII and hash-chained:

```
receiptHash = SHA256( canonicalJSON( receipt without {receiptHash, signature} ) )
receipt[i].previousHash == receipt[i-1].receiptHash   (null for the first)
```

Verify by recomputing each `receiptHash` and checking the links. An optional
ed25519 `signature` over the receipt MAY be present (verified by the producing side
via oaa-core); the zero-dep verifier checks hashes and links only. Reference:
[`verifyReceiptChain`](./src/verify.js).

## 7. On-chain anchors (optional, non-normative for verification)

Commitments are written on-chain as a 0-amount self-payment whose note is
ASCII-tagged and ≤ 1 KB — **never** any PII or receipt/event body:

```
audit anchor:   walletless-anchor:v1:<merkleRoot hex>
receipt attest: walletless-receipt:v1:<receiptHash hex>
```

The chain is a timestamping/availability layer only; all verification in §1–§6 is
independent of it.

## 8. Proof bundle (`walletless-proof/v1`)

A single portable artifact packing a draw + optional entries, seed source, receipt
chain, trail root, and anchors:

```
{ bundleVersion: "walletless-proof/v1",
  draw, seedSource, entries|null, receipts|null,
  trail: { root, count }|null, anchors|null, meta|null,
  bundleHash }                          # SHA256(canonicalJSON(bundle without bundleHash))
```

`verifyBundle` re-derives each present section and returns a per-section verdict.
A bundle **with** `entries` is fully self-verifying; **without** them it is a
commitment that entrants check with their own §4.1 inclusion proofs. Reference:
[`bundleProof` / `verifyBundle`](./src/verify.js).

---

## Conformance

An implementation conforms to **walletless-proof/v1** if, given
[`test/vectors.json`](./test/vectors.json), it reproduces: the Merkle roots (§2),
the consistency proof and its verification (§3), the draw proof and winners (§4),
the entrant inclusion proof (§4.1), and the drand `randomness = SHA256(signature)`
binding (§5). Version this document and the `bundleVersion` tag together; any change
to a hashing rule is a new major version with new frozen vectors.
