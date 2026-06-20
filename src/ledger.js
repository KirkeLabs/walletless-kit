/**
 * ledger.js — segregated, append-only money books for a walletless flow.
 *
 * Three independent books — `inflow`, `charity`, `escrow` — keep ticket revenue,
 * charity allocations, and held funds clearly separated for reconciliation.
 *
 * Hardening:
 *   - Money is ALWAYS integer microALGO (or BigInt-safe integers). Never a JS
 *     float — floating-point money silently drifts and breaks reconciliation.
 *   - Books are append-only; `snapshot()` returns a deep-FROZEN copy so a caller
 *     can't retro-edit history.
 *   - `reconciliationSheet` is a pure, deterministic function of the books.
 *
 * This is bookkeeping/transparency tooling, NOT regulated custody or accounting.
 * See LEGAL.md (money handling / AML).
 */

const BOOKS = ['inflow', 'charity', 'escrow'];
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

function assertMicro(amount) {
  const n = Number(amount);
  if (!Number.isInteger(n) || n < 0 || n > MAX_SAFE)
    throw new Error('ledger: amountMicro must be a non-negative integer (microALGO), never a float');
  return n;
}

export class Ledger {
  constructor() {
    this._books = { inflow: [], charity: [], escrow: [] };
    this._seq = 0;
  }

  /**
   * Append an entry to a book. `amountMicro` MUST be an integer (microALGO).
   * @param {{book:string, amountMicro:number, ref?:string, txRef?:string, kind?:string, meta?:object}} e
   */
  post({ book, amountMicro, ref = null, txRef = null, kind = 'generic', meta = null }) {
    if (!BOOKS.includes(book)) throw new Error(`ledger: unknown book "${book}" (use ${BOOKS.join('/')})`);
    const entry = Object.freeze({
      seq: ++this._seq,
      book,
      amountMicro: assertMicro(amountMicro),
      ref: ref == null ? null : String(ref),
      txRef: txRef == null ? null : String(txRef),
      kind: String(kind),
      meta: meta == null ? null : Object.freeze({ ...meta }),
    });
    this._books[book].push(entry);
    return entry;
  }

  /** Integer balance of a book. */
  balance(book) {
    if (!BOOKS.includes(book)) throw new Error(`ledger: unknown book "${book}"`);
    return this._books[book].reduce((s, e) => s + e.amountMicro, 0);
  }

  /** All three balances. */
  balances() {
    return { inflow: this.balance('inflow'), charity: this.balance('charity'), escrow: this.balance('escrow') };
  }

  /** Deep-frozen immutable snapshot of every book + balances. */
  snapshot() {
    const books = {};
    for (const b of BOOKS) books[b] = Object.freeze(this._books[b].slice());
    return Object.freeze({ books: Object.freeze(books), balances: Object.freeze(this.balances()) });
  }

  /**
   * Human-readable reconciliation sheet for a draw. Pure/deterministic.
   * @param {string} drawId
   * @param {{winnerProofLink?:string}} [opts]
   */
  reconciliationSheet(drawId, { winnerProofLink = null } = {}) {
    const inflow = this._books.inflow;
    const sum = (arr) => arr.reduce((s, e) => s + e.amountMicro, 0);
    const ticketsSold = inflow.filter((e) => e.kind === 'ticket').length;
    const gross = sum(inflow);
    const fees = sum(
      [...inflow, ...this._books.charity, ...this._books.escrow].filter((e) => e.kind === 'fee'),
    );
    const charityTotal = this.balance('charity');
    const escrowTotal = this.balance('escrow');
    return {
      drawId: String(drawId),
      ticketsSold,
      grossMicroAlgos: gross,
      feesMicroAlgos: fees,
      charity: {
        totalMicroAlgos: charityTotal,
        destinations: this._books.charity.map((e) => ({
          address: e.ref,
          amountMicroAlgos: e.amountMicro,
          txRef: e.txRef,
        })),
      },
      escrow: {
        totalMicroAlgos: escrowTotal,
        refs: this._books.escrow.map((e) => ({ ref: e.ref, txRef: e.txRef, amountMicroAlgos: e.amountMicro })),
      },
      netMicroAlgos: gross - fees - charityTotal - escrowTotal,
      winnerProofLink,
    };
  }
}

/** Convenience factory. */
export function createLedger() {
  return new Ledger();
}
