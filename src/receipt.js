/**
 * receipt.js — receipt-only on-chain proofs. The user signs NOTHING.
 *
 * An order receipt is a compact, NON-PII record that hash-chains to the previous
 * one (tamper-evident) and can be signed by the operator. Only the receipt HASH
 * is attested on-chain — never the body, never any personal data. x402-charged
 * actions go through oaa-agent-kit's hardened `payAndFetch` (SSRF guard, timeout,
 * response-size cap, redirect:error, allowedHosts, confirm hook).
 */

import algosdk from 'algosdk';
import {
  createReceiptId,
  hashCanonicalJson,
  signReceipt as coreSignReceipt,
  verifyReceiptSignature,
} from '@kirkelabs/open-agent-access-core';
import { payAndFetch, makeAlgorandPayer } from '@kirkelabs/oaa-agent-kit';
import { assertNoPii } from './privacy.js';

/** Canonical hash payload: the receipt without its own hash/signature fields. */
function hashPayload(r) {
  const c = { ...r };
  delete c.receiptHash;
  delete c.signature;
  return c;
}

/** A deterministic, reproducible order id from a seed (no randomness/clock). */
export function deterministicOrderId(seed) {
  return `ord_${hashCanonicalJson(seed).slice(0, 24)}`;
}

/**
 * Build a non-PII, hash-chained order receipt. Throws if any field looks like PII
 * (so a receipt can never carry personal data on-chain). Pass `previousHash`
 * (the prior receipt's `receiptHash`) to chain.
 */
export function buildOrderReceipt(input = {}) {
  // Reject PII on the RAW input (before we drop unknown keys), so a caller can
  // never smuggle personal data into anything that may be attested on-chain.
  assertNoPii(input);
  const {
    orderId,
    action,
    quantity,
    price,
    agent,
    previousHash = null,
    receiptId,
    timestamp,
  } = input;
  if (orderId == null || action == null) throw new Error('buildOrderReceipt: orderId and action are required');
  const receipt = {
    receiptVersion: '0.1',
    receiptType: 'walletless_order',
    receiptId: receiptId ?? createReceiptId(),
    orderId: String(orderId),
    action: String(action),
    quantity: quantity == null ? null : Number(quantity),
    price: price == null ? null : String(price), // string/integer — never a float literal
    agent: agent == null ? null : String(agent),
    previousHash,
    timestamp: timestamp ?? new Date().toISOString(),
  };
  assertNoPii(receipt);
  receipt.receiptHash = hashCanonicalJson(hashPayload(receipt));
  return receipt;
}

/** Operator-sign a receipt (ed25519, via core). */
export function signReceipt(receipt, { privateKeyPem, publicKeyPem }) {
  return coreSignReceipt(receipt, privateKeyPem, publicKeyPem);
}

/**
 * Verify a chain of receipts: each links to the previous, each hash recomputes,
 * and any signature present is valid. Robust to malformed input (never throws).
 * @returns {{ok:boolean, count:number, errors:string[]}}
 */
export function verifyReceiptChain(receipts) {
  const errors = [];
  if (!Array.isArray(receipts)) return { ok: false, count: 0, errors: ['not_an_array'] };
  let prev = null;
  receipts.forEach((r, i) => {
    try {
      if ((r.previousHash ?? null) !== prev) errors.push(`receipt ${i + 1}: previousHash mismatch`);
      if (r.receiptHash !== hashCanonicalJson(hashPayload(r)))
        errors.push(`receipt ${i + 1}: receiptHash mismatch`);
      if (r.signature && !verifyReceiptSignature(r)) errors.push(`receipt ${i + 1}: bad signature`);
      prev = r.receiptHash;
    } catch (e) {
      errors.push(`receipt ${i + 1}: ${e.message}`);
    }
  });
  return { ok: errors.length === 0, count: receipts.length, errors };
}

/**
 * Attest a receipt on-chain as a compact, NON-PII note: only
 * `walletless-receipt:v1:<receiptHash>` (the receipt body stays off-chain).
 * Network-bound (genesis via suggestedParams) and size-bounded (note ≤ 1 KB).
 * @returns {Promise<{txid:string, confirmedRound:number, receiptHash:string}>}
 */
export async function attestOnChain(algod, signer, receipt) {
  if (!receipt?.receiptHash) throw new Error('attestOnChain: receipt has no receiptHash');
  assertNoPii(receipt);
  const note = new TextEncoder().encode(`walletless-receipt:v1:${receipt.receiptHash}`);
  if (note.length > 1024) throw new Error('attestOnChain: note exceeds 1KB');
  const sp = await algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: signer.address,
    receiver: signer.address,
    amount: 0,
    note,
    suggestedParams: sp,
  });
  const [signed] = await signer.signTxns([txn]);
  const { txid } = await algod.sendRawTransaction(signed).do();
  const res = await algosdk.waitForConfirmation(algod, txid, 10);
  return {
    txid,
    confirmedRound: Number(res.confirmedRound ?? res['confirmed-round']),
    receiptHash: receipt.receiptHash,
  };
}

/**
 * Pay-and-fetch an x402-charged action from a mandate-bound agent account, reusing
 * oaa-agent-kit's hardened client. `fetchPolicy` (allowInsecure, allowedHosts,
 * timeoutMs, maxBytes, maxAmountMicroAlgos, confirm) is forwarded verbatim — set
 * `allowedHosts` when the action URL is not fully trusted.
 */
export async function chargeForAction({ algod, account, mandate, url, method, body, ...fetchPolicy }) {
  const payer =
    algod && account && mandate ? makeAlgorandPayer({ algod, account, mandate }) : undefined;
  return payAndFetch(url, { payer, method, body, ...fetchPolicy });
}
