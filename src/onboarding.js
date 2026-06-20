/**
 * onboarding.js — low-friction guest onboarding via EPHEMERAL CUSTODIAL accounts.
 *
 * A guest gets a fresh, server-held Algorand account that is tightly scoped and
 * auto-expires. The user signs nothing. This trades self-custody for low friction,
 * so it is handled defensively:
 *   - The secret key is generated from a CSPRNG (oaa-agent-kit LocalOwnerSigner)
 *     and attached NON-ENUMERABLY, so it never lands in JSON.stringify, logs,
 *     receipts, events, or ledger snapshots. JS cannot wipe key memory — these are
 *     DEV/TestNet-grade; production custody needs your own KMS/HSM (see LEGAL.md).
 *   - Expiry is ROUND-RELATIVE (live round + ttlRounds), never a hard-coded round
 *     (a static default silently expires — a footgun we will not repeat).
 *   - Authority can be bounded by composing an oaa-agent-kit mandate, so a leaked
 *     ephemeral key is loss-limited (per-tx cap / payee allowlist / expiry).
 */

import algosdk from 'algosdk';
import { LocalOwnerSigner, createMandate } from '@kirkelabs/oaa-agent-kit';

const MS_DEFAULT_TTL = 50_000; // ~2 days of rounds on Algorand (~2.8s/round)

/**
 * Create an ephemeral custodial account. The returned object is safe to persist
 * (no secret in its enumerable fields); the signer is reachable via the
 * non-enumerable `.signer` for server-side signing only.
 *
 * @param {object} opts
 * @param {algosdk.Algodv2} opts.algod
 * @param {number} [opts.ttlRounds]  rounds until expiry (added to the live round)
 * @param {object} [opts.scope]      optional authority bound: {perTxMicroAlgos, allowlist?, owner?}
 * @param {string} [opts.network]    'algorand-testnet' (default) | 'algorand'
 */
export async function createEphemeralAccount({
  algod,
  ttlRounds = MS_DEFAULT_TTL,
  scope = null,
  network = 'algorand-testnet',
}) {
  if (!Number.isInteger(ttlRounds) || ttlRounds <= 0)
    throw new Error('createEphemeralAccount: ttlRounds must be a positive integer');
  const sp = await algod.getTransactionParams().do();
  const expiryRound = Number(sp.lastValid) + ttlRounds; // round-relative

  const signer = LocalOwnerSigner.random(); // CSPRNG key, held in-process only
  let mandate = null;
  if (scope && scope.perTxMicroAlgos != null) {
    mandate = createMandate({
      owner: scope.owner ?? signer.address,
      perTxMicroAlgos: scope.perTxMicroAlgos,
      allowlist: scope.allowlist ?? [],
      expiryRound,
      network,
    });
  }

  const account = {
    address: signer.address,
    network,
    createdAtRound: Number(sp.firstValid),
    expiryRound,
    scope: scope ? { ...scope } : null,
    mandate,
  };
  // The secret signer is NON-ENUMERABLE: it is excluded from JSON/logs/snapshots.
  Object.defineProperty(account, 'signer', { value: signer, enumerable: false });
  return account;
}

/** True if the account has passed its expiry round. */
export function isExpired(account, currentRound) {
  if (account == null || account.expiryRound == null)
    throw new Error('isExpired: account.expiryRound is required');
  if (currentRound == null) throw new Error('isExpired: currentRound is required');
  return Number(currentRound) > Number(account.expiryRound);
}

/** Sweep the full balance of an ephemeral account to `toAddress` (close-out). */
async function sweep(algod, fromSigner, toAddress) {
  if (!algosdk.isValidAddress(String(toAddress)))
    throw new Error('sweep: invalid destination address');
  const sp = await algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: fromSigner.address,
    receiver: toAddress,
    amount: 0,
    closeRemainderTo: toAddress, // close the ephemeral account, sweeping everything
    suggestedParams: sp,
  });
  const [signed] = await fromSigner.signTxns([txn]);
  const { txid } = await algod.sendRawTransaction(signed).do();
  await algosdk.waitForConfirmation(algod, txid, 10);
  return txid;
}

/**
 * Expire an account NOW: sweep its balance back to the operator and abandon it.
 * @returns {Promise<{txid:string, sweptTo:string}>}
 */
export async function expireAccount({ algod, account, to }) {
  if (!account?.signer) throw new Error('expireAccount: account.signer is required');
  const txid = await sweep(algod, account.signer, to);
  return { txid, sweptTo: String(to) };
}

/**
 * Rotate to a fresh ephemeral account (e.g. on suspected key compromise) and
 * sweep the old balance into it. Inherits scope/network unless overridden.
 * @returns {Promise<{account:object, sweepTxid:string}>}
 */
export async function rotateAccount({ algod, account, ttlRounds, scope, network }) {
  if (!account?.signer) throw new Error('rotateAccount: account.signer is required');
  const next = await createEphemeralAccount({
    algod,
    ttlRounds: ttlRounds ?? MS_DEFAULT_TTL,
    scope: scope ?? account.scope,
    network: network ?? account.network,
  });
  const sweepTxid = await sweep(algod, account.signer, next.address);
  return { account: next, sweepTxid };
}
