import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEphemeralAccount, isExpired } from '../src/index.js';

// Minimal algod stub: only getTransactionParams is needed for account creation.
const stubAlgod = (lastValid = 1000, firstValid = 990) => ({
  getTransactionParams: () => ({ do: async () => ({ lastValid, firstValid }) }),
});

test('createEphemeralAccount sets a ROUND-RELATIVE expiry', async () => {
  const acct = await createEphemeralAccount({ algod: stubAlgod(1000), ttlRounds: 50 });
  assert.equal(acct.expiryRound, 1050); // lastValid(1000) + ttlRounds(50)
  assert.match(acct.address, /^[A-Z2-7]{58}$/); // base32 Algorand address
});

test('the secret signer is NON-ENUMERABLE (never serialized/logged)', async () => {
  const acct = await createEphemeralAccount({ algod: stubAlgod(), ttlRounds: 10 });
  const json = JSON.stringify(acct);
  assert.equal(json.includes('signer'), false);
  assert.equal(json.includes('mnemonic'), false);
  // ...but it IS reachable for server-side signing.
  assert.equal(typeof acct.signer.signTxns, 'function');
  assert.ok(Object.keys(acct).every((k) => k !== 'signer'));
});

test('isExpired is true only past the expiry round', async () => {
  const acct = await createEphemeralAccount({ algod: stubAlgod(1000), ttlRounds: 50 });
  assert.equal(isExpired(acct, 1050), false); // exactly at expiry: still valid
  assert.equal(isExpired(acct, 1051), true); // one past: expired
  assert.equal(isExpired(acct, 999), false);
});

test('scope composes an oaa-agent-kit mandate to bound authority', async () => {
  const acct = await createEphemeralAccount({
    algod: stubAlgod(1000),
    ttlRounds: 100,
    scope: { perTxMicroAlgos: 1_000_000 },
  });
  assert.ok(acct.mandate);
  assert.equal(acct.mandate.perTxMicroAlgos, 1_000_000);
  assert.equal(acct.mandate.expiryRound, 1100); // mandate expiry tracks account expiry
});

test('createEphemeralAccount rejects a non-positive ttlRounds', async () => {
  await assert.rejects(
    () => createEphemeralAccount({ algod: stubAlgod(), ttlRounds: 0 }),
    /ttlRounds/,
  );
});
