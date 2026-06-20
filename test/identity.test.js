import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OtpIdentity } from '../src/index.js';

const PEPPER = 'identity-pepper-at-least-16-chars';
// Capture the delivered code (in real use this goes via email/SMS).
function makeId(extra = {}) {
  let last = null;
  const id = new OtpIdentity({ pepper: PEPPER, send: async (_c, code) => (last = code), ...extra });
  return { id, getCode: () => last };
}

test('issueChallenge never returns the code and stores only keyed refs', async () => {
  const { id, getCode } = makeId();
  const r = await id.issueChallenge('alice@example.com');
  assert.equal(r.sent, true);
  assert.equal('code' in r, false);
  assert.match(r.contactRef, /^[0-9a-f]{64}$/); // keyed hash, not the email
  assert.match(getCode(), /^\d{6}$/);
});

test('a correct code verifies once (single-use)', async () => {
  const { id, getCode } = makeId();
  await id.issueChallenge('bob@example.com');
  const ok = await id.verifyChallenge('bob@example.com', getCode());
  assert.equal(ok.ok, true);
  // replay the same code -> rejected (consumed)
  const again = await id.verifyChallenge('bob@example.com', getCode());
  assert.equal(again.ok, false);
  assert.equal(again.reason, 'invalid_or_expired');
});

test('a wrong code fails generically and locks out after maxAttempts', async () => {
  const { id } = makeId({ maxAttempts: 3 });
  await id.issueChallenge('carol@example.com');
  for (let i = 0; i < 3; i++) {
    const r = await id.verifyChallenge('carol@example.com', '000000');
    assert.equal(r.ok, false);
  }
  const locked = await id.verifyChallenge('carol@example.com', '000000');
  assert.equal(locked.reason, 'locked_out');
});

test('an expired code is rejected', async () => {
  const { id, getCode } = makeId({ ttlMs: 1000 });
  await id.issueChallenge('dan@example.com', { now: 0 });
  const r = await id.verifyChallenge('dan@example.com', getCode(), { now: 2000 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid_or_expired');
});

test('verifying an unknown contact is generic (anti-enumeration)', async () => {
  const { id } = makeId();
  const r = await id.verifyChallenge('nobody@example.com', '123456');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid_or_expired'); // same reason as a wrong code
});

test('issue is rate-limited per contact', async () => {
  const { id } = makeId({ rateLimit: { requests: 2, window: '10m' } });
  assert.equal((await id.issueChallenge('e@example.com', { now: 0 })).sent, true);
  assert.equal((await id.issueChallenge('e@example.com', { now: 1 })).sent, true);
  const third = await id.issueChallenge('e@example.com', { now: 2 });
  assert.equal(third.sent, false);
  assert.equal(third.reason, 'rate_limited');
});

test('rejects a weak pepper', () => {
  assert.throws(() => new OtpIdentity({ pepper: 'short' }), /pepper/);
});
