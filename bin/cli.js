#!/usr/bin/env node
/**
 * walletless-kit CLI
 *
 *   walletless init [dir]                 scaffold a starter raffle project
 *   walletless keygen [--out <file>]      generate a dev Algorand account
 *   walletless draw --entries <f> --seed <s> [--winners N]   run + print a draw proof
 *   walletless reconcile --ledger <f> [--draw id]            print a reconciliation sheet
 *   walletless verify --proof <f> [--entries <f>]            recompute a draw proof / audit trail
 *   walletless help
 */

import { writeFile, mkdir, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import {
  algosdk,
  publishDrawProof,
  verifyDraw,
  verifyTrail,
  createLedger,
} from '../src/index.js';

// Copied from @kirkelabs/oaa-agent-kit — same flag-parsing convention.
function parse(argv) {
  const o = { _: [] };
  for (let i = 3; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) o[a.slice(2)] = argv[i + 1]?.startsWith('--') ? true : argv[++i];
    else o._.push(a);
  }
  return o;
}

function fail(msg) {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

async function main() {
  const cmd = process.argv[2];
  const o = parse(process.argv);

  if (cmd === 'keygen') {
    const a = algosdk.generateAccount();
    const account = { address: String(a.addr), mnemonic: algosdk.secretKeyToMnemonic(a.sk) };
    if (o.out) {
      await writeFile(resolve(o.out), JSON.stringify(account, null, 2), { mode: 0o600 });
      console.log(`Wrote account to ${resolve(o.out)} (keep the mnemonic secret).`);
    } else {
      console.log(JSON.stringify(account, null, 2));
      console.log(
        '\n⚠ The mnemonic above is a SECRET (printed to your terminal). Anyone with it' +
          '\n  controls the account. Prefer: walletless keygen --out owner.json' +
          '\n⚠ Dev only. Fund on TestNet via https://bank.testnet.algorand.network/',
      );
    }
    return;
  }

  if (cmd === 'draw') {
    if (!o.entries || !o.seed) return fail('draw requires --entries <file.json> and --seed <seed>');
    const entries = JSON.parse(await readFile(resolve(o.entries), 'utf8'));
    const proof = publishDrawProof({
      entries,
      seed: String(o.seed),
      winners: parseInt(o.winners || '1', 10),
    });
    console.log(JSON.stringify(proof, null, 2));
    return;
  }

  if (cmd === 'reconcile') {
    if (!o.ledger) return fail('reconcile requires --ledger <file.json> (an array of ledger entries or {drawId,entries})');
    const data = JSON.parse(await readFile(resolve(o.ledger), 'utf8'));
    const entries = Array.isArray(data) ? data : data.entries || [];
    const l = createLedger();
    for (const e of entries) l.post(e);
    const drawId = o.draw || data.drawId || 'draw';
    console.log(JSON.stringify(l.reconciliationSheet(drawId, { winnerProofLink: o.proof || null }), null, 2));
    return;
  }

  if (cmd === 'verify') {
    const path = o.proof || o.file || o._[0];
    if (!path) return fail('verify requires --proof <file.json> (a draw proof or an audit trail)');
    const obj = JSON.parse(await readFile(resolve(path), 'utf8'));
    if (obj && obj.entriesRoot) {
      if (!o.entries) return fail('verifying a draw proof also requires --entries <file.json>');
      const entries = JSON.parse(await readFile(resolve(o.entries), 'utf8'));
      console.log(JSON.stringify(verifyDraw(obj, entries), null, 2));
    } else {
      console.log(JSON.stringify(verifyTrail(obj), null, 2));
    }
    return;
  }

  if (cmd === 'init') {
    const dir = resolve(o._[0] || 'my-raffle');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'package.json'), STARTER_PKG);
    await writeFile(join(dir, 'raffle.js'), STARTER_RAFFLE);
    await writeFile(join(dir, '.env.example'), STARTER_ENV);
    await writeFile(join(dir, '.gitignore'), STARTER_GITIGNORE);
    await writeFile(join(dir, 'README.md'), STARTER_README);
    console.log(
      `Scaffolded a raffle in ${dir}\n  cd ${dir} && npm install && cp .env.example .env && node raffle.js`,
    );
    return;
  }

  help();
}

function help() {
  console.log(`
walletless-kit — walletless web architecture (onboarding · proofs · audit · ledger · draw)

Commands
  init [dir]                              scaffold a starter raffle project
  keygen [--out <file>]                   generate a dev Algorand account (mnemonic)
  draw --entries <f> --seed <s> [--winners N]
                                          run a draw and print its recomputable proof
  reconcile --ledger <f> [--draw id]      print a per-draw reconciliation sheet
  verify --proof <f> [--entries <f>]      recompute a draw proof or an audit trail
  help

TestNet by default. Prize draws/lotteries are regulated — see LEGAL.md.
MIT · Kirke Labs · free & open source
`);
}

const STARTER_PKG = `{
  "name": "my-raffle",
  "private": true,
  "type": "module",
  "dependencies": { "@kirkelabs/walletless-kit": "^0.1.0" }
}
`;

const STARTER_ENV = `# Operator account (dev). Generate with: npx walletless keygen --out owner.json
# SECRET — never commit your real .env. The 25 words control all funds.
OPERATOR_MNEMONIC="word1 word2 ... word25"
NETWORK=algorand-testnet
`;

const STARTER_GITIGNORE = `# Secrets — NEVER commit these. The mnemonic controls all funds.
.env
*.key
owner.json
node_modules/
`;

const STARTER_RAFFLE = `import {
  getAlgod, runDraw, publishDrawProof, verifyDraw,
  createLedger, OtpIdentity, deterministicOrderId,
} from '@kirkelabs/walletless-kit';

// A minimal, OFFLINE walletless raffle: entries -> draw -> proof -> verify.
// See the package's examples/raffle.js for the full on-chain TestNet flow.
const entries = ['ref_alice', 'ref_bob', 'ref_carol', 'ref_dave'];
const seed = 'demo-seed-replace-with-a-committed-block-hash';

const proof = publishDrawProof({ entries, seed, winners: 1 });
console.log('Winner:', proof.winners[0]);
console.log('Proof verifies:', verifyDraw(proof, entries).ok);

// NOTE: a real draw must use a COMMITTED public seed (announce the future block
// round before entries close) — see the README guardrails. Prize draws are
// regulated; you own licensing, the free-entry route, and age/geo gating.
`;

const STARTER_README = `# my-raffle

A starter walletless raffle built with @kirkelabs/walletless-kit.

1. \`npx walletless keygen --out owner.json\` (TestNet operator account)
2. Fund it on TestNet: https://bank.testnet.algorand.network/
3. \`npm install && node raffle.js\`

⚠ Prize draws/lotteries are REGULATED. This is transparency tooling, not legal
compliance: you are responsible for licensing, a genuine free-entry route, and
age/geo gating. Draw fairness equals the public seed you choose — use a committed
block hash or a VRF/beacon. See the package LEGAL.md.
`;

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
