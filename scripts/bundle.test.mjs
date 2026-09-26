import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { build, verify } from './bundle.mjs';

const root = path.join(import.meta.dirname, '..');
const throwaway = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) };
};
function tmpRepo(seq = '4') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-bundle-'));
  fs.cpSync(path.join(root, 'entries'), path.join(dir, 'entries'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'bundle-seq.txt'), `${seq}\n`);
  return dir;
}

test('builds a signed bundle with seq = previous + 1 that verifies byte for byte', () => {
  const k = throwaway(), dir = tmpRepo();
  const { bytes, sig, bundle } = build({ dir, ...k, now: new Date('2026-09-26T00:00:00Z') });
  assert.equal(bundle.bundle_seq, 5);
  assert.equal(bundle.schema, 2);
  assert.ok(bundle.entries.every((e) => e.schema === 2));
  assert.equal(bundle.entries.length, fs.readdirSync(path.join(root, 'entries')).filter((f) => f.endsWith('.json')).length);
  assert.equal(Buffer.from(sig, 'base64').length, 64);
  assert.ok(verify(bytes, sig, k.publicKeyPem));
  assert.ok(!verify(Buffer.concat([bytes, Buffer.from(' ')]), sig, k.publicKeyPem), 'one extra byte breaks it');
  assert.ok(!verify(bytes, sig), 'a throwaway key never verifies against the published key');
});

test('refuses to build with an invalid entry, a bad seq file, or a key that does not match the published one', () => {
  const k = throwaway();
  const dir = tmpRepo();
  fs.writeFileSync(path.join(dir, 'entries', 'kr.bad.entry.json'), JSON.stringify({ schema: 2, id: 'kr.bad.entry' }));
  assert.throws(() => build({ dir, ...k }), /invalid entries/);
  assert.throws(() => build({ dir: tmpRepo('x'), ...k }), /whole number/);
  assert.throws(() => build({ dir: tmpRepo(), keyPem: k.keyPem }), /does not verify with the published public key/);
});
