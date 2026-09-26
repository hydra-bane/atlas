// Builds and signs the Atlas bundle that `hydra-bane atlas update` downloads.
// Format matches hydra-bane src/atlas/bundle.ts: atlas-bundle.json = {schema:2, bundle_seq, created, entries} (entries in schema 2), and
// atlas-bundle.json.sig = base64 of the raw 64-byte Ed25519 signature over the exact bytes of atlas-bundle.json.
//
//   ATLAS_SIGNING_KEY=<path to private key PEM> node scripts/bundle.mjs build [--out dist] [--release]
//   node scripts/bundle.mjs verify [dist/atlas-bundle.json]
//
// --release also writes the new seq to bundle-seq.txt; commit that file together with the release.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { entryFiles, validateEntry, validateFiles } from './entry-validate.mjs';

export const ATLAS_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4KB00lv83/aH04JUgObXNipstROZDKFo4Giu2Cgp5+k=
-----END PUBLIC KEY-----
`;

export function verify(bytes, sigBase64, publicKeyPem = ATLAS_PUBLIC_KEY_PEM) {
  const sig = Buffer.from(String(sigBase64).trim(), 'base64');
  if (sig.length !== 64) return false;
  try { return crypto.verify(null, bytes, crypto.createPublicKey(publicKeyPem), sig); } catch { return false; }
}

/** Returns the bundle bytes and signature; throws on any invalid entry or a key that does not match publicKeyPem. */
export function build({ dir = '.', keyPem, seqFile = path.join(dir, 'bundle-seq.txt'), now = new Date(), publicKeyPem = ATLAS_PUBLIC_KEY_PEM }) {
  const { problems, entries } = validateFiles(entryFiles(path.join(dir, 'entries')));
  if (problems.length) throw new Error(`invalid entries:\n${problems.join('\n')}`);
  if (!entries.length) throw new Error('no entries');
  const prev = Number(fs.readFileSync(seqFile, 'utf8').trim());
  if (!Number.isSafeInteger(prev) || prev < 0) throw new Error(`${seqFile} must hold a whole number`);
  const bundle = { schema: 2, bundle_seq: prev + 1, created: now.toISOString(), entries: entries.sort((a, b) => a.id.localeCompare(b.id)) };
  const bytes = Buffer.from(JSON.stringify(bundle, null, 2) + '\n', 'utf8');
  const sig = crypto.sign(null, bytes, crypto.createPrivateKey(keyPem)).toString('base64');
  if (!verify(bytes, sig, publicKeyPem)) throw new Error('signature does not verify with the published public key (wrong signing key?)');
  return { bytes, sig, bundle };
}

if (import.meta.url === `file://${process.argv[1]}` || import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}`) {
  const [cmd, ...args] = process.argv.slice(2);
  const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
  try {
    if (cmd === 'build') {
      const keyFile = process.env.ATLAS_SIGNING_KEY;
      if (!keyFile) throw new Error('set ATLAS_SIGNING_KEY to the private key PEM path');
      const { bytes, sig, bundle } = build({ keyPem: fs.readFileSync(keyFile) });
      const out = opt('--out', 'dist');
      fs.mkdirSync(out, { recursive: true });
      fs.writeFileSync(path.join(out, 'atlas-bundle.json'), bytes);
      fs.writeFileSync(path.join(out, 'atlas-bundle.json.sig'), sig + '\n');
      if (args.includes('--release')) fs.writeFileSync('bundle-seq.txt', `${bundle.bundle_seq}\n`);
      const sha = crypto.createHash('sha256').update(bytes).digest('hex');
      console.log(`built ${out}/atlas-bundle.json: bundle_seq ${bundle.bundle_seq}, ${bundle.entries.length} entries, ${bytes.length} bytes, sha256 ${sha}; signature verified`);
    } else if (cmd === 'verify') {
      const file = args[0] ?? 'dist/atlas-bundle.json';
      const bytes = fs.readFileSync(file);
      if (!verify(bytes, fs.readFileSync(`${file}.sig`, 'utf8'))) throw new Error(`${file}: bad signature`);
      const b = JSON.parse(bytes.toString('utf8'));
      if (b.schema !== 2) throw new Error(`${file}: bundle schema ${b.schema}, expected 2`);
      const bad = b.entries.filter((e) => validateEntry(e).length).map((e) => e?.id);
      if (bad.length) throw new Error(`${file}: invalid entries ${bad.join(', ')}`);
      console.log(`${file}: signature OK, bundle_seq ${b.bundle_seq}, created ${b.created}, ${b.entries.length} entries, all valid`);
    } else {
      throw new Error('usage: bundle.mjs build [--out dist] [--release] | verify [file]');
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
