// Atlas entry validator, schema 2. KEEP IN SYNC with validateEntry in hydra-bane/hydra-bane src/atlas/entry.ts:
// the client runs that function on every bundle entry, so any rule that differs here ships entries users reject.
// Usage: node scripts/entry-validate.mjs [files...]   (default: every entries/*.json)
import fs from 'node:fs';
import path from 'node:path';

export const SOURCE_KINDS = ['security-research', 'vendor', 'government', 'news', 'regulator', 'package-manifest'];
export const ADVISORY_PUBLISHERS = ['KISA', 'NVD', 'EUVD', 'CISA', 'JVN', 'CERT-FR', 'BSI', 'NCSC', 'vendor', 'other'];

const ID = /^[a-z]{2}\.[a-z0-9-]+\.[a-z0-9-]+$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
export const GUID = /^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$/i;
const VERSION = /^\d+(?:[.,]\d+)*$/;
// Our own fields carry no verdicts: these words may appear only inside quoted advisory titles.
export const VERDICT_WORDS = /\b(malware|virus|scam|spyware|trojan|adware|pup|junk|bloatware|crapware|vulnerable|insecure|dangerous)\b|사기|악성|취약|위험/i;
const TOP_KEYS = ['schema', 'id', 'names', 'vendor', 'context', 'tags', 'detect', 'uninstall', 'residue', 'reversible', 'reinstall_note', 'sources', 'advisories', 'source', 'vendor_response', 'dispute', 'verified', 'verified_by', 'added', 'last_reviewed'];
const https = (u) => typeof u === 'string' && /^https:\/\/[^\s]+$/.test(u);

/** Returns problems; an empty list means the entry may be used. The client runs this on every bundle entry. */
export function validateEntry(e) {
  const p = [];
  if (!e || typeof e !== 'object' || Array.isArray(e)) return ['entry is not an object'];
  const x = e;
  for (const k of Object.keys(x)) if (!TOP_KEYS.includes(k)) p.push(`unexpected field ${k}`);
  if (x.schema !== 2) p.push('schema must be 2');
  if (typeof x.id !== 'string' || !ID.test(x.id)) p.push('id must look like cc.vendor.product');
  if (!Array.isArray(x.names) || !x.names.length || !x.names.every((n) => typeof n === 'string' && n.length > 0 && n.length <= 120)) p.push('names');
  if (typeof x.vendor?.name !== 'string' || !x.vendor.name) p.push('vendor.name');
  if (typeof x.context !== 'string' || x.context.length < 10 || x.context.length > 400) p.push('context: one neutral sentence (10-400 chars)');
  if (!Array.isArray(x.tags?.countries) || !x.tags.countries.length || !x.tags.countries.every((c) => /^[A-Z]{2}$/.test(c))) p.push('tags.countries');
  const signers = x.detect?.signers, keys = x.detect?.uninstall_keys, certs = x.detect?.root_certs;
  if (!Array.isArray(signers) || !Array.isArray(keys) || !Array.isArray(certs)) p.push('detect.signers, detect.uninstall_keys and detect.root_certs must be lists');
  else {
    if (!signers.length && !keys.length) p.push('detect needs a signer or an uninstall key (file names alone are not accepted)');
    for (const s of signers) if (typeof s?.subject !== 'string' || !s.subject || !Array.isArray(s.thumbprints) || !s.thumbprints.every((t) => /^[0-9A-F]{40}$/i.test(t))) p.push('detect.signers entry');
    for (const k of keys) {
      if (typeof k?.display_name !== 'string' || !k.display_name) { p.push('detect.uninstall_keys entry'); continue; }
      try { new RegExp(k.display_name, 'i'); } catch { p.push(`bad display_name regex ${k.display_name}`); }
    }
    if (!certs.every((c) => typeof c === 'string' && c.length >= 4 && c.length <= 200)) p.push('detect.root_certs entries must be subject substrings of 4-200 chars');
  }
  const u = x.uninstall;
  if (!u || !['msi-product-code', 'signed-exe'].includes(u.command_source)) p.push('uninstall.command_source');
  else {
    if (!Array.isArray(u.msi_product_codes) || !u.msi_product_codes.every((g) => GUID.test(g))) p.push('uninstall.msi_product_codes');
    if (u.command_source === 'signed-exe' && (typeof u.exe_name !== 'string' || !/^[\w .()-]+\.exe$/i.test(u.exe_name))) p.push('uninstall.exe_name must be a plain .exe file name');
    if (u.command_source === 'signed-exe' && !(signers ?? []).some((s) => s.thumbprints?.length)) p.push('signed-exe needs at least one signer thumbprint');
  }
  if (x.residue !== 'report-only') p.push('residue must be report-only');
  if (x.reversible !== 'reinstall-only') p.push('reversible must be reinstall-only');
  if (!Array.isArray(x.sources) || !x.sources.length || !x.sources.every((v) => https(v?.url) && DATE.test(v.date ?? '') && SOURCE_KINDS.includes(v.kind))) p.push('sources: at least one https source with a kind and date');
  if (!Array.isArray(x.advisories)) p.push('advisories must be a list');
  else for (const a of x.advisories) {
    if (!ADVISORY_PUBLISHERS.includes(a?.publisher) || !https(a.url) || !DATE.test(a.date ?? '') || typeof a.title !== 'string' || !a.title) { p.push('advisory needs publisher, https url, date and title'); continue; }
    if (a.cve !== undefined && (!Array.isArray(a.cve) || !a.cve.every((c) => /^CVE-\d{4}-\d{4,}$/.test(c)))) p.push('advisory.cve');
    if (a.affected !== undefined) {
      const f = a.affected, ver = (v) => typeof v === 'string' && VERSION.test(v);
      const list = Array.isArray(f.versions) && f.versions.length > 0 && f.versions.every(ver);
      const range = ver(f.up_to) && typeof f.inclusive === 'boolean' && (f.from === undefined || ver(f.from));
      if (!(list && f.up_to === undefined && f.from === undefined && f.inclusive === undefined) && !(range && f.versions === undefined)) p.push('advisory.affected: either versions[] or up_to + inclusive (+ optional from), digits and dots');
    }
    if (a.kev !== undefined && typeof a.kev !== 'boolean') p.push('advisory.kev');
  }
  if (!['original', 'win11debloat', 'loldrivers'].includes(x.source)) p.push('source');
  if (!Array.isArray(x.vendor_response)) p.push('vendor_response');
  if (!['none', 'open', 'upheld', 'rejected'].includes(x.dispute?.status)) p.push('dispute.status');
  if (typeof x.verified !== 'boolean' || ![null, 'bootstrap', 'maintainers'].includes(x.verified_by)) p.push('verified/verified_by');
  if (!DATE.test(x.added ?? '') || !DATE.test(x.last_reviewed ?? '')) p.push('added/last_reviewed dates');
  const own = [x.names, x.vendor?.name, x.context, x.reinstall_note, x.tags?.kind].flat().filter((v) => typeof v === 'string').join(' ');
  if (VERDICT_WORDS.test(own)) p.push('verdict words (malware, vulnerable, 취약, 악성…) are not allowed in our own fields; quote an advisory instead');
  return p;
}

/** Repo-level checks on top of validateEntry: the file name is the id, and ids are unique. */
export function validateFiles(files) {
  const problems = [], entries = [], seen = new Set();
  for (const f of files) {
    let e;
    try { e = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (err) { problems.push(`${f}: invalid JSON (${err.message})`); continue; }
    for (const m of validateEntry(e)) problems.push(`${f}: ${m}`);
    if (e?.id !== path.basename(f, '.json')) problems.push(`${f}: file name must be <id>.json`);
    if (seen.has(e?.id)) problems.push(`${f}: duplicate id ${e.id}`);
    seen.add(e?.id);
    entries.push(e);
  }
  return { problems, entries };
}

export const entryFiles = (dir = 'entries') => (fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => path.join(dir, f)) : []);

if (import.meta.url === `file://${process.argv[1]}` || import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}`) {
  const files = process.argv.length > 2 ? process.argv.slice(2) : entryFiles();
  const { problems, entries } = validateFiles(files);
  const stale = entries.filter((e) => typeof e?.last_reviewed === 'string' && Date.now() - Date.parse(e.last_reviewed) > 365 * 864e5);
  for (const e of stale) console.log(`warning: ${e.id} last_reviewed ${e.last_reviewed} is over 12 months old`);
  for (const m of problems) console.error(m);
  console.log(`${files.length} entries checked, ${problems.length} problem(s)`);
  process.exit(problems.length ? 1 : 0);
}
