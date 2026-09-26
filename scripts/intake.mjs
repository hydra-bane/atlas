// Turns a `hydra-bane report` issue into a candidate file (PLAN.md §7.7 in the hydra-bane repo).
// Issue content is untrusted: it arrives through environment variables, is validated against a closed schema,
// and only a validated id ever reaches a file name or a git branch.
import fs from 'node:fs';
import path from 'node:path';

const ID = /^[a-z0-9-]{1,40}\.[a-z0-9-]{1,40}$/;
const TOP_KEYS = ['schema', 'kind', 'suggested_id', 'program', 'detect', 'install_location', 'country', 'note', 'reporter_tool'];
const LEAKS = [
  [/[a-z]:\\{1,2}(?:users|documents and settings)\\{1,2}/i, 'contains a real profile path'],
  [/S-1-5-21-\d/i, 'contains a Windows SID'],
  [/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/, 'contains an email address'],
];

export function extractReport(body) {
  const m = /```json\s*\n([\s\S]*?)\n```/.exec(body ?? '');
  if (!m) return { error: 'no ```json block found' };
  try { return { report: JSON.parse(m[1]) }; } catch (e) { return { error: `invalid JSON: ${e.message}` }; }
}

const str = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;
const optStr = (v, max) => v === undefined || (typeof v === 'string' && v.length <= max);

export function validate(r) {
  const errors = [];
  if (!r || typeof r !== 'object' || Array.isArray(r)) return ['report is not an object'];
  const raw = JSON.stringify(r);
  if (raw.length > 8000) errors.push('report is too large');
  for (const k of Object.keys(r)) if (!TOP_KEYS.includes(k)) errors.push(`unexpected field "${k}"`);
  if (r.schema !== 1 || r.kind !== 'atlas-report') errors.push('not an atlas-report (schema 1)');
  if (typeof r.suggested_id !== 'string' || !ID.test(r.suggested_id)) errors.push('suggested_id must look like vendor.program');
  if (!str(r.program?.name, 200) || !optStr(r.program?.publisher, 200) || !optStr(r.program?.version, 100)) errors.push('program name/publisher/version missing or too long');
  const k = r.detect?.uninstall_key;
  if (!k || !['HKLM', 'HKCU'].includes(k.hive) || !['64', '32'].includes(k.view) || !str(k.key_name, 200) || !str(k.display_name, 200)) errors.push('detect.uninstall_key is incomplete');
  const s = r.detect?.signer;
  if (s !== undefined && (!str(s.status, 40) || !optStr(s.subject, 600) || (s.thumbprint !== undefined && !/^[0-9A-F]{40}$/i.test(s.thumbprint)))) errors.push('detect.signer is malformed');
  const f = r.detect?.file;
  if (f !== undefined && (!str(f.path, 400) || !/^%[A-Za-z0-9()]+%\\/.test(f.path) || (f.sha256 !== undefined && !/^[0-9a-f]{64}$/.test(f.sha256)))) errors.push('detect.file must use a %VAR%\\ path and a SHA-256');
  if (r.detect?.msi_product_code !== undefined && !/^\{[0-9A-F-]{36}\}$/i.test(r.detect.msi_product_code)) errors.push('msi_product_code is malformed');
  if (r.country !== undefined && !/^[A-Z]{2}$/.test(r.country)) errors.push('country must be a two-letter code');
  if (!optStr(r.note, 300) || !optStr(r.install_location, 400) || !optStr(r.reporter_tool, 60)) errors.push('note/install_location/reporter_tool too long');
  for (const [re, why] of LEAKS) if (re.test(raw)) errors.push(`privacy: ${why}; please re-run a current hydra-bane report`);
  return errors;
}

/** Add one report to a candidate. Re-running for the same issue (an edit) replaces that issue's entry. */
export function merge(existing, r, meta) {
  const c = existing ?? { id: r.suggested_id, status: 'candidate', program: r.program, detect: r.detect, install_location: r.install_location, seen_sha256: [], reports: [] };
  const sha = r.detect?.file?.sha256;
  if (sha && !c.seen_sha256.includes(sha)) c.seen_sha256.push(sha);
  c.reports = c.reports.filter((x) => x.issue !== meta.issue);
  c.reports.push({ issue: meta.issue, author: meta.author, date: meta.date, version: r.program.version, country: r.country, note: r.note, tool: r.reporter_tool });
  c.reports.sort((a, b) => a.issue - b.issue);
  c.report_count = c.reports.length;
  c.distinct_reporters = new Set(c.reports.map((x) => x.author)).size;
  c.countries = [...new Set(c.reports.map((x) => x.country).filter(Boolean))].sort();
  return c;
}

function out(name, value) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}<<__HB__\n${value}\n__HB__\n`);
  else console.log(`${name}=${value}`);
}

// CLI: `node scripts/intake.mjs check` validates and prints the id; `node scripts/intake.mjs write` updates candidates/<id>.json.
if (import.meta.url === `file://${process.argv[1]}` || import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}`) {
  const x = extractReport(process.env.ISSUE_BODY);
  const errors = x.error ? [x.error] : validate(x.report);
  if (errors.length) { out('errors', errors.map((e) => `- ${e}`).join('\n')); process.exit(0); }
  const r = x.report;
  out('id', r.suggested_id);
  out('name', r.program.name.replace(/[\r\n`]/g, ' '));
  if (process.argv[2] === 'write') {
    const file = path.join('candidates', `${r.suggested_id}.json`);
    const existing = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : undefined;
    const c = merge(existing, r, { issue: Number(process.env.ISSUE_NUMBER), author: process.env.ISSUE_AUTHOR, date: (process.env.ISSUE_CREATED ?? '').slice(0, 10) });
    fs.mkdirSync('candidates', { recursive: true });
    fs.writeFileSync(file, JSON.stringify(c, null, 2) + '\n');
    out('count', String(c.report_count));
  }
}
