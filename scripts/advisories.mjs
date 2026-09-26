// Weekly advisory watch. For every entry it asks NVD and EUVD (by the entry's names and vendor) and reads the KISA
// RSS feeds, keeps what mentions one of the entry's names and is not in the entry yet, and writes the candidates.
// It never edits entries: a maintainer reads each advisory and adds it with the version range it states.
//
//   node scripts/advisories.mjs [--out candidates/advisories.json] [--body advisories-pr.md]
//
// Set NVD_API_KEY to use NVD's higher rate limit. Everything fetched is untrusted text: it is only parsed, matched and
// escaped into Markdown, never passed to a shell.
import fs from 'node:fs';
import { entryFiles, validateFiles } from './entry-validate.mjs';

export const KISA_FEEDS = ['https://www.boho.or.kr/kr/rss.do?bbsId=B0000133', 'https://www.boho.or.kr/kr/rss.do?bbsId=B0000302'];
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=';
const EUVD_URL = 'https://euvdservices.enisa.europa.eu/api/search?size=100&text=';
const NON_WINDOWS = new Set(['mac_os_x', 'macos', 'iphone_os', 'ipados', 'android', 'linux']);
const CVE = /^CVE-\d{4}-\d{4,}$/;

const norm = (s) => String(s).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '');
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** True when the text names the entry. Short names must stand as a whole word ("ASTx" must not match "fastx"). */
export function mentions(text, entry) {
  const t = String(text ?? ''), nt = norm(t);
  return entry.names.some((n) => {
    const nn = norm(n);
    if (nn.length >= 6) return nt.includes(nn);
    return nn.length >= 3 && new RegExp(`(^|[^\\p{L}\\p{N}])${escapeRe(n)}([^\\p{L}\\p{N}]|$)`, 'iu').test(t);
  });
}

/** Terms sent to NVD and EUVD: Latin-script names and the vendor, each once. */
export function searchTerms(entry) {
  const seen = new Set(), out = [];
  for (const t of [...entry.names, entry.vendor?.name]) {
    if (typeof t !== 'string' || t.length < 4 || !/^[\x20-\x7e]+$/.test(t) || seen.has(t.toLowerCase())) continue;
    seen.add(t.toLowerCase());
    out.push(t);
  }
  return out;
}

const text = (s, max = 200) => String(s ?? '').replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const day = (s) => { const d = new Date(s); return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 10); };

/** KISA RSS: [{title, url, date, nttId}]; links are rebuilt from the numeric ids, never taken as given. */
export function parseRss(xml) {
  const cdata = (s) => text((s ?? '').replace(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/, '$1'), 300);
  const out = [];
  for (const [, item] of String(xml).matchAll(/<item>([\s\S]*?)<\/item>/g)) {
    const title = cdata(item.match(/<title>([\s\S]*?)<\/title>/)?.[1]);
    const link = cdata(item.match(/<link>([\s\S]*?)<\/link>/)?.[1]);
    let u;
    try { u = new URL(link); } catch { continue; }
    const [bbsId, menuNo, nttId] = ['bbsId', 'menuNo', 'nttId'].map((k) => u.searchParams.get(k) ?? '');
    if (!title || u.protocol !== 'https:' || u.host !== 'www.boho.or.kr' || u.pathname !== '/kr/bbs/view.do' || !/^B\d{7}$/.test(bbsId) || !/^\d+$/.test(menuNo) || !/^\d+$/.test(nttId)) continue;
    out.push({ title, nttId, date: day(cdata(item.match(/<pubDate>([\s\S]*?)<\/pubDate>/)?.[1])), url: `https://www.boho.or.kr/kr/bbs/view.do?bbsId=${bbsId}&menuNo=${menuNo}&nttId=${nttId}` });
  }
  return out;
}

export const parseKev = (json) => new Set((json?.vulnerabilities ?? []).map((v) => v?.cveID).filter((c) => CVE.test(c ?? '')));

/** NVD CPE match → version hint from the configuration ("up to 1.2.3 inclusive", "from 1.0"). */
function cpeHint(m) {
  const parts = [];
  if (m.versionStartIncluding) parts.push(`from ${m.versionStartIncluding}`);
  if (m.versionStartExcluding) parts.push(`after ${m.versionStartExcluding}`);
  if (m.versionEndIncluding) parts.push(`up to ${m.versionEndIncluding} inclusive`);
  if (m.versionEndExcluding) parts.push(`before ${m.versionEndExcluding}`);
  const v = m.criteria?.split(':')[5];
  if (!parts.length && v && v !== '*' && v !== '-') parts.push(`version ${v}`);
  return parts.map((p) => text(p, 60)).join(' ');
}

/** NVD 2.0 response → candidates that mention the entry, skipping rejected CVEs and CPEs for other platforms only. */
export function parseNvd(json, entry, kev = new Set()) {
  const out = [];
  for (const { cve } of json?.vulnerabilities ?? []) {
    if (!CVE.test(cve?.id ?? '') || /reject/i.test(cve.vulnStatus ?? '')) continue;
    const desc = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? '';
    const matches = (cve.configurations ?? []).flatMap((c) => c.nodes ?? []).flatMap((n) => n.cpeMatch ?? []).filter((m) => m.vulnerable && typeof m.criteria === 'string');
    const named = matches.filter((m) => mentions(m.criteria.split(':').slice(3, 5).join(' '), entry));
    if (!mentions(desc, entry) && !named.length) continue;
    const relevant = named.length ? named : matches;
    if (relevant.length && relevant.every((m) => NON_WINDOWS.has(m.criteria.split(':')[10]))) continue;
    out.push({
      publisher: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${cve.id}`, date: day(cve.published), title: `NVD - ${cve.id}`, cve: [cve.id], kev: kev.has(cve.id),
      versions: [...new Set(relevant.map(cpeHint).filter(Boolean))].join('; '), summary: text(desc),
    });
  }
  return out;
}

/** EUVD search response → candidates that mention the entry. */
export function parseEuvd(json, entry, kev = new Set()) {
  const out = [];
  for (const it of json?.items ?? []) {
    if (!/^EUVD-\d{4}-\d+$/.test(it?.id ?? '')) continue;
    const products = (it.enisaIdProduct ?? []).map((p) => `${p?.product?.name ?? ''} ${p?.product_version ?? ''}`);
    if (!mentions([it.description, ...products].join(' '), entry)) continue;
    // ponytail: EUVD has no CPE platform field, so "on macOS"-style wording in the description stands in for it.
    if (/\bon (mac ?os( x)?|os x|android|ios|linux)\b/i.test(it.description ?? '') && !/windows/i.test(it.description ?? '')) continue;
    const cve = String(it.aliases ?? '').split(/\s+/).filter((a) => CVE.test(a));
    out.push({
      publisher: 'EUVD', url: `https://euvd.enisa.europa.eu/vulnerability/${it.id}`, date: day(it.datePublished), title: it.id, ...(cve.length ? { cve } : {}), kev: cve.some((c) => kev.has(c)),
      versions: text([...new Set((it.enisaIdProduct ?? []).map((p) => p?.product_version).filter((v) => v && v !== 'n/a'))].join(', '), 120), summary: text(it.description),
    });
  }
  return out;
}

const kisaId = (u) => (/boho\.or\.kr|krcert\.or\.kr/.test(u) ? u.match(/nttId=(\d+)/)?.[1] : undefined);

/** Whether the entry already carries this advisory (same URL, same KISA post, or a shared CVE). */
export function isKnown(c, entry) {
  return entry.advisories.some((a) => a.url === c.url || (kisaId(c.url) && kisaId(c.url) === kisaId(a.url)) || (a.cve ?? []).some((x) => (c.cve ?? []).includes(x)));
}

/** New candidates per entry; an EUVD record is dropped when NVD already reported the same CVE. */
export function newCandidates(entry, found) {
  const out = [], cves = new Set();
  for (const c of [...found].sort((a, b) => (a.publisher === 'NVD' ? -1 : 0) - (b.publisher === 'NVD' ? -1 : 0))) {
    if (isKnown(c, entry) || out.some((o) => o.url === c.url)) continue;
    if (c.publisher === 'EUVD' && c.cve?.some((x) => cves.has(x))) continue;
    for (const x of c.cve ?? []) cves.add(x);
    out.push(c);
  }
  return out.sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '') || a.url.localeCompare(b.url));
}

const md = (s) => text(s, 300).replace(/[\\`*_[\]<>|#~!]/g, '\\$&').replace(/@/g, '@\u200b').replace(/(https?):\/\//gi, '$1\u200b://');

export function renderBody(byEntry, errors = []) {
  const lines = ['Candidate advisories found by the weekly watch (NVD, EUVD, KISA RSS, CISA KEV). Nothing here reaches users.', '',
    'For each one: open the advisory, check that it is about the Windows program in the entry, and add it to the entry\'s `advisories` with the title as published and the versions the advisory itself states (`affected`: a range with optional `from`, or a `versions` list). Close the ones that are not about the entry.', ''];
  for (const [id, list] of byEntry) {
    if (!list.length) continue;
    lines.push(`### ${id}`, '');
    for (const c of list) {
      const extra = [c.cve?.length ? c.cve.join(', ') : '', c.kev ? '**in CISA KEV**' : '', c.versions ? `versions: ${md(c.versions)}` : ''].filter(Boolean).join(' · ');
      lines.push(`- ${c.publisher} ${c.date ?? 'undated'}: [${md(c.title)}](${c.url})${extra ? ` · ${extra}` : ''}`);
      if (c.summary) lines.push(`  > ${md(c.summary)}`);
    }
    lines.push('');
  }
  if (errors.length) lines.push('### Sources that failed this run', '', ...errors.map((e) => `- ${md(e)}`), '');
  return lines.join('\n');
}

// --- network ---

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getText(url, { headers = {}, timeout = 60_000 } = {}) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, { headers: { 'User-Agent': 'hydra-bane-atlas advisory watch (+https://github.com/hydra-bane/atlas)', ...headers }, signal: AbortSignal.timeout(timeout), redirect: 'follow' });
    if (res.ok) return res.text();
    if (attempt < 2 && [403, 429, 500, 502, 503, 504].includes(res.status)) { await sleep(30_000 * (attempt + 1)); continue; }
    throw new Error(`HTTP ${res.status}`);
  }
}

export async function scan(entries, { log = console.error } = {}) {
  const errors = [], byEntry = new Map();
  const nvdKey = process.env.NVD_API_KEY, nvdGap = nvdKey ? 700 : 6_500;
  let kev = new Set();
  try { kev = parseKev(JSON.parse(await getText(KEV_URL))); } catch (e) { errors.push(`CISA KEV: ${e.message}`); }
  const rss = [];
  for (const feed of KISA_FEEDS) {
    try { rss.push(...parseRss(await getText(feed))); } catch (e) { errors.push(`KISA RSS ${feed}: ${e.message}`); }
  }
  let first = true;
  for (const entry of entries) {
    const found = rss.filter((r) => mentions(r.title, entry)).map((r) => ({ publisher: 'KISA', url: r.url, date: r.date, title: r.title }));
    for (const term of searchTerms(entry)) {
      if (!first) await sleep(nvdGap);
      first = false;
      try { found.push(...parseNvd(JSON.parse(await getText(NVD_URL + encodeURIComponent(term), { headers: nvdKey ? { apiKey: nvdKey } : {} })), entry, kev)); }
      catch (e) { errors.push(`NVD "${term}": ${e.message}`); }
      try { found.push(...parseEuvd(JSON.parse(await getText(EUVD_URL + encodeURIComponent(term))), entry, kev)); }
      catch (e) { errors.push(`EUVD "${term}": ${e.message}`); }
    }
    const list = newCandidates(entry, found);
    log(`${entry.id}: ${found.length} matching, ${list.length} new`);
    byEntry.set(entry.id, list);
  }
  return { byEntry, errors };
}

if (import.meta.url === `file://${process.argv[1]}` || import.meta.url === `file:///${process.argv[1]?.replace(/\\/g, '/')}`) {
  const args = process.argv.slice(2);
  const opt = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : dflt; };
  const { problems, entries } = validateFiles(entryFiles());
  if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
  const { byEntry, errors } = await scan(entries);
  const count = [...byEntry.values()].reduce((n, l) => n + l.length, 0);
  const out = opt('--out', 'candidates/advisories.json'), body = opt('--body', 'advisories-pr.md');
  fs.writeFileSync(out, JSON.stringify(Object.fromEntries([...byEntry].filter(([, l]) => l.length)), null, 2) + '\n');
  fs.writeFileSync(body, renderBody(byEntry, errors));
  for (const e of errors) console.error(`error: ${e}`);
  console.log(`${count} new candidate(s), ${errors.length} source error(s)`);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `count=${count}\nerrors=${errors.length}\n`);
}
