import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { isKnown, mentions, newCandidates, parseEuvd, parseKev, parseNvd, parseRss, renderBody, searchTerms } from './advisories.mjs';

const fx = (f) => fs.readFileSync(path.join(import.meta.dirname, 'fixtures', f), 'utf8');
const entry = (id) => JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', 'entries', `${id}.json`), 'utf8'));
const anysign = entry('kr.hancomwith.anysign4pc'), veraport = entry('kr.wizvera.veraport'), superfish = entry('us.superfish.visualdiscovery');
const astx = entry('kr.ahnlab.safe-transaction'), touchen = entry('kr.raonsecure.touchen-nxkey');

test('mentions: long names match inside words and CPE names, short names only as whole words', () => {
  assert.ok(mentions('cpe:2.3:a:hancom:anysign4pc:1.1.1.0', anysign));
  assert.ok(mentions('anySign 디렉토리 탐색', anysign));
  assert.ok(mentions('보안 모듈 ASTx 업데이트', astx));
  assert.ok(!mentions('fastx compression library', astx));
  assert.ok(mentions('터치엔 엔엑스키 업데이트', touchen));
  assert.ok(!mentions('Hancom Office Word', anysign));
});

test('search terms: Latin-script names and vendor, no duplicates', () => {
  assert.deepEqual(searchTerms(veraport), ['Veraport', 'WIZVERA Veraport', 'Veraport G3', 'Wizvera']);
  assert.ok(!searchTerms(touchen).includes('터치엔 엔엑스키'));
});

test('KISA RSS: items parsed, links rebuilt from ids, other hosts dropped', () => {
  const items = parseRss(fx('kisa-rss.xml'));
  assert.equal(items.length, 4);
  assert.deepEqual(items[1], { title: '한컴위드 제품 보안 업데이트 권고 (AnySign4PC)', nttId: '72177', date: '2026-09-01', url: 'https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72177' });
  assert.equal(items[3].url, 'https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000302&menuNo=205023&nttId=71959');
  assert.ok(!items.some((i) => i.url.includes('evil')));
  assert.deepEqual(parseRss('<rss><item><title>x</title></item></rss>'), []);
});

test('KEV: a set of CVE ids', () => {
  const kev = parseKev(JSON.parse(fx('kev.json')));
  assert.ok(kev.has('CVE-2020-7882'));
  assert.equal(kev.size, 2);
  assert.equal(parseKev({}).size, 0);
});

test('NVD: keeps CVEs that name the entry, skips macOS-only CPEs and unrelated vendor CVEs, reads version hints and KEV', () => {
  const nvd = JSON.parse(fx('nvd.json')), kev = parseKev(JSON.parse(fx('kev.json')));
  const a = parseNvd(nvd, anysign, kev);
  assert.deepEqual(a.map((c) => c.cve[0]), ['CVE-2020-7882'], 'CPE product anysign4pc matches; Hancom Office CVE does not');
  assert.equal(a[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2020-7882');
  assert.equal(a[0].date, '2021-11-22');
  assert.equal(a[0].kev, true);
  assert.equal(a[0].versions, 'version 1.1.1.0; version 1.1.2.6; version 1.1.2.7');
  assert.deepEqual(parseNvd(nvd, veraport), [], 'CVE-2018-5198 is Veraport on macOS only');
  assert.deepEqual(parseNvd(nvd, superfish).map((c) => c.cve[0]), ['CVE-2015-2077'], 'named in the description');
  const withRange = structuredClone(nvd);
  withRange.vulnerabilities[0].cve.configurations[0].nodes[0].cpeMatch = [{ vulnerable: true, criteria: 'cpe:2.3:a:hancom:anysign4pc:*:*:*:*:*:*:*:*', versionStartIncluding: '1.1.4.4', versionEndIncluding: '1.1.4.6' }];
  assert.equal(parseNvd(withRange, anysign)[0].versions, 'from 1.1.4.4 up to 1.1.4.6 inclusive');
  withRange.vulnerabilities[0].cve.vulnStatus = 'Rejected';
  assert.deepEqual(parseNvd(withRange, anysign), []);
});

test('EUVD: keeps records that name the entry, with CVE aliases and product versions', () => {
  const e = parseEuvd(JSON.parse(fx('euvd.json')), anysign);
  assert.equal(e.length, 1);
  assert.deepEqual(e[0].cve, ['CVE-2020-7882']);
  assert.equal(e[0].url, 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2020-28814');
  assert.equal(e[0].date, '2021-11-22');
  assert.equal(e[0].versions, '1.1.2.7, 1.1.1.0, 1.1.2.6');
  assert.deepEqual(parseEuvd(JSON.parse(fx('euvd.json')), astx), [], 'AhnLab EPP records do not name Safe Transaction');
  const mac = { items: [{ id: 'EUVD-2018-16983', description: 'In Veraport G3 ALL on MacOS, a race condition ...', aliases: 'CVE-2018-5198\n', datePublished: 'Dec 20, 2018, 2:00:00 PM', enisaIdProduct: [] }] };
  assert.deepEqual(parseEuvd(mac, veraport), [], 'macOS-only records are skipped');
});

test('known advisories are not candidates again; EUVD duplicates of NVD CVEs are dropped', () => {
  const kisa = parseRss(fx('kisa-rss.xml')).filter((r) => mentions(r.title, anysign)).map((r) => ({ publisher: 'KISA', url: r.url, date: r.date, title: r.title }));
  const found = [...kisa, ...parseEuvd(JSON.parse(fx('euvd.json')), anysign), ...parseNvd(JSON.parse(fx('nvd.json')), anysign)];
  assert.ok(isKnown(kisa[0], anysign), 'KISA nttId 72177 is already in the entry (different URL form)');
  assert.deepEqual(newCandidates(anysign, found).map((c) => c.url), ['https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72201'], 'CVE-2020-7882 is already in the entry');
  const bare = { ...anysign, advisories: [] };
  assert.deepEqual(newCandidates(bare, found).map((c) => c.publisher), ['KISA', 'KISA', 'NVD'], 'EUVD record for the same CVE as NVD is dropped');
});

test('PR body escapes untrusted text and lists failed sources', () => {
  const found = parseRss(fx('kisa-rss.xml')).filter((r) => mentions(r.title, anysign)).map((r) => ({ publisher: 'KISA', url: r.url, date: r.date, title: r.title }));
  const body = renderBody(new Map([[anysign.id, newCandidates(anysign, found)], [veraport.id, []]]), ['NVD "Veraport": HTTP 503']);
  assert.ok(body.includes('### kr.hancomwith.anysign4pc'));
  assert.ok(!body.includes('### kr.wizvera.veraport'));
  assert.ok(body.includes('\\`$(touch /tmp/pwned)\\`'), 'backticks escaped');
  assert.ok(!body.includes('<b>') && !body.includes(' @maintainer'), 'no raw HTML, no mention');
  assert.ok(body.includes('NVD "Veraport": HTTP 503'));
});
