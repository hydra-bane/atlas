import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { entryFiles, validateEntry, validateFiles } from './entry-validate.mjs';

const good = {
  schema: 2, id: 'kr.example.product', names: ['Example'], vendor: { name: 'Example Co.', country: 'KR' },
  context: 'Security module that some Korean banking websites ask users to install.',
  tags: { countries: ['KR'], kind: 'banking-security' },
  detect: { signers: [{ subject: 'CN=Example*', thumbprints: ['0F3E67708D7DB53143A69F2F9DA1C41120D02C21'] }], uninstall_keys: [{ display_name: '^Example$', publisher: 'Example Co.' }], root_certs: ['Example Root CA'] },
  uninstall: { command_source: 'signed-exe', msi_product_codes: [], exe_name: 'uninst.exe' },
  residue: 'report-only', reversible: 'reinstall-only',
  sources: [{ url: 'https://example.org/a', kind: 'vendor', date: '2023-01-09' }],
  advisories: [{ publisher: 'KISA', url: 'https://www.boho.or.kr/x', date: '2025-07-07', title: '보안 취약점 업데이트 권고', cve: ['CVE-2020-7882'], affected: { up_to: '1.1.4.3', inclusive: true }, kev: false }],
  source: 'original', vendor_response: [], dispute: { status: 'none' }, verified: false, verified_by: null, added: '2026-09-26', last_reviewed: '2026-09-26',
};
const bad = (patch) => validateEntry({ ...structuredClone(good), ...patch });
const withAdvisory = (a) => bad({ advisories: [{ ...good.advisories[0], ...a }] });

test('accepts a complete entry', () => assert.deepEqual(validateEntry(good), []));

test('an entry without a known uninstaller or advisories is valid', () => {
  assert.deepEqual(bad({ detect: { signers: [], uninstall_keys: [{ display_name: '^X' }], root_certs: [] }, uninstall: { command_source: 'msi-product-code', msi_product_codes: [] }, advisories: [] }), []);
});

test('rejects what the client would reject', () => {
  assert.ok(bad({ schema: 1 }).length);
  assert.ok(bad({ id: 'Example' }).length);
  assert.ok(bad({ command: 'cmd /c x' }).some((e) => e.includes('unexpected field')));
  for (const old of ['category', 'criteria_refs', 'removal_recommendation', 'evidence']) assert.ok(bad({ [old]: [] }).some((e) => e.includes(`unexpected field ${old}`)), old);
  assert.ok(bad({ context: 'short' }).some((e) => e.startsWith('context')));
  assert.ok(bad({ context: undefined }).some((e) => e.startsWith('context')));
  assert.ok(bad({ tags: { countries: ['Korea'] } }).length);
  assert.ok(bad({ detect: { signers: [], uninstall_keys: [] , root_certs: [] } }).some((e) => e.includes('detect needs')));
  assert.ok(bad({ detect: { signers: [], uninstall_keys: [{ display_name: '^X' }] } }).some((e) => e.includes('root_certs must be lists')));
  assert.ok(bad({ detect: { signers: [], uninstall_keys: [{ display_name: '^X' }], root_certs: ['CA'] } }).some((e) => e.includes('root_certs entries')));
  assert.ok(bad({ detect: { signers: [], uninstall_keys: [{ display_name: '(' }], root_certs: [] } }).some((e) => e.includes('regex')));
  assert.ok(bad({ uninstall: { command_source: 'signed-exe', msi_product_codes: [], exe_name: '..\\x.exe' } }).some((e) => e.includes('exe_name')));
  assert.ok(bad({ detect: { signers: [{ subject: 'CN=X', thumbprints: [] }], uninstall_keys: [], root_certs: [] } }).some((e) => e.includes('thumbprint')));
  assert.ok(bad({ uninstall: { command_source: 'msi-product-code', msi_product_codes: ['not-a-guid'] } }).length);
  assert.ok(bad({ sources: [{ url: 'http://example.org', kind: 'vendor', date: '2023-01-01' }] }).some((e) => e.startsWith('sources')));
  assert.ok(bad({ sources: [{ url: 'https://example.org', kind: 'blog', date: '2023-01-01' }] }).some((e) => e.startsWith('sources')));
  assert.ok(bad({ sources: [] }).some((e) => e.startsWith('sources')));
  assert.ok(bad({ advisories: undefined }).some((e) => e.startsWith('advisories')));
  assert.ok(bad({ residue: 'quarantine' }).length);
  assert.ok(bad({ verified_by: 'me' }).length);
});

test('advisories need a known publisher, https url, date and title; cve, affected and kev are checked', () => {
  assert.ok(withAdvisory({ publisher: 'blog' }).some((e) => e.startsWith('advisory needs')));
  assert.ok(withAdvisory({ url: 'http://x' }).some((e) => e.startsWith('advisory needs')));
  assert.ok(withAdvisory({ date: '2025-7-7' }).some((e) => e.startsWith('advisory needs')));
  assert.ok(withAdvisory({ title: '' }).some((e) => e.startsWith('advisory needs')));
  assert.ok(withAdvisory({ cve: ['CVE-20-1'] }).includes('advisory.cve'));
  assert.ok(withAdvisory({ affected: { up_to: 'v1.0', inclusive: true } }).some((e) => e.startsWith('advisory.affected')));
  assert.ok(withAdvisory({ affected: { up_to: '1.0' } }).some((e) => e.startsWith('advisory.affected')));
  assert.ok(withAdvisory({ kev: 'yes' }).includes('advisory.kev'));
  assert.deepEqual(withAdvisory({ cve: undefined, affected: undefined, kev: undefined }), []);
  assert.deepEqual(withAdvisory({ affected: { up_to: '4,0,0,0', inclusive: false } }), []);
});

test('advisory.affected is either a version list or a range with an optional lower bound, never both', () => {
  const affected = (f) => withAdvisory({ affected: f }).some((e) => e.startsWith('advisory.affected'));
  assert.ok(!affected({ from: '1.1.4.4', up_to: '1.1.4.6', inclusive: true }));
  assert.ok(!affected({ versions: ['1.1.1.0', '1.1.2.6', '1.1.2.7'] }));
  assert.ok(affected({ versions: [] }), 'empty list');
  assert.ok(affected({ versions: ['1.1.x'] }), 'non-numeric version');
  assert.ok(affected({ versions: ['1.0'], up_to: '2.0', inclusive: true }), 'list plus range');
  assert.ok(affected({ versions: ['1.0'], inclusive: true }), 'list with a stray inclusive');
  assert.ok(affected({ from: '1.0' }), 'lower bound alone');
  assert.ok(affected({ from: 'v1', up_to: '2.0', inclusive: true }), 'non-numeric lower bound');
  assert.ok(affected({}), 'empty object');
});

test('verdict words are rejected in our own fields but allowed in quoted advisory and source titles', () => {
  assert.ok(bad({ names: ['Example malware'] }).some((e) => e.startsWith('verdict')));
  assert.ok(bad({ context: 'A vulnerable banking module.' }).some((e) => e.startsWith('verdict')));
  assert.ok(bad({ context: '은행 사이트가 요구하는 취약한 모듈입니다.' }).some((e) => e.startsWith('verdict')));
  assert.ok(bad({ reinstall_note: '악성 프로그램' }).some((e) => e.startsWith('verdict')));
  assert.ok(bad({ tags: { countries: ['KR'], kind: 'adware' } }).some((e) => e.startsWith('verdict')));
  assert.deepEqual(bad({ context: 'Reports vulnerability notices to the vendor.' }), [], 'whole words only');
  assert.deepEqual(bad({ sources: [{ url: 'https://example.org', kind: 'news', date: '2023-01-25', title: "Korea's mandatory spyware" }] }), []);
  assert.deepEqual(withAdvisory({ title: 'Lenovo Superfish Adware Vulnerable to HTTPS Spoofing' }), []);
});

test('file name must match id, ids unique, and every committed entry is valid', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-'));
  fs.writeFileSync(path.join(dir, 'wrong.json'), JSON.stringify(good));
  assert.ok(validateFiles([path.join(dir, 'wrong.json')]).problems.some((p) => p.includes('<id>.json')));
  const a = path.join(dir, 'kr.example.product.json');
  fs.writeFileSync(a, JSON.stringify(good));
  assert.ok(validateFiles([a, a]).problems.some((p) => p.includes('duplicate id')));
  const { problems, entries } = validateFiles(entryFiles(path.join(import.meta.dirname, '..', 'entries')));
  assert.deepEqual(problems, []);
  assert.ok(entries.length > 0);
});
