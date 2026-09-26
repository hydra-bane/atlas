import assert from 'node:assert/strict';
import { test } from 'node:test';
import { extractReport, merge, rateLimit, validate } from './intake.mjs';

const good = {
  schema: 1, kind: 'atlas-report', suggested_id: 'ahnlab-inc.ahnlab-safe-transaction',
  program: { name: 'AhnLab Safe Transaction', publisher: 'AhnLab, Inc.', version: '1.18.1.1997' },
  detect: {
    uninstall_key: { hive: 'HKLM', view: '64', key_name: '{19DD1D8D-927F-45DF-ADF4-75D38267848D}', display_name: 'AhnLab Safe Transaction', publisher: 'AhnLab, Inc.' },
    signer: { status: 'Valid', subject: 'CN="AhnLab, Inc."', thumbprint: '0F3E67708D7DB53143A69F2F9DA1C41120D02C21' },
    file: { path: '%ProgramFiles%\\AhnLab\\Safe Transaction\\StSess.exe', size: 8999440, sha256: 'e08974166f64c6d3fa006029b600c2058b33e6d84c67befd58bdbde111e692bf' },
  },
  install_location: '%ProgramFiles%\\AhnLab\\Safe Transaction', country: 'KR', note: 'installed by a bank website', reporter_tool: 'hydra-bane 0.2.0',
};
const body = (r) => `Submitted with \`hydra-bane report\`.\n\n\`\`\`json\n${JSON.stringify(r, null, 2)}\n\`\`\``;

test('accepts a report from the CLI and from the issue form', () => {
  assert.deepEqual(validate(extractReport(body(good)).report), []);
  const form = `### Report\n\n\`\`\`json\n${JSON.stringify(good, null, 2)}\n\`\`\`\n`;
  assert.deepEqual(validate(extractReport(form).report), []);
});

test('rejects malformed, oversized, extra-field and privacy-leaking reports', () => {
  assert.match(extractReport('no json here').error, /no ```json/);
  assert.match(extractReport('```json\n{bad\n```').error, /invalid JSON/);
  const bad = (patch) => validate({ ...structuredClone(good), ...patch });
  assert.ok(bad({ suggested_id: '../../etc.passwd' }).some((e) => e.includes('suggested_id')));
  assert.ok(bad({ suggested_id: 'a.b; rm x' }).some((e) => e.includes('suggested_id')));
  assert.ok(bad({ uninstall: { command: 'cmd /c evil' } }).some((e) => e.includes('unexpected field')));
  assert.ok(bad({ note: 'x'.repeat(301) }).length);
  assert.ok(bad({ country: 'Korea' }).length);
  assert.ok(bad({ install_location: 'C:\\Users\\alice\\AppData' }).some((e) => e.startsWith('privacy')));
  assert.ok(bad({ note: 'from alice@example.com' }).some((e) => e.startsWith('privacy')));
  assert.ok(bad({ note: 'HKU\\S-1-5-21-1-2-3-1001' }).some((e) => e.startsWith('privacy')));
  const f = structuredClone(good); f.detect.file.path = 'C:\\Tools\\x.exe';
  assert.ok(validate(f).some((e) => e.includes('%VAR%')));
});

test('merges repeat reports into one candidate and counts distinct reporters', () => {
  let c = merge(undefined, good, { issue: 3, author: 'kim', date: '2026-09-26' });
  c = merge(c, { ...good, country: 'KR', program: { ...good.program, version: '1.19' } }, { issue: 5, author: 'lee', date: '2026-09-27' });
  c = merge(c, { ...good, note: 'edited' }, { issue: 5, author: 'lee', date: '2026-09-27' }); // issue edited
  c = merge(c, good, { issue: 9, author: 'kim', date: '2026-09-28' });
  assert.equal(c.report_count, 3);
  assert.equal(c.distinct_reporters, 2);
  assert.deepEqual(c.countries, ['KR']);
  assert.equal(c.reports.find((x) => x.issue === 5).note, 'edited');
  assert.equal(c.seen_sha256.length, 1);
});

test('spam limits: new accounts, more than 5 reports in 24h, and bad logins are held back', () => {
  const at = '2026-09-26T12:00:00Z';
  const old = '2020-01-01T00:00:00Z';
  const hoursAgo = (h) => ({ createdAt: new Date(Date.parse(at) - h * 36e5).toISOString() });
  assert.equal(rateLimit({ login: 'kim', accountCreated: old, issueCreated: at, recent: [hoursAgo(0)] }), null);
  assert.match(rateLimit({ login: 'kim', accountCreated: '2026-09-20T12:00:01Z', issueCreated: at, recent: [] }), /7 days/);
  assert.equal(rateLimit({ login: 'kim', accountCreated: '2026-09-19T12:00:00Z', issueCreated: at, recent: [] }), null);
  const five = [0, 1, 2, 3, 23].map(hoursAgo);
  assert.equal(rateLimit({ login: 'kim', accountCreated: old, issueCreated: at, recent: five }), null);
  assert.match(rateLimit({ login: 'kim', accountCreated: old, issueCreated: at, recent: [...five, hoursAgo(5)] }), /5 reports/);
  // Older reports and reports filed after this one (an edit re-run) do not count.
  assert.equal(rateLimit({ login: 'kim', accountCreated: old, issueCreated: at, recent: [...five, hoursAgo(25), hoursAgo(-2)] }), null);
  assert.ok(rateLimit({ login: 'kim; touch x', accountCreated: old, issueCreated: at, recent: [] }));
  assert.ok(rateLimit({ login: '-kim', accountCreated: old, issueCreated: at, recent: [] }));
  assert.ok(rateLimit({ login: 'kim', accountCreated: 'garbage', issueCreated: at, recent: [] }));
});
