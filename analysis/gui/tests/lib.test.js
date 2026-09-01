// Tests for the pure logic extracted to static/lib.js. Node's built-in test runner only —
// no new dependencies (codice-minimo.md rung 5).
//
// Run: cd analysis/gui && node --test tests/*.test.js
// (the glob, not `node --test tests/`: on Node 26 the directory form tries to require the
// directory itself and fails before running anything)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const lib = require('../static/lib.js');
const {
  esc,
  fileKey,
  pendingFiles,
  TOOL_NOTICES,
  toolNotices,
  techniqueName,
  techniqueLabel,
  TECHNIQUE_MAP,
  svgIcon,
  svgBarChart,
  summarizeRecord,
  matchIocs,
  iocScopeText,
  _tlWhyClass,
  timelineFilter,
  bundleAnalysis,
  _thorSevColor,
  zeekStatusColor,
  statTiles,
} = lib;

// ─── esc() ───

test('esc escapes &, < and > (in that order, so & is not double-escaped)', () => {
  assert.equal(esc('a & b < c > d'), 'a &amp; b &lt; c &gt; d');
});

test('esc escapes each of the five characters on its own', () => {
  assert.equal(esc('&'), '&amp;');
  assert.equal(esc('<'), '&lt;');
  assert.equal(esc('>'), '&gt;');
  assert.equal(esc('"'), '&quot;');
  assert.equal(esc("'"), '&#39;');
});

// esc() is used in ATTRIBUTE position at several call sites (title="...", value="..."), not just
// as text markup — an unescaped quote there breaks out of the attribute.
test('esc escapes double and single quotes (attribute-position safety)', () => {
  assert.equal(esc('say "hi"'), 'say &quot;hi&quot;');
  assert.equal(esc("it's a trap"), 'it&#39;s a trap');
  assert.equal(esc(`"><script>alert(1)</script>`), '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
});

test('esc coerces non-string input instead of throwing', () => {
  assert.equal(esc(null), 'null');
  assert.equal(esc(undefined), 'undefined');
  assert.equal(esc(42), '42');
});

// ─── techniqueName / techniqueLabel ───

test('techniqueName/techniqueLabel before the map is populated', () => {
  assert.equal(techniqueName('T1003'), '');
  assert.equal(techniqueLabel('T1003'), 'T1003');   // falls back to the bare id
});

test('techniqueName/techniqueLabel once the map has an entry', () => {
  // Mutate in place (not `TECHNIQUE_MAP = {...}`) — techniqueName/techniqueLabel close over
  // the binding lib.js declares, and only a mutation of the same object is visible to them
  // from here (a reassignment of the exported property would not be).
  TECHNIQUE_MAP['T1003.001'] = { name: 'LSASS Memory' };
  assert.equal(techniqueName('T1003.001'), 'LSASS Memory');
  assert.equal(techniqueLabel('T1003.001'), 'T1003.001 — LSASS Memory');
  delete TECHNIQUE_MAP['T1003.001'];
});

// ─── svgIcon ───

test('svgIcon returns an svg with the icon\'s path and requested size, empty path for an unknown name', () => {
  const known = svgIcon('check', 20);
  assert.match(known, /<svg[^>]*width="20"[^>]*height="20"/);
  assert.match(known, /<path d="m424-296/);
  const unknown = svgIcon('nope-not-a-real-icon');
  assert.match(unknown, /<path d=""\/>/);
});

// ─── svgBarChart ───

test('svgBarChart returns empty string when every row has a falsy value', () => {
  assert.equal(svgBarChart([{ k: 'a', v: 0 }], 'k', 'v'), '');
  assert.equal(svgBarChart([], 'k', 'v'), '');
  assert.equal(svgBarChart(undefined, 'k', 'v'), '');
});

test('svgBarChart caps at maxBars and escapes labels', () => {
  const rows = [
    { k: '<script>', v: 5 },
    { k: 'b', v: 3 },
    { k: 'c', v: 1 },
  ];
  const svg = svgBarChart(rows, 'k', 'v', 2);
  assert.match(svg, /<svg/);
  assert.match(svg, /&lt;script&gt;/);       // label escaped, not raw markup
  assert.ok(!svg.includes('c<'), 'the 3rd row (over maxBars) must not be rendered');
});

test('svgBarChart links a recognized ATT&CK technique id to attack.mitre.org', () => {
  TECHNIQUE_MAP['T1059'] = { name: 'Command and Scripting Interpreter' };
  const svg = svgBarChart([{ tid: 'T1059', hits: 4 }], 'tid', 'hits');
  assert.match(svg, /https:\/\/attack\.mitre\.org\/techniques\/T1059\//);
  delete TECHNIQUE_MAP['T1059'];
});

// ─── summarizeRecord ───

test('summarizeRecord builds a short summary from known fields', () => {
  const rec = { 'source.ip': '10.0.0.1', 'destination.ip': '10.0.0.2', 'destination.port': 443 };
  assert.equal(summarizeRecord(rec), '10.0.0.1 -> 10.0.0.2 :443');
});

test('summarizeRecord falls back to a truncated JSON dump when no known field is present', () => {
  const rec = { unrelated_field: 'x'.repeat(200) };
  const out = summarizeRecord(rec);
  assert.ok(out.length <= 80);
  assert.match(out, /^\{"unrelated_field"/);
});

// ─── iocScopeText ───

test('iocScopeText says nothing when the searchable corpus is the whole dataset', () => {
  assert.equal(iocScopeText(120, 120), '');
  assert.equal(iocScopeText(0, 0), '');
  assert.equal(iocScopeText(5000, 900), '');    // total below shown: nothing to warn about
});

test('iocScopeText names both counts when the corpus is truncated', () => {
  const text = iocScopeText(5000, 41233);
  assert.match(text, /first 5,000 of 41,233 events/);
  // the point of the sentence: a miss here is not evidence of absence
  assert.match(text, /not proof of absence/);
});

// ─── matchIocs ───

test('matchIocs finds a hit in the middle of a field, case-insensitively', () => {
  const records = [{ 'process.name': 'MIMIKATZ.exe', '@timestamp': 't1', 'event.source': 'evtx' }];
  const matches = matchIocs(records, ['mikatz']);
  assert.equal(matches['mikatz'].length, 1);
  assert.equal(matches['mikatz'][0].source, 'evtx');
});

test('matchIocs returns an empty array for a genuine miss', () => {
  const records = [{ 'process.name': 'explorer.exe' }];
  const matches = matchIocs(records, ['mimikatz']);
  assert.deepEqual(matches['mimikatz'], []);
});

test('matchIocs does not throw on records missing the field entirely', () => {
  const records = [{}, { 'file.name': null }, { nested: { deep: 'evil.com' } }];
  assert.doesNotThrow(() => matchIocs(records, ['evil.com']));
  const matches = matchIocs(records, ['evil.com']);
  assert.equal(matches['evil.com'].length, 1);   // the nested field still matches (stringify+search)
});

test('matchIocs defaults source/timestamp when absent, and searches every ioc independently', () => {
  const records = [{ 'dns.question.name': 'evil.com' }];
  const matches = matchIocs(records, ['evil.com', 'not-there']);
  assert.equal(matches['evil.com'][0].source, 'unknown');
  assert.equal(matches['evil.com'][0].timestamp, '');
  assert.deepEqual(matches['not-there'], []);
});

// ─── _tlWhyClass ───

test('_tlWhyClass classifies findings, warnings and neutral pills', () => {
  assert.equal(_tlWhyClass('ATT&CK technique'), 'pill bad');
  assert.equal(_tlWhyClass('THOR finding'), 'pill bad');
  assert.equal(_tlWhyClass('high-signal event type'), 'pill bad');
  assert.equal(_tlWhyClass('failed action'), 'pill warn');
  assert.equal(_tlWhyClass('Sigma: some rule'), 'pill warn');
  assert.equal(_tlWhyClass('context'), 'pill');
  assert.equal(_tlWhyClass(undefined), 'pill');
});

// ─── timelineFilter ───

const TL_ROWS = [
  { host: 'HOST-01', user_name: 'USER-01', source: 'evtx', why: 'ATT&CK technique', process_name: 'powershell.exe' },
  { host: 'HOST-02', user_name: 'USER-02', source: 'pcap', why: 'context', dst_ip: '203.0.113.7' },
  { host: 'HOST-01', user_name: 'USER-03', source: 'logs', why: 'failed action', url: 'http://evil.example/x' },
];

test('timelineFilter with no filters returns every row', () => {
  assert.equal(timelineFilter(TL_ROWS, {}).length, 3);
  assert.equal(timelineFilter(TL_ROWS, { q: '' }).length, 3);
});

test('timelineFilter matches q against each searchable field', () => {
  assert.equal(timelineFilter(TL_ROWS, { q: 'HOST-01' }).length, 2);
  assert.equal(timelineFilter(TL_ROWS, { q: 'powershell' }).length, 1);
  assert.equal(timelineFilter(TL_ROWS, { q: '203.0.113.7' }).length, 1);
  assert.equal(timelineFilter(TL_ROWS, { q: 'evil.example' }).length, 1);
});

test('timelineFilter q is case-insensitive', () => {
  assert.equal(timelineFilter(TL_ROWS, { q: 'host-01' }).length, 2);
  assert.equal(timelineFilter(TL_ROWS, { q: 'POWERSHELL' }).length, 1);
});

test('timelineFilter source and why filters are exact matches, combinable with q', () => {
  assert.equal(timelineFilter(TL_ROWS, { source: 'evtx' }).length, 1);
  assert.equal(timelineFilter(TL_ROWS, { why: 'failed action' }).length, 1);
  assert.equal(timelineFilter(TL_ROWS, { source: 'evtx', q: 'USER-01' }).length, 1);
  assert.equal(timelineFilter(TL_ROWS, { source: 'evtx', q: 'USER-03' }).length, 0);
});

test('timelineFilter that matches nothing returns []', () => {
  assert.deepEqual(timelineFilter(TL_ROWS, { q: 'no-such-value-anywhere' }), []);
  assert.deepEqual(timelineFilter(TL_ROWS, { source: 'no-such-source' }), []);
});

// ─── bundleAnalysis ───

test('bundleAnalysis reads a well-formed bundle_version 1 export', () => {
  const bundle = {
    bundle_version: 1,
    meta: { records: 10 },
    analysis: { summary: { events: 10 } },
  };
  const a = bundleAnalysis(bundle);
  assert.equal(a.summary.events, 10);
  assert.deepEqual(a._meta, { records: 10 });   // meta is copied down when analysis lacks one
});

test('bundleAnalysis accepts a bare analyze() export (report --format json --level full)', () => {
  const bare = { summary: { events: 3 } };
  assert.equal(bundleAnalysis(bare), bare);   // returned as-is
});

test('bundleAnalysis rejects malformed input with a descriptive error (does not silently coerce)', () => {
  assert.throws(() => bundleAnalysis(null), /not a bundle/);
  assert.throws(() => bundleAnalysis([1, 2, 3]), /not a bundle/);
  assert.throws(() => bundleAnalysis({}), /not a bundle and not an analysis export/);
  assert.throws(() => bundleAnalysis({ bundle_version: 2, analysis: {} }), /unsupported bundle_version 2/);
  assert.throws(() => bundleAnalysis({ bundle_version: 1 }), /'analysis' missing/);
});

// ─── _thorSevColor ───

test('_thorSevColor maps known severities and falls back to muted', () => {
  assert.equal(_thorSevColor('high'), 'var(--bad)');
  assert.equal(_thorSevColor('medium'), 'var(--warn)');
  assert.equal(_thorSevColor('low'), 'var(--muted)');
  assert.equal(_thorSevColor('unknown-severity'), 'var(--muted)');
  assert.equal(_thorSevColor(undefined), 'var(--muted)');
});

// ─── zeekStatusColor ───

test('zeekStatusColor bands 2xx/3xx/other, missing status reads as "other"', () => {
  assert.equal(zeekStatusColor('200'), 'var(--accent)');
  assert.equal(zeekStatusColor(301), 'var(--warn)');
  assert.equal(zeekStatusColor('404'), 'var(--bad)');
  assert.equal(zeekStatusColor('500'), 'var(--bad)');
  assert.equal(zeekStatusColor(undefined), 'var(--bad)');
  assert.equal(zeekStatusColor(''), 'var(--bad)');
});

// ─── statTiles ───

test('statTiles stringifies each value and coalesces null/undefined to "0"', () => {
  assert.deepEqual(
    statTiles([[5, 'events'], [undefined, 'hosts'], [null, 'users'], [0, 'episodes']]),
    [{ n: '5', l: 'events' }, { n: '0', l: 'hosts' }, { n: '0', l: 'users' }, { n: '0', l: 'episodes' }]
  );
});

test('statTiles returns [] for missing/empty input', () => {
  assert.deepEqual(statTiles(undefined), []);
  assert.deepEqual(statTiles([]), []);
});

// ─── Structural guard (Task B rule, pinned so it cannot silently come back) ───
//
// The rule: esc() belongs only inside template strings assigned to innerHTML; never around a
// value passed as a plain text child of el() (el() appends text children via .append(), which
// never interprets markup, so esc()'ing them just shows a literal "&amp;" on screen).
//
// This regex catches the direct-argument form that caused the bug: `el('tag', ..., esc(...))`
// with no backtick between "el(" and "esc(" (a backtick means esc() is building an HTML string
// for innerHTML, which is correct). It anchors on `el(` preceded by a word boundary and a
// quoted tag name, so it does not false-positive on prose like "...el() ... esc()..." in
// comments, or on identifiers that merely end in "el(" (e.g. techniqueLabel(...)).
//
// It deliberately does NOT catch indirect violations where esc() is wrapped in a concatenation
// before reaching el() (e.g. `el('span', {}, 'updated ' + esc(x))`) — those were reviewed and
// fixed by hand (analysis/gui/static/index.html, case cards) but are not mechanically pinned
// here; a readable regex for that shape would need to tolerate arbitrary prefix expressions,
// which stops being reliably distinguishable from legitimate string-building.
// ─── pendingFiles / fileKey ──────────────────────────────────────────────────
// The defect these guard: every Analyze click re-sent the whole accumulated session, and the case
// store refuses only an EXACT repeat of a batch — so "EVTX, then EVTX+PCAP" appended the EVTX
// records twice and every additive number in the analysis read high.
const f = (name, size, lastModified) => ({ name, size, lastModified });

test('pendingFiles returns everything when nothing has been ingested', () => {
  const files = [f('a.evtx', 10, 1), f('b.evtx', 20, 2)];
  assert.deepEqual(pendingFiles(files, new Set()), files);
  assert.deepEqual(pendingFiles(files, null), files);
  assert.deepEqual(pendingFiles(undefined, new Set()), []);
});

test('pendingFiles offers a file to a case exactly once', () => {
  const evtx = f('Security.evtx', 4096, 1700000000000);
  const pcap = f('capture.pcap', 512, 1700000001000);
  const ingested = new Set();
  // First click: the EVTX goes.
  assert.deepEqual(pendingFiles([evtx], ingested), [evtx]);
  pendingFiles([evtx], ingested).forEach(x => ingested.add(fileKey(x)));
  // Second click, after adding a capture: ONLY the capture goes. This is the whole fix.
  assert.deepEqual(pendingFiles([evtx, pcap], ingested), [pcap]);
});

test('fileKey separates files that differ in any of name, size or mtime', () => {
  const base = f('Security.evtx', 4096, 1700000000000);
  const keys = new Set([
    fileKey(base),
    fileKey(f('Security.evtx', 4097, 1700000000000)),
    fileKey(f('Security.evtx', 4096, 1700000009000)),
    fileKey(f('System.evtx', 4096, 1700000000000)),
  ]);
  assert.equal(keys.size, 4);
  // Two hosts' Security.evtx of identical size, collected at the same instant, would collide —
  // stated rather than hidden: the browser exposes nothing else without reading every byte back
  // on each click, and the collision costs a skipped duplicate, never a dropped distinct file.
  assert.equal(fileKey(base), fileKey(f('Security.evtx', 4096, 1700000000000)));
});

// ─── toolNotices ─────────────────────────────────────────────────────────────
test('toolNotices names only what is actually missing, and says what it costs', () => {
  const all = { hayabusa: true, tshark: true, zeek: true, evtxecmd: true, recmd: true };
  assert.deepEqual(toolNotices('evtx', all), []);
  assert.deepEqual(toolNotices('pcap', all), []);

  const noZeek = { ...all, zeek: false };
  const n = toolNotices('pcap', noZeek);
  assert.equal(n.length, 1);
  assert.equal(n[0].required, false);
  assert.match(n[0].lost, /application layer/);
  assert.match(n[0].lost, /tshark/);           // says what still works, not only what is lost
});

test('toolNotices stays silent until health has been asked', () => {
  // null health is "not asked yet", which must not render as "everything is missing".
  assert.deepEqual(toolNotices('evtx', null), []);
  assert.deepEqual(toolNotices('evtx', undefined), []);
  // An unknown key is unknown, not false: only an explicit false is a missing tool.
  assert.deepEqual(toolNotices('evtx', {}), []);
  assert.equal(toolNotices('evtx', { hayabusa: false, evtxecmd: false }).length, 2);
});

test('every view with an uploader that TOOL_NOTICES covers has a placeholder in index.html', () => {
  const htmlPath = path.join(__dirname, '..', 'static', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');
  for (const view of Object.keys(TOOL_NOTICES)) {
    assert.ok(html.includes(`id="${view}-tool-notice"`), `no notice placeholder for the ${view} view`);
  }
});

test('esc() never appears as a direct text-child argument of an el() call in index.html', () => {
  const htmlPath = path.join(__dirname, '..', 'static', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const re = /\bel\(\s*['"][\w-]+['"][^`]*?,\s*esc\(/g;
  const matches = html.match(re) || [];
  assert.deepEqual(matches, []);
});
