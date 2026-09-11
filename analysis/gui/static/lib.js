// Pure logic extracted from index.html's inline <script> (no `document`, no `session`/
// `lastResult` globals, no `fetch`, no side effects) so it can be exercised by
// `node --test tests/` instead of only `node --check` (syntax, not behaviour).
//
// Loaded as a plain classic script, before the inline <script> block
// (`<script src="lib.js"></script>`), so every name below stays a global exactly as it was
// when it lived inline — the rest of the page calls these unqualified, unchanged.
//
// Also loadable via require() from Node's test runner (see the module.exports at the bottom).

// Used both as text-node markup (only &<> matter) and in ATTRIBUTE position (title="...",
// href="...") across index.html — an unescaped " or ' there breaks out of the attribute and lets
// whatever follows in the value become live markup/attributes. & must go first so escaping the
// other four characters cannot introduce a second '&' that then gets re-escaped.
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// ─── ATT&CK Technique Map ───
// TECHNIQUE_MAP is populated by the page from /api/attack-map (analytics/attack_map.json — the
// SAME file the engine uses, generated from the official STIX bundle). That fetch is I/O and
// stays in the page; techniqueName/techniqueLabel are pure lookups over whatever is currently
// loaded (empty object until the fetch resolves — both return '' until then, same as before).
let TECHNIQUE_MAP = {};
function techniqueName(tid) {
    const e = TECHNIQUE_MAP[tid];
    return e ? e.name : '';
}
function techniqueLabel(tid) {
    const name = techniqueName(tid);
    return name ? `${tid} — ${name}` : tid;
}

// Single source of truth for UI icons — official Material Symbols (Outlined, 24px,
// viewBox 0 -960 960 960), from github.com/google/material-design-icons, embedded inline
// (fully offline, CSP-safe). One path per glyph → every place that shows e.g. "EVTX" uses
// the same icon (no more sidebar/panel mismatch).
//
// THIRD-PARTY: these path data are Google's, licensed Apache-2.0 — the one piece of somebody
// else's work actually redistributed in this repository (everything else is downloaded at install
// time and stays outside it). Inlining does not change the licence; see NOTICE.md.
const ICON_PATHS = {
    dashboard: 'M520-600v-240h320v240H520ZM120-440v-400h320v400H120Zm400 320v-400h320v400H520Zm-400 0v-240h320v240H120Zm80-400h160v-240H200v240Zm400 320h160v-240H600v240Zm0-480h160v-80H600v80ZM200-200h160v-80H200v80Zm160-320Zm240-160Zm0 240ZM360-280Z',
    // NOT from the Material set: the icons above were vendored offline and that set, as
    // vendored here, carries no graph/hub glyph. Drawn in the same 0 -960 960 960 grid so it
    // sits with the others — recorded as hand-drawn so nobody later assumes a provenance it
    // does not have. Three linked nodes: the attack map in miniature.
    hub: 'M390-760a90 90 0 1 0 180 0a90 90 0 1 0-180 0M150-280a90 90 0 1 0 180 0a90 90 0 1 0-180 0M630-280a90 90 0 1 0 180 0a90 90 0 1 0-180 0M496.6-688.9L463.4-711.1L223.4-351.1L256.6-328.9ZM463.4-688.9L496.6-711.1L736.6-351.1L703.4-328.9Z',
    timeline: 'M612-292l56-56-148-148v-184h-80v216l172 172ZM480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-320Zm0 240q100 0 170-70t70-170q0-100-70-170t-170-70q-100 0-170 70t-70 170q0 100 70 170t170 70Z',
    evtx: 'M320-240h320v-80H320v80Zm0-160h320v-80H320v80ZM240-80q-33 0-56.5-23.5T160-160v-640q0-33 23.5-56.5T240-880h320l240 240v480q0 33-23.5 56.5T720-80H240Zm280-520v-200H240v640h480v-440H520ZM240-800v200-200 640-640Z',
    pcap: 'M240-40q-50 0-85-35t-35-85q0-50 35-85t85-35q14 0 26 3t23 8l57-71q-28-31-39-70t-5-78l-81-27q-17 25-43 40t-58 15q-50 0-85-35T0-580q0-50 35-85t85-35q50 0 85 35t35 85v8l81 28q20-36 53.5-61t75.5-32v-87q-39-11-64.5-42.5T360-840q0-50 35-85t85-35q50 0 85 35t35 85q0 42-26 73.5T510-724v87q42 7 75.5 32t53.5 61l81-28v-8q0-50 35-85t85-35q50 0 85 35t35 85q0 50-35 85t-85 35q-32 0-58.5-15T739-515l-81 27q6 39-5 77.5T614-340l57 70q11-5 23-7.5t26-2.5q50 0 85 35t35 85q0 50-35 85t-85 35q-50 0-85-35t-35-85q0-20 6.5-38.5T624-232l-57-71q-41 23-87.5 23T392-303l-56 71q11 15 17.5 33.5T360-160q0 50-35 85t-85 35ZM120-540q17 0 28.5-11.5T160-580q0-17-11.5-28.5T120-620q-17 0-28.5 11.5T80-580q0 17 11.5 28.5T120-540Zm120 420q17 0 28.5-11.5T280-160q0-17-11.5-28.5T240-200q-17 0-28.5 11.5T200-160q0 17 11.5 28.5T240-120Zm240-680q17 0 28.5-11.5T520-840q0-17-11.5-28.5T480-880q-17 0-28.5 11.5T440-840q0 17 11.5 28.5T480-800Zm0 440q42 0 71-29t29-71q0-42-29-71t-71-29q-42 0-71 29t-29 71q0 42 29 71t71 29Zm240 240q17 0 28.5-11.5T760-160q0-17-11.5-28.5T720-200q-17 0-28.5 11.5T680-160q0 17 11.5 28.5T720-120Zm120-420q17 0 28.5-11.5T880-580q0-17-11.5-28.5T840-620q-17 0-28.5 11.5T800-580q0 17 11.5 28.5T840-540ZM480-840ZM120-580Zm360 120Zm360-120ZM240-160Zm480 0Z',
    registry: 'M600-120v-120H440v-400h-80v120H80v-320h280v120h240v-120h280v320H600v-120h-80v320h80v-120h280v320H600ZM160-760v160-160Zm520 400v160-160Zm0-400v160-160Zm0 160h120v-160H680v160Zm0 400h120v-160H680v160ZM160-600h120v-160H160v160Z',
    logs: 'M240-80q-50 0-85-35t-35-85v-120h120v-560l60 60 60-60 60 60 60-60 60 60 60-60 60 60 60-60v680q0 50-35 85t-85 35H240Zm480-80q17 0 28.5-11.5T760-200v-560H320v440h360v120q0 17 11.5 28.5T720-160ZM360-600v-80h240v80H360Zm0 120v-80h240v80H360Zm320-120q-17 0-28.5-11.5T640-640q0-17 11.5-28.5T680-680q17 0 28.5 11.5T720-640q0 17-11.5 28.5T680-600Zm0 120q-17 0-28.5-11.5T640-520q0-17 11.5-28.5T680-560q17 0 28.5 11.5T720-520q0 17-11.5 28.5T680-480ZM240-160h360v-80H200v40q0 17 11.5 28.5T240-160Zm-40 0v-80 80Z',
    decode: 'M320-240 80-480l240-240 57 57-184 184 183 183-56 56Zm320 0-57-57 184-184-183-183 56-56 240 240-240 240Z',
    rag: 'M80-200v-80h400v80H80Zm0-200v-80h200v80H80Zm0-200v-80h200v80H80Zm744 400L670-354q-24 17-52.5 25.5T560-320q-83 0-141.5-58.5T360-520q0-83 58.5-141.5T560-720q83 0 141.5 58.5T760-520q0 29-8.5 57.5T726-410l154 154-56 56ZM560-400q50 0 85-35t35-85q0-50-35-85t-85-35q-50 0-85 35t-35 85q0 50 35 85t85 35Z',
    report: 'M640-160v-280h160v280H640Zm-240 0v-640h160v640H400Zm-240 0v-440h160v440H160Z',
    settings: 'm370-80-16-128q-13-5-24.5-12T307-235l-119 50L78-375l103-78q-1-7-1-13.5v-27q0-6.5 1-13.5L78-585l110-190 119 50q11-8 23-15t24-12l16-128h220l16 128q13 5 24.5 12t22.5 15l119-50 110 190-103 78q1 7 1 13.5v27q0 6.5-2 13.5l103 78-110 190-118-50q-11 8-23 15t-24 12L590-80H370Zm70-80h79l14-106q31-8 57.5-23.5T639-327l99 41 39-68-86-65q5-14 7-29.5t2-31.5q0-16-2-31.5t-7-29.5l86-65-39-68-99 42q-22-23-48.5-38.5T533-694l-13-106h-79l-14 106q-31 8-57.5 23.5T321-633l-99-41-39 68 86 64q-5 15-7 30t-2 32q0 16 2 31t7 30l-86 65 39 68 99-42q22 23 48.5 38.5T427-266l13 106Zm42-180q58 0 99-41t41-99q0-58-41-99t-99-41q-59 0-99.5 41T342-480q0 58 40.5 99t99.5 41Zm-2-140Z',
    help: 'M478-240q21 0 35.5-14.5T528-290q0-21-14.5-35.5T478-340q-21 0-35.5 14.5T428-290q0 21 14.5 35.5T478-240Zm-36-154h74q0-33 7.5-52t42.5-52q26-26 41-49.5t15-56.5q0-56-41-86t-97-30q-57 0-92.5 30T342-618l66 26q5-18 22.5-39t53.5-21q32 0 48 17.5t16 38.5q0 20-12 37.5T506-526q-44 39-54 59t-10 73Zm38 314q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 0-227 93t-93 227q0 134 93 227t227 93Zm0-320Z',
    check: 'm424-296 282-282-56-56-226 226-114-114-56 56 170 170Zm56 216q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 0-227 93t-93 227q0 134 93 227t227 93Zm0-320Z',
    cross: 'm336-280 144-144 144 144 56-56-144-144 144-144-56-56-144 144-144-144-56 56 144 144-144 144 56 56ZM480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 0-227 93t-93 227q0 134 93 227t227 93Zm0-320Z',
    refresh: 'M480-160q-134 0-227-93t-93-227q0-134 93-227t227-93q69 0 132 28.5T720-690v-110h80v280H520v-80h168q-32-56-87.5-88T480-720q-100 0-170 70t-70 170q0 100 70 170t170 70q77 0 139-44t87-116h84q-28 106-114 173t-196 67Z',
    menu: 'M120-240v-80h720v80H120Zm0-200v-80h720v80H120Zm0-200v-80h720v80H120Z',
    hayabusa: 'M824-120 636-308q-41 32-90.5 50T440-240q-90 0-162.5-44T163-400h98q34 37 79.5 58.5T440-320q100 0 170-70t70-170q0-100-70-170t-170-70q-94 0-162.5 63.5T201-580h-80q8-127 99.5-213.5T440-880q134 0 227 93t93 227q0 56-18 105.5T692-364l188 188-56 56ZM397-400l-63-208-52 148H80v-60h160l66-190h60l61 204 43-134h60l60 120h30v60h-67l-47-94-50 154h-59Z',
    thor: 'M480-80q-139-35-229.5-159.5T160-516v-244l320-120 320 120v244q0 152-90.5 276.5T480-80Zm0-84q104-33 172-132t68-220v-189l-240-90-240 90v189q0 121 68 220t172 132Zm0-316Z',
    cases: 'M160-160q-33 0-56.5-23.5T80-240v-480q0-33 23.5-56.5T160-800h240l80 80h320q33 0 56.5 23.5T880-640v400q0 33-23.5 56.5T800-160H160Zm0-80h640v-400H447l-80-80H160v480Zm0 0v-480 480Z',
};

function svgIcon(name, size = 18) {
    const d = ICON_PATHS[name] || '';
    return `<svg class="svg-ic" width="${size}" height="${size}" viewBox="0 -960 960 960" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
}

function svgBarChart(rows, labelKey, valueKey, maxBars){
  if(maxBars===undefined) maxBars=10;
  rows=(rows||[]).filter(r=>r[valueKey]).slice(0,maxBars);
  if(!rows.length) return '';
  const maxv=Math.max(...rows.map(r=>r[valueKey]))||1;
  const bar_h=18,gap=9,label_w=240,val_w=52,width=760;
  const plot_w=width-label_w-val_w;
  const height=rows.length*(bar_h+gap)+gap;
  const p=[`<svg viewBox="0 0 ${width} ${height}" width="100%" role="img">`];
  let y=gap;
  rows.forEach(r=>{
      const v=r[valueKey];
      const w=Math.max(3,plot_w*v/maxv);
      const rawLbl=String(r[labelKey]);
      const isTechnique=/^T\d+(\.\d+)?$/.test(rawLbl);
      let displayLbl;
      let url='';
      if(isTechnique && techniqueName(rawLbl)){
        displayLbl=esc(rawLbl+' — '+techniqueName(rawLbl));
        const dot=rawLbl.indexOf('.');
        url=dot!==-1 ? 'https://attack.mitre.org/techniques/'+rawLbl.slice(0,dot)+'/'+rawLbl.slice(dot+1)+'/'
                     : 'https://attack.mitre.org/techniques/'+rawLbl+'/';
      } else {
        displayLbl=esc(rawLbl);
      }
      if(displayLbl.length>40) displayLbl=displayLbl.slice(0,39)+'…';
      const cy=y+bar_h*0.72;
      if(url){
        p.push(`<a href="${url}" target="_blank"><text x="${label_w-8}" y="${cy}" fill="#8b93a3" font-size="11" font-family="ui-monospace,monospace" text-anchor="end">${displayLbl}</text></a>`);
      } else {
        p.push(`<text x="${label_w-8}" y="${cy}" fill="#8b93a3" font-size="11" font-family="ui-monospace,monospace" text-anchor="end">${displayLbl}</text>`);
      }
      p.push(`<rect x="${label_w}" y="${y}" width="${w}" height="${bar_h}" rx="4" fill="#4f8cff"/>`);
      p.push(`<text x="${label_w+w+6}" y="${cy}" fill="#e6e9f0" font-size="11" font-weight="600" font-family="ui-monospace,monospace">${esc(v)}</text>`);
    y+=bar_h+gap;
  });
  p.push('</svg>');
  return p.join('');
}

function summarizeRecord(rec) {
  // Create a short summary of a record for IoC results display
  const parts = [];
  if (rec['source.ip']) parts.push(rec['source.ip']);
  if (rec['destination.ip']) parts.push('-> ' + rec['destination.ip']);
  if (rec['destination.port']) parts.push(':' + rec['destination.port']);
  if (rec['process.name']) parts.push(rec['process.name']);
  if (rec['dns.question.name']) parts.push(rec['dns.question.name']);
  if (rec['registry.key']) parts.push(rec['registry.key']);
  if (rec['RuleTitle']) parts.push(rec['RuleTitle']);
  return parts.join(' ') || JSON.stringify(rec).slice(0, 80);
}

// Case-insensitive substring match across every field of a record (JSON.stringify + lowercase,
// same crude-but-schema-free approach the old inline loop used) — a miss here would be silent,
// so this is the part of the IoC search worth unit-testing on its own.
function matchIocs(records, iocs) {
  const matches = {};
  for (const ioc of (iocs || [])) {
    const needle = String(ioc).toLowerCase();
    const found = [];
    for (const rec of (records || [])) {
      const recStr = JSON.stringify(rec).toLowerCase();
      if (recStr.includes(needle)) {
        found.push({
          source: rec['event.source'] || rec['_source'] || 'unknown',
          timestamp: rec['@timestamp'] || '',
          summary: summarizeRecord(rec)
        });
      }
    }
    matches[ioc] = found;
  }
  return matches;
}

// What the IoC search actually covers. The analysis carries at most RECORDS_CAP raw records
// (analytics/runner.py) while the SQL analytics run over everything, so on a large dataset the
// browser searches a prefix. Saying nothing would turn "not found" into a false negative the
// analyst cannot distinguish from a real absence — so this returns the sentence, or '' when the
// corpus is complete and there is nothing to warn about.
function iocScopeText(shown, total) {
  const s = Number(shown) || 0, t = Number(total) || 0;
  if (t <= s) return '';
  const n = (v) => v.toLocaleString('en-US');
  return `Searching the first ${n(s)} of ${n(t)} events. "Not found" here is not proof of absence — `
       + `use the CLI (run_analytics), which queries the full dataset.`;
}

// "why" badge color: technique hits, THOR findings and high-signal event types read as findings
// (bad), Sigma hits and failed actions as warnings, plain context as a neutral pill — the pill
// communicates the selection reason, not a computed severity (the timeline never asserts one,
// see view-desc).
const _tlWhyClass = (why) => (why === 'ATT&CK technique' || why === 'THOR finding' || why === 'high-signal event type') ? 'pill bad'
  : (why === 'failed action' || String(why || '').startsWith('Sigma')) ? 'pill warn' : 'pill';

// Timeline filter predicate: source/why are exact matches, q is a case-insensitive substring
// match over the fields an analyst would actually search by. The highest-value extraction here
// — a wrong filter silently hides events an analyst is looking for, so it is unit-tested
// directly rather than only through the DOM-touching renderTimeline() that calls it.
function timelineFilter(rows, opts) {
  opts = opts || {};
  const q = String(opts.q || '').trim().toLowerCase();
  const source = opts.source || '';
  const why = opts.why || '';
  return (rows || []).filter(r => {
    if (source && r.source !== source) return false;
    if (why && r.why !== why) return false;
    if (!q) return true;
    const hay = [r.host, r.user_name, r.src_ip, r.dst_ip, r.process_name, r.cmdline,
                 r.dns_query, r.url, r.file_name, r.rule_title, r.techniques]
      .filter(Boolean).join(' ').toLowerCase();
    return hay.includes(q);
  });
}

// ─── Bundle import (client-side: the file never leaves the browser) ───
// Mirror of engine/bundle.py loads(): same version check, same tolerance for a bare
// analyze() export (report --format json --level full), so neither export is a dead end.
function bundleAnalysis(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not a bundle: top level is not an object');
  if (data.bundle_version === undefined) {
    if (data.summary) return data;   // bare analysis export
    throw new Error('not a bundle and not an analysis export (no bundle_version, no summary)');
  }
  if (data.bundle_version !== 1) throw new Error(`unsupported bundle_version ${data.bundle_version} (this build reads 1)`);
  if (!data.analysis || typeof data.analysis !== 'object') throw new Error("malformed bundle: 'analysis' missing");
  const a = data.analysis;
  if (!a._meta && data.meta) a._meta = data.meta;
  return a;
}

// THOR severity → color, used by both the dashboard THOR card and the THOR view's table.
const _thorSevColor = (s) => ({high:'var(--bad)', medium:'var(--warn)', low:'var(--muted)'}[s] || 'var(--muted)');

// HTTP status → color, used by the Zeek HTTP table (previously redefined identically in both the
// PCAP and Logs result renderers, with the same 2xx/3xx/other split each time).
const zeekStatusColor = (status) => {
  const s = String(status || '');
  return s.startsWith('2') ? 'var(--accent)' : s.startsWith('3') ? 'var(--warn)' : 'var(--bad)';
};

// Normalizes the (value, label) pairs behind a summary stat-tile grid (EVTX/PCAP/Logs results,
// previously three verbatim copies of the same `st(n,l)` closure in index.html): coalesces a
// missing/undefined count to 0 and stringifies it, so a summary field absent from one source's
// response renders "0" rather than "undefined" — the one thing that can silently go wrong here,
// so it is the part worth testing without a DOM. The DOM-building half (index.html's statsGrid())
// just maps this over `el()`.
function statTiles(pairs) {
  return (pairs || []).map(([n, l]) => ({ n: String(n ?? 0), l }));
}

// ─── Which uploads still have to be sent ─────────────────────────────────────
// Every Analyze click used to re-send every file the session had accumulated, and the case store's
// duplicate check hashes the WHOLE batch: EVTX alone, then EVTX+PCAP, are two different batches, so
// the second click appended the EVTX records to the case a second time. Every additive number —
// record counts, beaconing connections, episode sizes — then read high, with nothing on screen
// saying it had happened. The list itself has to stay (the file counts and the Hayabusa toolbox
// read it), so what changes is what gets *sent*: a file is offered once per case.
//
// The identity is the browser's own (name, size, mtime): the page cannot hash contents without
// reading every file back on each click, and two files agreeing on all three are the same upload
// for this purpose. Worst case is a re-picked identical file being skipped — which is exactly the
// intent — never a distinct file being dropped.
function fileKey(f) {
  return [f.name, f.size, f.lastModified].join('\u0000');
}

function pendingFiles(files, ingested) {
  if (!ingested || !ingested.size) return (files || []).slice();
  return (files || []).filter(f => !ingested.has(fileKey(f)));
}

// ─── What a missing tool costs, per source view ──────────────────────────────
// /api/health has always known which wrapped tools are present, and only the Settings view ever
// read it: the uploader let you tick "Full stream (EvtxECmd)" with no EvtxECmd installed, and a
// PCAP with no tshark produced a grid of zeros. The last column of the README's tool table is the
// one that matters to an analyst — what is LOST — so it is what these say, and it is written once
// here rather than in five views.
const TOOL_NOTICES = {
  evtx: [
    { key: 'hayabusa', tool: 'Hayabusa', required: true,
      lost: 'no EVTX can be analysed: detection, the Sigma/ATT&CK mapping and the whole toolbox need it' },
    { key: 'evtxecmd', tool: 'EvtxECmd (needs dotnet)', required: false,
      lost: 'the "Full stream" option is unavailable — detections only, without the long tail of undetected events' },
  ],
  pcap: [
    { key: 'tshark', tool: 'tshark', required: true, lost: 'no capture can be read at all' },
    { key: 'zeek', tool: 'Zeek', required: false,
      lost: 'no application layer — HTTP, TLS/JA3, DNS answers and Zeek notices. Flows and DNS questions still come from tshark' },
  ],
  registry: [
    { key: 'recmd', tool: 'RECmd (needs dotnet)', required: false,
      lost: 'binary hives (SAM/SYSTEM/SOFTWARE/NTUSER.DAT) cannot be parsed; native .reg exports still work' },
  ],
};

function toolNotices(view, health) {
  if (!health) return [];                    // not asked yet: say nothing rather than guess
  return (TOOL_NOTICES[view] || []).filter(n => health[n.key] === false);
}

if (typeof module !== 'undefined' && module.exports) module.exports = {
  esc,
  TECHNIQUE_MAP,
  techniqueName,
  techniqueLabel,
  ICON_PATHS,
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
  fileKey,
  pendingFiles,
  TOOL_NOTICES,
  toolNotices,
};
