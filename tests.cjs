// Static regression suite: node tests.cjs (no dependencies).
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const LAB = require('./data.js');
const { validateEnvelope, missingFields, grade, traceStep, VERSION, MIN_TEXT, UNGRADED } = require('./app.js');

let passed = 0;
const test = (name, fn) => {
  try { fn(); passed++; console.log('ok   ' + name); } catch (e) { console.log('FAIL ' + name + '\n     ' + e.message); process.exitCode = 1; }
};

const all = [...LAB.modules.flatMap((m) => m.exercises), ...LAB.queue];
const complete = (ex) => ({
  source: String(ex.source.answer), sink: String(ex.sink.answer), control: String(ex.control.answer), cls: ex.cls,
  rationale: 'x'.repeat(MIN_TEXT), impact: 'x'.repeat(MIN_TEXT), ticket: 'x'.repeat(MIN_TEXT), verification: 'x'.repeat(MIN_TEXT),
});
const env = (o) => JSON.stringify({ version: VERSION, view: '', drafts: {}, submitted: {}, fixes: {}, ...o });

test('four modules in the required order', () => assert.deepEqual(LAB.modules.map((m) => m.cwe), ['CWE-94', 'CWE-79', 'CWE-78', 'CWE-22']));

test('every module has a beginner block: short problem, dangerous-line and fix notes, tiny unsafe + fixed snippet, ordinary and harmful samples', () => {
  const sentences = (s) => (s.match(/[.!?](?=\s|$)/g) || []).length;
  for (const m of LAB.modules) {
    const b = m.basics;
    assert.ok(b && b.lesson.length <= 100, m.id + ' short lesson');
    for (const k of ['problem', 'line', 'works']) assert.ok(typeof b[k] === 'string' && b[k].length >= 40 && b[k].length <= 200 && sentences(b[k]) <= 2, m.id + ' ' + k + ' is 1-2 short sentences');
    assert.equal(b.why, undefined, m.id + ' old why paragraph removed');
    const lines = (c) => c.split('\n').length;
    assert.ok(lines(b.unsafe.code) >= 2 && lines(b.unsafe.code) <= 5, m.id + ' unsafe 2-5 lines');
    assert.ok(lines(b.fixed.code) >= 2 && lines(b.fixed.code) <= 6, m.id + ' fixed 2-6 lines');
    for (const k of ['unsafe', 'fixed']) assert.ok(b[k].hot >= 0 && b[k].hot < lines(b[k].code), m.id + ' ' + k + ' hot line');
    const kinds = b.samples.map((s) => s.kind);
    assert.ok(kinds.includes('Ordinary') && kinds.includes('Harmful'), m.id + ' sample kinds');
    for (const s of b.samples) {
      assert.ok(s.input, m.id + ' sample input');
      for (const k of ['unsafe', 'fixed']) assert.ok(s[k].op && s[k].out && ['ok', 'harm', 'blocked'].includes(s[k].effect), m.id + ' ' + s.input + ' ' + k);
      if (s.kind === 'Ordinary') assert.deepEqual([s.unsafe.effect, s.fixed.effect], ['ok', 'ok'], m.id + ' ordinary works both ways');
      else assert.deepEqual([s.unsafe.effect, s.fixed.effect], ['harm', 'blocked'], m.id + ' harmful: unsafe harms, fixed blocks');
    }
  }
  assert.ok(LAB.queue.every((q) => !q.basics), 'queue has no beginner block (would leak the family)');
});

test('beginner fixes address the toy weakness, not just rename it', () => {
  const fix = Object.fromEntries(LAB.modules.map((m) => [m.id, m.basics.fixed.code]));
  const bad = Object.fromEntries(LAB.modules.map((m) => [m.id, m.basics.unsafe.code]));
  assert.match(bad.m94, /eval\(/); assert.doesNotMatch(fix.m94, /eval|Function|vm\./); assert.match(fix.m94, /\/\^[^\n]*\$\/\.(exec|test)\(/); assert.match(fix.m94, /return res\.sendStatus\(400\)/);
  assert.match(bad.m79, /innerHTML/); assert.doesNotMatch(fix.m79, /innerHTML/); assert.match(fix.m79, /textContent/);
  assert.match(bad.m78, /exec\(/); assert.doesNotMatch(fix.m78, /exec\(|shell:/); assert.match(fix.m78, /execFile\(/); assert.match(fix.m78, /\.has\(host\)/);
  assert.match(bad.m22, /path\.join\([^)]*req\./); assert.doesNotMatch(fix.m22, /path\.join\([^)]*req\.|startsWith/); assert.match(fix.m22, /new Map[\s\S]*\.get\(req\./);
});

test('traceStep reveals input, operation, result one step at a time and nothing stale', () => {
  const s = LAB.modules[0].basics.samples[1];
  assert.deepEqual(traceStep(s, 'unsafe', 0), [null, null, null]);
  assert.deepEqual(traceStep(s, 'unsafe', 1), [s.input, null, null]);
  assert.deepEqual(traceStep(s, 'fixed', 2), [s.input, s.fixed.op, null]);
  assert.deepEqual(traceStep(s, 'fixed', 3), [s.input, s.fixed.op, s.fixed.out]);
  assert.deepEqual(traceStep(s, 'fixed', 9), traceStep(s, 'fixed', 3), 'clamped');
});

test('exercise ids unique', () => assert.equal(new Set(all.map((e) => e.id)).size, all.length));

test('every exercise is well formed', () => {
  for (const ex of all) {
    for (const k of ['title', 'scenario', 'lang', 'code', 'cwe']) assert.ok(typeof ex[k] === 'string' && ex[k], ex.id + ' ' + k);
    for (const k of ['rule', 'severity', 'location', 'message']) assert.ok(ex.alert[k], ex.id + ' alert.' + k);
    for (const k of ['source', 'sink', 'control']) assert.ok(ex[k].answer >= 0 && ex[k].answer < ex[k].options.length, ex.id + ' ' + k);
    assert.ok(['confirmed', 'false-positive', 'needs-evidence'].includes(ex.cls), ex.id + ' cls');
    assert.ok(ex.worked.length && ex.model.impact && ex.model.ticket && ex.model.verification, ex.id + ' answer');
  }
});

test('every module exercise has a remediation drill with ordinary + exploit fixtures and a mix of verdicts', () => {
  for (const ex of LAB.modules.flatMap((m) => m.exercises)) {
    const kinds = ex.fix.regressions.map((r) => r.kind);
    assert.ok(kinds.includes('Ordinary') && kinds.includes('Exploit'), ex.id);
    for (const o of ex.fix.options) assert.equal(o.results.length, ex.fix.regressions.length, ex.id + ' ' + o.label);
    assert.ok(ex.fix.options.some((o) => o.results.every((r) => r.pass)), ex.id + ' has a full-pass fix');
    assert.ok(ex.fix.options.some((o) => o.results.some((r) => !r.pass)), ex.id + ' has a failing fix');
  }
});

test('CWE-79 covers reflected, stored and DOM; CWE-78 covers argument injection without a shell', () => {
  const m79 = LAB.modules[1].exercises.map((e) => e.cwe).join(' ');
  for (const t of ['reflected', 'stored', 'DOM']) assert.match(m79, new RegExp(t));
  assert.ok(LAB.modules[2].exercises.some((e) => /CWE-88/.test(e.cwe) && !/exec\(/.test(e.code)));
});

test('queue: >=4 cases, a false positive, a needs-evidence, and each family', () => {
  assert.ok(LAB.queue.length >= 4);
  assert.ok(LAB.queue.some((q) => q.cls === 'false-positive'));
  assert.ok(LAB.queue.some((q) => q.cls === 'needs-evidence'));
  for (const c of ['94', '79', '78', '22']) assert.ok(LAB.queue.some((q) => q.cwe.includes('CWE-' + c)), c);
});

test('queue pre-submission text never names a CWE id or family label', () => {
  const leak = /CWE-?\d|injection|cross-site|xss|traversal|eval injection/i;
  for (const q of LAB.queue) {
    const visible = [q.title, q.scenario, q.lang, q.code, ...Object.values(q.alert), ...['source', 'sink', 'control'].flatMap((k) => q[k].options)];
    for (const t of visible) assert.doesNotMatch(t, leak, q.id + ': ' + t);
  }
});

test('correct trace answers are spread across option positions', () => {
  const answers = all.flatMap((ex) => ['source', 'sink', 'control'].map((k) => ex[k].answer));
  const counts = [0, 1, 2, 3].map((i) => answers.filter((a) => a === i).length);
  assert.ok(counts.every((c) => c > 0), 'every position holds some answers: ' + counts);
  assert.ok(Math.max(...counts) <= answers.length / 2, 'one position holds most answers: ' + counts);
  for (const k of ['source', 'sink', 'control']) assert.ok(new Set(all.map((ex) => ex[k].answer)).size >= 3, k + ' answers vary');
});

test('option length is no answer cue: no length rank, longest or shortest guess wins most trace questions', () => {
  const qs = all.flatMap((ex) => ['source', 'sink', 'control'].map((k) => ex[k]));
  const len = (q) => [q.options[q.answer].length, q.options.filter((o, i) => i !== q.answer).map((o) => o.length)];
  const longer = qs.map((q) => { const [c, rest] = len(q); return rest.filter((l) => l > c).length; });
  const shortest = qs.filter((q) => { const [c, rest] = len(q); return rest.every((l) => l >= c); }).length;
  const ranks = [0, 1, 2, 3].map((r) => longer.filter((x) => x === r).length);
  assert.ok(Math.max(...ranks) <= qs.length / 2, 'correct option by length rank (0 = longest): ' + ranks);
  assert.ok(shortest <= qs.length / 2, 'correct option is shortest in ' + shortest + ' of ' + qs.length);
});

test('queue: correct trace options state evidence, not the classification', () => {
  // Scenario/code may carry the deciding evidence; only the correct option wording is checked.
  const giveaway = /\b(unknown|none missing|never user-supplied|false positive|needs? (more )?evidence|not exploitable|origin not shown)\b/i;
  for (const q of LAB.queue) for (const k of ['source', 'sink', 'control']) assert.doesNotMatch(q[k].options[q[k].answer], giveaway, q.id + ' ' + k);
});

test('CWE-79 reflected: ordinary text a sanitizer really changes; encoder keeps it exactly', () => {
  const ex = all.find((e) => e.id === 'm79-reflected');
  const i = ex.fix.regressions.findIndex((r) => r.kind === 'Ordinary');
  const input = ex.fix.regressions[i].input;
  assert.match(input, /<[a-z][a-z0-9-]*>/i, 'needs an element-like token; "<3" is text to an HTML parser');
  const enc = ex.fix.options.find((o) => /escaping template/i.test(o.label));
  const san = ex.fix.options.find((o) => /sanitizer/i.test(o.label));
  assert.ok(enc.results[i].pass && enc.results[i].out.includes(input), 'encoder output');
  assert.ok(!san.results[i].pass && !san.results[i].out.includes(input), 'sanitizer output');
  assert.ok(ex.model.verification.includes(input) && ex.worked.join(' ').includes(input), 'worked/model use the same input');
  assert.doesNotMatch(JSON.stringify(ex), /<3/);
});

test('missingFields: empty draft lists all eight; complete draft lists none; short text rejected', () => {
  const ex = all[0];
  assert.equal(missingFields({}, ex).length, 8);
  assert.deepEqual(missingFields(complete(ex), ex), []);
  assert.equal(missingFields({ ...complete(ex), ticket: '  short  ' }, ex).length, 1);
  assert.equal(missingFields({ ...complete(ex), source: '99' }, ex).length, 1);
  assert.equal(missingFields({ ...complete(ex), cls: 'maybe' }, ex).length, 1);
});

test('grade marks correct and wrong answers', () => {
  const ex = LAB.queue.find((q) => q.cls === 'false-positive');
  assert.deepEqual(grade(complete(ex), ex), { source: true, sink: true, control: true, cls: true });
  const g = grade({ ...complete(ex), cls: 'confirmed', sink: String((ex.sink.answer + 1) % ex.sink.options.length) }, ex);
  assert.equal(g.cls, false);
  assert.equal(g.sink, false);
});

test('validateEnvelope accepts absent and valid data', () => {
  assert.ok(validateEnvelope(null, LAB).ok);
  const id = all[0].id;
  const r = validateEnvelope(env({ view: 'queue', drafts: { [id]: complete(all[0]) }, submitted: { [id]: true }, fixes: { [id]: 1 } }), LAB);
  assert.ok(r.ok, r.reason);
});

test('validateEnvelope rejects malformed, future, wrong-type and unsafe shapes', () => {
  const id = all[0].id;
  const bad = {
    json: '{not json',
    array: '[]',
    nullv: 'null',
    future: env({ version: VERSION + 1 }),
    oldv: env({ version: 0 }),
    strVersion: JSON.stringify({ version: '1', view: '', drafts: {}, submitted: {}, fixes: {} }),
    extraKey: env({ extra: 1 }),
    view: env({ view: 'admin' }),
    draftsArray: env({ drafts: [] }),
    nestedArray: env({ drafts: { [id]: [['source', '0']] } }),
    fieldType: env({ drafts: { [id]: { source: 0 } } }),
    unknownField: env({ drafts: { [id]: { notes: 'x' } } }),
    unknownId: env({ drafts: { nope: {} } }),
    proto: '{"version":1,"view":"","drafts":{"__proto__":{"source":"0"}},"submitted":{},"fixes":{}}',
    longText: env({ drafts: { [id]: { rationale: 'x'.repeat(5000) } } }),
    submittedType: env({ submitted: { [id]: 'yes' } }),
    submittedIncomplete: env({ drafts: { [id]: { source: '0' } }, submitted: { [id]: true } }),
    fixRange: env({ drafts: { [id]: complete(all[0]) }, submitted: { [id]: true }, fixes: { [id]: 99 } }),
    fixUnsubmitted: env({ fixes: { [id]: 0 } }),
    fixOnQueue: env({ drafts: { 'q-avatar': complete(LAB.queue[2]) }, submitted: { 'q-avatar': true }, fixes: { 'q-avatar': 0 } }),
  };
  for (const [name, raw] of Object.entries(bad)) assert.equal(validateEnvelope(raw, LAB).ok, false, name);
  assert.match(validateEnvelope(bad.future, LAB).reason, /newer/);
});

test('feedback and README disclose that written answers are not machine-graded', () => {
  assert.match(UNGRADED, /^Only the three trace choices and the classification are scored\. Compare your rationale, impact, ticket and verification with the model answer yourself\.$/);
  assert.match(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), /return h\('section', \{ class: 'feedback'[\s\S]*h\('p', \{ class: 'ungraded' \}, UNGRADED\)/);
  assert.ok(fs.readFileSync(path.join(__dirname, 'README.md'), 'utf8').includes(UNGRADED), 'README sentence matches');
});

test('fonts are local files with licenses; no external URLs in page sources', () => {
  const css = fs.readFileSync(path.join(__dirname, 'style.css'), 'utf8');
  for (const f of ['source-sans-3.ttf', 'ibm-plex-mono-regular.ttf', 'sourcesans3-OFL.txt', 'ibmplexmono-OFL.txt']) assert.ok(fs.existsSync(path.join(__dirname, 'fonts', f)), f);
  assert.deepEqual(css.match(/url\([^)]*\)/g), ['url(fonts/source-sans-3.ttf)', 'url(fonts/ibm-plex-mono-regular.ttf)'], 'only the two shipped faces are loaded');
  assert.match(css, /font-family: 'Source Sans 3'; font-style: normal; font-weight: 200 900;/);
  assert.match(css, /font-family: 'IBM Plex Mono'; font-style: normal; font-weight: 400;/);
  assert.match(css, /--mono: 'IBM Plex Mono', ui-monospace[^;]*monospace;/);
  assert.match(css, /--sans: 'Source Sans 3', system-ui[^;]*sans-serif;/);
  assert.doesNotMatch(css, /italic|oblique|Newsreader|JetBrains|--serif|font-weight:\s*bold/, 'no unshipped italic, bold keyword or old face');
  assert.match(css, /font-synthesis: none/);
  for (const f of ['style.css', 'index.html']) assert.doesNotMatch(fs.readFileSync(path.join(__dirname, f), 'utf8'), /https?:\/\/(?!cwe\.mitre|owasp)/, f);
});

test('calculator intro is the exact quick-tutorial copy', () => {
  assert.equal(LAB.modules[0].basics.problem, 'The calculator reads expr from the URL and passes it to eval(). Anyone who controls expr can make the server run JavaScript.');
});

test('"sink" is defined once (CWE-94 step 2); no repeated Input/Code/Sink glossary', () => {
  const app = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
  assert.doesNotMatch(app, /class: 'terms'|Text that comes from outside|The sink is|what the sink does/, 'old per-module definitions');
  const hits = [];
  const walk = (o, at) => { if (typeof o === 'string') { if (/\bsinks?\b/i.test(o)) hits.push(at); } else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) if (!['code', 'sink', 'rule'].includes(k)) walk(v, at + '.' + k); };
  walk(LAB, 'LAB');
  assert.deepEqual(hits, ['LAB.modules.0.basics.line'], 'learner prose using "sink"');
  assert.match(LAB.modules[0].basics.line, /sink, the operation that uses the input/);
});

// Baseline commit before the quick-copy pass. Read-only: `git show` output is evaluated in a sandbox, nothing is written.
const BASE_REV = '78a52056ce26c4ec3ec2097dec296196d7bfa659';
const baseLab = () => {
  const src = require('node:child_process').execFileSync('git', ['show', BASE_REV + ':data.js'], { cwd: __dirname, encoding: 'utf8' });
  const sandbox = { module: { exports: {} } };
  require('node:vm').runInNewContext(src, sandbox);
  return sandbox.module.exports;
};
const PROSE = ['intro', 'problem', 'why', 'line', 'works', 'lesson', 'scenario', 'message', 'worked', 'model'];
const strip = (o) => JSON.parse(JSON.stringify(o, (k, v) => (PROSE.includes(k) ? undefined : v)));
const words = (o, inProse = false) => {
  if (typeof o === 'string') return inProse ? o.split(/\s+/).filter(Boolean).length : 0;
  if (!o || typeof o !== 'object') return 0;
  return Object.entries(o).reduce((n, [k, v]) => n + words(v, inProse || PROSE.includes(k)), 0);
};

test('only learner prose changed since baseline: code, inputs, outcomes, ids, options, answers, classes, CWEs, fixes, links identical', () => {
  const base = baseLab();
  assert.deepEqual(strip(LAB), strip(base));
  assert.deepEqual(all.map((e) => e.id), [...base.modules.flatMap((m) => m.exercises), ...base.queue].map((e) => e.id), 'ids and case counts');
  // Saved progress from the baseline still validates.
  const id = 'm22-invoice';
  assert.ok(validateEnvelope(env({ view: 'm22', drafts: { [id]: complete(all.find((e) => e.id === id)) }, submitted: { [id]: true }, fixes: { [id]: 3 } }), LAB).ok);
});

test('prose is shorter in every module and the queue, per exercise too (word counts printed)', () => {
  const base = baseLab();
  const units = [...LAB.modules.map((m, i) => [m.id, base.modules[i], m]), ['queue', base.queue, LAB.queue]];
  let before = 0;
  let after = 0;
  for (const [name, b, a] of units) {
    const [wb, wa] = [words(b), words(a)];
    before += wb; after += wa;
    console.log(`     ${name}: ${wb} -> ${wa} words (${Math.round(100 - (100 * wa) / wb)}% shorter)`);
    assert.ok(wa <= wb * 0.8, name + ' prose cut by at least a fifth');
  }
  console.log(`     total learner prose in data.js: ${before} -> ${after} words`);
  const baseEx = new Map([...base.modules.flatMap((m) => m.exercises), ...base.queue].map((e) => [e.id, e]));
  for (const ex of all) {
    const pick = (e) => ({ worked: e.worked, model: e.model });
    assert.ok(words(pick(ex), true) < words(pick(baseEx.get(ex.id)), true), ex.id + ' feedback shortened');
  }
});

test('feedback leads with concrete evidence from the shown code and keeps the security nuance', () => {
  const by = Object.fromEntries(all.map((e) => [e.id, e]));
  for (const ex of all) {
    assert.match(ex.worked[0], /^Evidence:/, ex.id + ' evidence first');
    const tokens = ex.worked[0].match(/[\w.$]{4,}/g).filter((t) => /[._(]|[a-z][A-Z]/.test(t) || t.length >= 8);
    assert.ok(tokens.some((t) => ex.code.includes(t.replace(/[.,]$/, ''))), ex.id + ' evidence cites the code shown');
  }
  const text = (id) => [...by[id].worked, ...Object.values(by[id].model)].join(' ');
  assert.match(text('q-avatar'), /randomUUID[\s\S]*CHECK[\s\S]*no route/, 'false positive cites the control evidence');
  assert.match(text('q-thumbs'), /shell=True[\s\S]*media-ingest[\s\S]*cannot see/, 'needs-evidence names the dangerous call and the missing evidence');
  assert.match(text('q-columns'), /__builtins__/, 'eval with empty globals');
  assert.match(text('m94-promo'), /CWE-95[\s\S]*Function constructor[\s\S]*node:vm/);
  assert.match(text('m79-reflected'), /entity encoding[\s\S]*sanitizer is for rich HTML[\s\S]*URL, JavaScript or CSS/);
  assert.match(text('m79-stored'), /javascript: URL[\s\S]*http:\/https:[\s\S]*Style values[\s\S]*event-handler/);
  assert.match(text('m79-dom'), /server-side encoding never sees[\s\S]*textContent[\s\S]*first "<"[\s\S]*URL-encoding/);
  assert.match(text('m78-lookup'), /\/bin\/sh[\s\S]*dns\.promises\.lookup[\s\S]*-timeout=3600 as an option[\s\S]*CWE-88/);
  assert.match(text('m78-gitlog'), /no shell[\s\S]*"-" is an option[\s\S]*--end-of-options/);
  assert.match(text('q-uptime'), /avoids the shell[\s\S]*ProxyCommand[\s\S]*inventory/);
  assert.match(text('m22-invoice'), /absolute path replaces BASE[\s\S]*%252e[\s\S]*path\.relative, not a string prefix[\s\S]*invoices-archive[\s\S]*TOCTOU/);
});

test('app.js never uses HTML or code-evaluating sinks', () => {
  for (const f of ['app.js', 'index.html']) {
    const src = fs.readFileSync(path.join(__dirname, f), 'utf8');
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setTimeout\(\s*['"`]|child_process|require\(['"]node:fs/, f);
  }
});

console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`);
