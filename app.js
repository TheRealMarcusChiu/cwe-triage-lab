// CWE Triage Lab UI. Learner text and fixture strings only ever reach the DOM through text nodes / value / textContent.
(function () {
  'use strict';

  const KEY = 'cwe-triage-lab:v1';
  const VERSION = 1;
  const CHOICES = [['source', 'Untrusted source'], ['sink', 'Dangerous operation'], ['control', 'Missing control']];
  const TEXTS = [
    ['rationale', 'Rationale for the classification'],
    ['impact', 'Impact if exploited (or why there is none)'],
    ['ticket', 'Remediation ticket: concrete change'],
    ['verification', 'Verification criteria'],
  ];
  const CLASSES = [['confirmed', 'Confirmed vulnerability'], ['false-positive', 'False positive'], ['needs-evidence', 'Needs more evidence']];
  const FIELDS = [...CHOICES.map((c) => c[0]), 'cls', ...TEXTS.map((t) => t[0])];
  const MIN_TEXT = 12;
  const MAX_TEXT = 4000;
  const UNGRADED = 'Your rationale, impact, ticket and verification are not machine-graded: compare your own text with the worked answer. Only the three trace choices and the classification are scored.';

  const allExercises = (lab) => [...lab.modules.flatMap((m) => m.exercises), ...lab.queue];
  const emptyState = () => ({ version: VERSION, view: '', drafts: {}, submitted: {}, fixes: {} });
  const isPlain = (o) => o !== null && typeof o === 'object' && !Array.isArray(o) && Object.getPrototypeOf(o) === Object.prototype;

  // Missing required fields for an exercise draft, as human labels.
  function missingFields(draft, ex) {
    const d = draft || {};
    const missing = [];
    for (const [k, label] of CHOICES) {
      const i = Number(d[k]);
      if (d[k] === undefined || d[k] === '' || !Number.isInteger(i) || i < 0 || i >= ex[k].options.length) missing.push(label);
    }
    if (!CLASSES.some((c) => c[0] === d.cls)) missing.push('Classification');
    for (const [k, label] of TEXTS) if (typeof d[k] !== 'string' || d[k].trim().length < MIN_TEXT) missing.push(label);
    return missing;
  }

  function grade(draft, ex) {
    const out = {};
    for (const [k] of CHOICES) out[k] = Number(draft[k]) === ex[k].answer;
    out.cls = draft.cls === ex.cls;
    return out;
  }

  // Parse and structurally validate a stored envelope. Returns {ok, state} or {ok:false, reason}.
  function validateEnvelope(raw, lab) {
    if (raw === null || raw === undefined) return { ok: true, state: emptyState() };
    let d;
    try { d = JSON.parse(raw); } catch { return { ok: false, reason: 'not valid JSON' }; }
    if (!isPlain(d)) return { ok: false, reason: 'not an object' };
    if (typeof d.version !== 'number') return { ok: false, reason: 'missing version' };
    if (d.version > VERSION) return { ok: false, reason: 'saved by a newer version of the lab' };
    if (d.version !== VERSION) return { ok: false, reason: 'unknown version' };
    const allowed = ['version', 'view', 'drafts', 'submitted', 'fixes'];
    if (Object.keys(d).some((k) => !allowed.includes(k))) return { ok: false, reason: 'unexpected top-level field' };
    const byId = new Map(allExercises(lab).map((e) => [e.id, e]));
    const views = ['', 'queue', ...lab.modules.map((m) => m.id)];
    if (!views.includes(d.view)) return { ok: false, reason: 'invalid view' };
    for (const part of ['drafts', 'submitted', 'fixes']) {
      if (!isPlain(d[part])) return { ok: false, reason: part + ' is not an object' };
      for (const id of Object.keys(d[part])) if (!byId.has(id)) return { ok: false, reason: 'unknown exercise in ' + part };
    }
    for (const draft of Object.values(d.drafts)) {
      if (!isPlain(draft)) return { ok: false, reason: 'draft is not an object' };
      for (const [k, v] of Object.entries(draft)) {
        if (!FIELDS.includes(k) || typeof v !== 'string' || v.length > MAX_TEXT) return { ok: false, reason: 'invalid draft field' };
      }
    }
    for (const [id, v] of Object.entries(d.submitted)) {
      if (v !== true) return { ok: false, reason: 'invalid submitted flag' };
      if (missingFields(d.drafts[id], byId.get(id)).length) return { ok: false, reason: 'submitted exercise is incomplete' };
    }
    for (const [id, v] of Object.entries(d.fixes)) {
      const ex = byId.get(id);
      if (!ex.fix || !Number.isInteger(v) || v < 0 || v >= ex.fix.options.length || !d.submitted[id]) return { ok: false, reason: 'invalid fix choice' };
    }
    return { ok: true, state: d };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { validateEnvelope, missingFields, grade, KEY, VERSION, FIELDS, MIN_TEXT, UNGRADED };
    return;
  }

  // ---------- browser ----------
  const LAB = window.LAB;
  const warnEl = document.getElementById('storage-warning');
  const main = document.getElementById('main');
  let store = null;
  let blocked = false; // unreadable data present: never overwrite it
  let state = emptyState();

  function warn(msg) {
    warnEl.textContent = msg;
    warnEl.hidden = false;
  }

  function load() {
    let raw;
    try {
      store = window.localStorage;
      raw = store.getItem(KEY);
    } catch (e) {
      store = null;
      warn('Browser storage is unavailable (' + e.name + '). Your work is kept in this tab only and will be lost on reload.');
      return;
    }
    const r = validateEnvelope(raw, LAB);
    if (r.ok) { state = r.state; return; }
    blocked = true;
    warn('Saved progress could not be read (' + r.reason + '). It was left untouched and will not be overwritten. Work in this tab is not saved; use "Reset saved progress" to discard the stored copy.');
  }

  function save() {
    if (!store || blocked) return;
    try {
      store.setItem(KEY, JSON.stringify(state));
    } catch (e) {
      warn('Could not save progress (' + e.name + '). Your work is kept in this tab only.');
    }
  }

  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.className = v;
      else if (k.startsWith('aria-') || k === 'role' || k === 'for' || k === 'tabindex') el.setAttribute(k, String(v));
      else el[k] = v;
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    return el;
  }

  // Same generic strategy for every exercise: it must never name a classification, weakness or answer.
  const TRACE_HINT = () => h('details', { class: 'hint' },
    h('summary', {}, 'Trace hint'),
    h('p', {}, 'Follow the data in three steps: where outside input enters, what transforms or checks it on the way, and the operation that would be dangerous if that input reached it.'),
    h('p', {}, 'Then separate what the code shown proves from what it does not show. A control you cannot see here is missing evidence to ask for, not proof either way.'));

  const codeBlock = (label, text) => h('pre', { class: 'code', tabindex: 0, 'aria-label': label }, h('code', {}, text));

  function draftOf(id) {
    if (!isPlain(state.drafts[id])) state.drafts[id] = {};
    return state.drafts[id];
  }

  function renderExercise(ex) {
    const done = !!state.submitted[ex.id];
    const d = draftOf(ex.id);
    const fid = (k) => ex.id + '-' + k;
    const onInput = (k) => (e) => {
      d[k] = e.target.value;
      e.target.removeAttribute('aria-invalid');
      e.target.closest('fieldset')?.removeAttribute('aria-invalid'); // radios: invalid state lives on the fieldset
      save();
    };

    const alert = h('div', { class: 'alert', role: 'group', 'aria-label': 'Scanner alert' },
      h('p', { class: 'alert-head' }, h('span', { class: 'sev' }, ex.alert.severity), ' ', h('code', {}, ex.alert.rule)),
      h('p', {}, ex.alert.message),
      h('p', { class: 'loc' }, ex.alert.location));

    const choiceFields = CHOICES.map(([k, label]) => h('div', { class: 'field' },
      h('label', { for: fid(k) }, label),
      h('select', { id: fid(k), disabled: done, onchange: onInput(k) },
        h('option', { value: '' }, 'Choose…'),
        ex[k].options.map((o, i) => h('option', { value: String(i), selected: d[k] === String(i) }, o)))));

    const clsField = h('fieldset', { class: 'field', id: fid('cls') },
      h('legend', {}, 'Classification'),
      CLASSES.map(([v, label]) => h('label', { class: 'radio' },
        h('input', { type: 'radio', name: fid('cls'), value: v, checked: d.cls === v, disabled: done, onchange: onInput('cls') }), ' ', label)));

    const textFields = TEXTS.map(([k, label]) => h('div', { class: 'field' },
      h('label', { for: fid(k) }, label),
      h('textarea', { id: fid(k), rows: 2, maxLength: MAX_TEXT, readOnly: done, value: d[k] || '', oninput: onInput(k) })));

    const errors = h('p', { class: 'errors', id: fid('errors'), role: 'alert' });
    const form = h('form', { class: 'decision', noValidate: true, 'aria-label': 'Triage decision', onsubmit: (e) => {
      e.preventDefault();
      const missing = missingFields(d, ex);
      if (missing.length) {
        errors.textContent = 'Complete every field before feedback is shown. Missing: ' + missing.join(', ') + '. Text answers need at least ' + MIN_TEXT + ' characters.';
        const labels = Object.fromEntries([...CHOICES, ...TEXTS, ['cls', 'Classification']].map(([k, l]) => [l, k]));
        for (const l of missing) document.getElementById(fid(labels[l])).setAttribute('aria-invalid', 'true');
        const first = document.getElementById(fid(labels[missing[0]]));
        (first.matches('fieldset') ? first.querySelector('input') : first).focus();
        return;
      }
      state.submitted[ex.id] = true;
      save();
      render(); // full render so the submitted counter updates
      document.getElementById(fid('feedback-h')).focus();
    } },
    choiceFields, clsField, textFields, errors,
    done ? h('p', { class: 'locked' }, 'Submitted. Answers are locked so feedback stays matched to them.') : h('button', { type: 'submit' }, 'Submit triage'));

    return h('section', { class: 'exercise', id: ex.id, 'aria-labelledby': fid('h') },
      h('h3', { id: fid('h') }, ex.title),
      h('div', { class: 'split' },
        h('div', { class: 'evidence' }, alert, h('p', { class: 'scenario' }, ex.scenario),
          h('p', { class: 'lang' }, ex.lang), codeBlock('Flagged code', ex.code), done ? null : TRACE_HINT()),
        form),
      done ? renderFeedback(ex, d) : null);
  }

  function renderFeedback(ex, d) {
    const g = grade(d, ex);
    const fid = (k) => ex.id + '-' + k;
    const clsLabel = (v) => CLASSES.find((c) => c[0] === v)[1];
    const row = (label, ok, expected) => h('li', { class: ok ? 'ok' : 'bad' }, ok ? '✓ ' + label + ': matches' : '✗ ' + label + ': expected — ' + expected);
    return h('section', { class: 'feedback', 'aria-labelledby': fid('feedback-h') },
      h('h4', { id: fid('feedback-h'), tabindex: -1 }, 'Feedback and worked answer'),
      h('ul', { class: 'marks' },
        CHOICES.map(([k, label]) => row(label, g[k], ex[k].options[ex[k].answer])),
        row('Classification', g.cls, clsLabel(ex.cls))),
      h('p', { class: 'ungraded' }, UNGRADED),
      h('p', { class: 'mapped' }, 'Mapped weakness: ', h('strong', {}, ex.cwe)),
      h('h5', {}, 'Reasoning'),
      ex.worked.map((p) => h('p', {}, p)),
      h('h5', {}, 'Model answer'),
      h('dl', { class: 'model' },
        h('dt', {}, 'Impact'), h('dd', {}, ex.model.impact),
        h('dt', {}, 'Ticket'), h('dd', {}, ex.model.ticket),
        h('dt', {}, 'Verification'), h('dd', {}, ex.model.verification)),
      ex.fix ? renderFix(ex) : null);
  }

  function renderFix(ex) {
    const fid = (k) => ex.id + '-' + k;
    const chosen = Number.isInteger(state.fixes[ex.id]) ? state.fixes[ex.id] : null;
    const opt = chosen === null ? null : ex.fix.options[chosen];
    const fails = opt ? opt.results.filter((r) => !r.pass).length : 0;
    return h('div', { class: 'fix' },
      h('h5', {}, 'Remediation drill'),
      h('fieldset', { class: 'field' },
        h('legend', {}, 'Choose a fix to test'),
        ex.fix.options.map((o, i) => h('label', { class: 'radio' },
          h('input', { type: 'radio', name: fid('fix'), id: fid('fix-' + i), value: String(i), checked: chosen === i, onchange: () => {
            state.fixes[ex.id] = i;
            save();
            rerender(ex, fid('fix-' + i));
          } }), ' ', o.label))),
      h('div', { class: 'side' },
        h('figure', {}, h('figcaption', {}, 'Vulnerable'), codeBlock('Vulnerable code', ex.code)),
        h('figure', {}, h('figcaption', {}, 'Candidate fix'), opt ? codeBlock('Candidate fix code', opt.code) : h('p', { class: 'muted' }, 'Choose a fix to compare.'))),
      opt ? h('div', { class: 'table-wrap', tabindex: 0, role: 'region', 'aria-label': 'Regression results' }, h('table', { class: 'regress' },
        h('caption', {}, 'Regression fixtures: predefined outcomes, nothing is executed'),
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Kind'), h('th', { scope: 'col' }, 'Input'), h('th', { scope: 'col' }, 'Observed'), h('th', { scope: 'col' }, 'Verdict'))),
        h('tbody', {}, ex.fix.regressions.map((r, i) => h('tr', { class: opt.results[i].pass ? 'pass' : 'fail' },
          h('td', {}, r.kind), h('td', {}, h('code', {}, r.input)), h('td', {}, opt.results[i].out),
          h('td', {}, opt.results[i].pass ? 'PASS' : 'FAIL')))))) : null,
      opt ? h('p', { class: fails ? 'summary fail' : 'summary pass', role: 'status' },
        fails ? 'This fix fails ' + fails + ' of ' + opt.results.length + ' fixtures.' : 'This fix passes all ' + opt.results.length + ' fixtures.') : null);
  }

  function rerender(ex, focusId) {
    document.getElementById(ex.id).replaceWith(renderExercise(ex));
    const el = focusId && document.getElementById(focusId);
    if (el) el.focus();
  }

  function currentView() {
    const v = location.hash.slice(1);
    if (v === 'queue' || LAB.modules.some((m) => m.id === v)) return v;
    return state.view || LAB.modules[0].id;
  }

  function render() {
    const view = currentView();
    if (state.view !== view) { state.view = view; save(); }
    for (const a of document.querySelectorAll('nav a')) {
      if (a.hash === '#' + view) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    }
    main.replaceChildren();
    if (view === 'queue') {
      const n = LAB.queue.filter((q) => state.submitted[q.id]).length;
      main.append(
        h('h2', {}, 'Mixed triage queue'),
        h('p', { class: 'intro' }, 'Alerts from different services. Decide each on the evidence shown. The mapped weakness appears only after you submit. ' + n + ' of ' + LAB.queue.length + ' submitted.'),
        ...LAB.queue.map(renderExercise));
    } else {
      const m = LAB.modules.find((x) => x.id === view);
      const n = m.exercises.filter((e) => state.submitted[e.id]).length;
      main.append(
        h('h2', {}, m.cwe + ': ' + m.title),
        h('p', { class: 'intro' }, m.intro + ' ' + n + ' of ' + m.exercises.length + ' submitted.'),
        ...m.exercises.map(renderExercise),
        h('aside', { class: 'sources', 'aria-label': 'Sources' }, h('h3', {}, 'Sources'),
          h('ul', {}, m.links.map(([t, href]) => h('li', {}, h('a', { href, rel: 'noopener noreferrer' }, t))))));
    }
  }

  document.getElementById('reset').addEventListener('click', () => {
    const msg = store
      ? 'Delete this lab\'s saved progress in this browser and clear this tab\'s work? Other sites and apps are not affected.'
      : 'Browser storage is unavailable, so there is no saved progress to delete. This will clear this tab\'s in-memory work for this lab, and it cannot be recovered. Continue?';
    if (!window.confirm(msg)) return;
    try { if (store) store.removeItem(KEY); } catch (e) { warn('Could not remove saved progress (' + e.name + ').'); return; }
    blocked = false;
    state = emptyState();
    warnEl.hidden = true;
    render();
  });

  window.addEventListener('hashchange', render);
  load();
  render();
})();
