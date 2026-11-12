# CWE Triage Lab

A static workbench for learning four weaknesses and practising scanner-alert triage. Four modules (CWE-94 code injection, CWE-79 cross-site scripting, CWE-78 OS command injection with CWE-88 argument injection, CWE-22 path traversal) and a mixed queue with confirmed, false-positive and needs-more-evidence cases.

## First run

1. Pick a weakness in the left sidebar (on phones, the **☰ Modules** button opens it). The lab opens on CWE-94.
2. Read the lesson from top to bottom, in one column:
   1. **Understand the problem**: one or two sentences: where the input comes from, the operation that uses it, and the impact.
   2. **Read the unsafe code**: a one-line note on the dangerous line, then the tiny **✗ Unsafe** snippet. CWE-94 defines *sink* here once (the operation that uses the input); the other modules just say *operation*.
   3. **Follow one input**: press **Step through input** to send a harmful input through the unsafe code one stage at a time. The trace runs down the page, Input → Operation → Result, lights the dangerous line and labels the outcome *Works*, *Harmful effect* or *Blocked*. Nothing animates until you press it.
   4. **See the fix**: a one-line note on the protecting line, the **✓ Fixed** snippet, and the one-line rule.
3. Optional: open **Try another input or code** to choose an ordinary or harmful input and the unsafe or fixed code, then press **Run** (animated) or **Replay**. The trace in step 3 shows the result. Outcomes are predefined text. Nothing is executed. With reduced motion turned on in the operating system, Run shows the result at once.
4. Open **Practice triage** when you are ready for the full scanner-alert exercises described below. It starts closed and reopens on its own once you have saved a draft or submission for that module. A closed **Sources** disclosure follows at the end; open it for the module's references.

The **Mixed queue** has no beginner lesson, because the lesson would name each case's weakness family.

## Practice triage

For each alert you record the untrusted source, the dangerous operation, the missing control, a classification, and written rationale, impact, remediation ticket and verification criteria. Feedback and the worked answer appear only after every field is filled in; the reasoning starts with the evidence in the shown code. Only the three trace choices and the classification are scored. Compare your rationale, impact, ticket and verification with the model answer yourself. Module exercises then open a remediation drill: the vulnerable and candidate-fixed code side by side, plus predefined regression outcomes for ordinary and exploit inputs.

## Run locally

```sh
python3 -m http.server 8769
# open http://127.0.0.1:8769/
```

Plain HTML/CSS/JS, no build step, no dependencies, no backend.

## Tests

```sh
node tests.cjs   # static data, beginner blocks, validation, fonts and sink checks (no dependencies)
```

Two tests read the pre-quick-copy baseline (`git show 78a52056…:data.js`, read-only) to prove that only learner prose changed and that it got shorter; they print before/after word counts. They need the git history.

The repository does not include a browser regression harness. One is maintained outside the source tree (`cwe-triage-lab-ops/browser.cjs`, Playwright and Chromium). It takes `node browser.cjs [BASE_URL] [SCREENSHOT_DIR]`.

## Safety

- Nothing is executed. Regression "results" are fixed strings in `data.js`. The app never evaluates learner text, runs commands, touches the filesystem or loads payloads.
- All fixture and learner text reaches the page through `textContent`, form `value` or text nodes. There is no `innerHTML`, and a Content-Security-Policy meta tag allows scripts only from this origin.
- Payloads such as `<img src=x onerror=...>` and `; cat /etc/passwd` are teaching literals. Do not paste them into systems you do not own.

## Local storage and privacy

- Drafts, submissions, fix choices and the current view are saved in this browser's `localStorage` under the single key `cwe-triage-lab:v1`. Nothing is sent anywhere, but anyone using the same browser profile can read the saved data.
- The stored envelope is versioned and structurally validated. If the saved data is malformed, has the wrong types, unknown fields or exercises, or comes from a newer version, the lab shows a warning, works in memory only, and **does not overwrite** the stored copy.
- If storage is blocked, or a read or write fails, the lab shows a warning and keeps your work in the tab.
- **Reset saved progress** asks for confirmation and then removes only this lab's key.

## Adding an exercise

Edit `data.js`:

1. To add to a module, push an object into that module's `exercises` array. For the queue, push into `queue`.
2. Required fields:
   - `id`: unique, and stable once published, because saved progress is keyed by it.
   - `title`, `scenario`, `lang`, and `code`, which must be original, short and written as a plain string.
   - `alert: { rule, severity, location, message }`.
   - `source`, `sink` and `control`, each as `{ options: [...], answer: index }`. Options render in authored order, so put the correct one at varying positions; `node tests.cjs` fails if one position holds most answers.
   - `cls`: one of `confirmed`, `false-positive` or `needs-evidence`.
   - `cwe`: revealed only after submission.
   - `worked`: an array of one or two short paragraphs. The first starts with `Evidence:` and cites what in the shown code supports the classification.
   - `model: { impact, ticket, verification }`.
3. Module exercises also need a `fix`:
   - `regressions`: `[{ kind: 'Ordinary' | 'Exploit', input }]`.
   - `options`: `[{ label, code, results: [{ out, pass }] }]`, with one result per regression, in the same order.
   - Include at least one option that passes every fixture and one that fails at least one.
4. Queue cases must not reveal the answer before submission. The title, alert, scenario, code and options must not name a CWE id or weakness family, and the correct trace option should describe evidence, not state the classification (no "unknown", "none missing", "false positive"). The scenario and code still carry the evidence needed to decide. `node tests.cjs` checks this.
5. Run `node tests.cjs`.

### Beginner block

Each module also has `basics` (the queue must not have one):

- `lesson`: the one-line rule, 100 characters at most.
- `problem`, `line` and `works`: one or two short sentences each. `problem` (step 1) names the input source, the operation and the impact. `line` (step 2) explains the dangerous line; `works` (step 4) explains how the protecting line stops it. The UI prefixes both with the line number.
- `unsafe` and `fixed`: `{ code, hot }`. `code` is 2–5 lines (unsafe) or 2–6 lines (fixed). `hot` is the 0-based index of the dangerous line or the protective line that the trace lights up.
- `samples`: `[{ kind: 'Ordinary' | 'Harmful', input, unsafe: { op, out, effect }, fixed: { op, out, effect } }]`. `effect` is `ok`, `harm` or `blocked`. Step 3 starts on the first `Harmful` sample. Ordinary samples must be `ok` both ways. Harmful samples must be `harm` unsafe and `blocked` fixed.
- The fix must really remove the weakness. `node tests.cjs` checks the toy fixes for these patterns: no eval, plus a validated fixed handler; `textContent`; no shell, plus an allowlist; a server-side `Map` lookup instead of joining request text.

Demo choices are kept in memory only and never stored.

Removing or renaming an exercise id makes older saved progress fail validation. The lab then warns and leaves that data untouched instead of guessing.

## Fonts

The colours follow <http://git.marcuschiu.com/thoughts/>. For readability, headings and body use Source Sans 3 (variable, normal style, weights 200–900) at 17px, and code uses IBM Plex Mono (400). System fonts are the fallback. The two font files are served locally from `fonts/`, so the Content-Security-Policy stays `'self'` and the lab makes no external requests. No italic ships, and `font-synthesis: none` stops the browser from faking styles.

- Source Sans 3, Copyright 2010–2020 Adobe. SIL Open Font License 1.1: `fonts/sourcesans3-OFL.txt`.
- IBM Plex Mono, Copyright © 2017 IBM Corp. SIL Open Font License 1.1: `fonts/ibmplexmono-OFL.txt`.
- The files are the upstream Google Fonts repository files `ofl/sourcesans3/SourceSans3[wght].ttf` and `ofl/ibmplexmono/IBMPlexMono-Regular.ttf`.
- The earlier JetBrains Mono and Newsreader files and their licenses are still in `fonts/` but are no longer loaded.

## Sources

- MITRE CWE-94 <https://cwe.mitre.org/data/definitions/94.html>, CWE-95 <https://cwe.mitre.org/data/definitions/95.html>, CWE-79 <https://cwe.mitre.org/data/definitions/79.html>, CWE-78 <https://cwe.mitre.org/data/definitions/78.html>, CWE-88 <https://cwe.mitre.org/data/definitions/88.html>, CWE-22 <https://cwe.mitre.org/data/definitions/22.html>
- OWASP Code Injection <https://owasp.org/www-community/attacks/Code_Injection>
- OWASP Cross Site Scripting Prevention Cheat Sheet <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- OWASP OS Command Injection Defense Cheat Sheet <https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html>
- OWASP Path Traversal <https://owasp.org/www-community/attacks/Path_Traversal>
