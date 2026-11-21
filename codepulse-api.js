'use strict';
// codepulse-api.js - login + /api/audit for the CodePulse AI web page. No dependencies.
const crypto = require('crypto');
const a = require('./analyzer.js');

const tokens = new Map();   // token -> { email, exp }
const codes = new Map();    // email -> { code, exp }
const HOUR = 3600 * 1000;

const FILE_BY_LANG = { Python: 'a.py', Java: 'A.java', 'C++': 'a.c', JavaScript: 'a.js', TypeScript: 'a.js' };
const SEVERITY = {
  critical: ['syntax', 'secret', 'unsafe-eval', 'unsafe-os-system', 'undefined-name', 'unbound-local', 'self-append', 'unhashable-key', 'sql-injection', 'zero-division'],
  optimization: ['long-function'],
  style: ['shadow-builtin', 'none-compare', 'type-compare', 'mixed-indentation', 'scope-leak', 'unreachable-code'],
};
const TIER = { syntax: 1, 'undefined-name': 2, secret: 3, 'unsafe-eval': 3, 'unsafe-os-system': 3, 'sql-injection': 3, 'zero-division': 3, 'long-function': 4 };

function severityOf(rule) {
  for (const [s, rules] of Object.entries(SEVERITY)) if (rules.includes(rule)) return s;
  return 'warning';
}
function titleOf(rule) { return rule.replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase()); }
function stripMd(s) { return String(s).replace(/\*\*/g, '').replace(/`/g, ''); }

// safe, line-level auto fixes
function autoFix(code, language, findings) {
  const lines = code.split('\n');
  const log = [];
  let needsOs = false;
  const isJs = language === 'JavaScript' || language === 'TypeScript';
  for (const f of findings) {
    const i = f.line - 1;
    if (i < 0 || i >= lines.length) continue;
    const before = lines[i];
    let after = before;
    if (f.rule === 'none-compare') {
      after = before.replace(/==\s*None\b/, 'is None').replace(/!=\s*None\b/, 'is not None');
    } else if (f.rule === 'secret' && !isJs) {
      const m = before.match(/^(\s*)([A-Za-z_]\w*)(\s*=\s*)(["'])[^"']+\4(.*)$/);
      if (m) { after = `${m[1]}${m[2]}${m[3]}os.getenv("${m[2].toUpperCase()}", "")${m[5]}`; needsOs = true; }
    } else if (f.rule === 'secret' && isJs) {
      const m = before.match(/^(\s*(?:const|let|var)\s+)([A-Za-z_$][\w$]*)(\s*=\s*)(["'`])[^"'`]+\4(.*)$/);
      if (m) after = `${m[1]}${m[2]}${m[3]}process.env.${m[2].replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase()}${m[5]}`;
    } else if (f.rule === 'syntax' && /^\s*else\s+if\b/.test(before) && language === 'Python') {
      after = before.replace(/else\s+if\b/, 'elif');
    }
    if (after !== before) {
      lines[i] = after;
      log.push({ change: `Line ${f.line}: ${before.trim()}  ->  ${after.trim()}`, reason: stripMd(f.message).split('\n')[0].slice(0, 140) });
    }
  }

  // Extra safe security hardening fixes for Python (TLS, Weak Hash, Shell, Debug)
  if (language === 'Python') {
    for (let idx = 0; idx < lines.length; idx++) {
      const before = lines[idx];
      if (before.trim().startsWith('#')) continue;
      let after = before;
      after = after.replace(/verify\s*=\s*False\b/, 'verify=True');
      after = after.replace(/hashlib\.(md5|sha1)\(/, 'hashlib.sha256(');
      after = after.replace(/shell\s*=\s*True\b/, 'shell=False');
      after = after.replace(/debug\s*=\s*True\b/, 'debug=False');
      if (after !== before) {
        lines[idx] = after;
        log.push({ change: `Line ${idx + 1}: ${before.trim()}  ->  ${after.trim()}`, reason: 'Hardened insecure default (TLS/Hash/Shell/Debug).' });
      }
    }
  }

  if (needsOs && !lines.some((l) => /^\s*import\s+os\b/.test(l))) {
    lines.unshift('import os');
    log.push({ change: 'Added `import os` at the top', reason: 'Needed for os.getenv() used by the secret fixes.' });
  }
  return { fixedCode: lines.join('\n'), changelog: log };
}

/* ---------- language detection (used when the page sends "Auto") ---------- */
const FILE_FOR = { Python: 'a.py', JavaScript: 'a.js', TypeScript: 'a.js', Java: 'A.java', 'C++': 'a.c', Go: 'a.go', SQL: 'a.sql', 'HTML/CSS': 'a.html' };

function detectLanguage(code) {
  const noBlock = code.replace(/\/\*[\s\S]*?\*\//g, ' ');
  const bare = noBlock.replace(/("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`[^`]*`)/g, '""');
  const sc = { Java: 0, 'C++': 0, Go: 0, SQL: 0, 'HTML/CSS': 0, JavaScript: 0, Python: 0 };
  const has = (re, lang, n) => { if (re.test(bare)) sc[lang] += n; };
  // Python
  has(/^\s*def\s+\w+\s*\(.*\)\s*(->.*)?:/m, 'Python', 3);
  has(/^\s*class\s+\w+.*:\s*$/m, 'Python', 3);
  has(/^\s*(elif|else)\b.*:\s*$/m, 'Python', 2);
  has(/^[ \t]*(if|for|while)\b[^;{}\n]*:[ \t]*$/m, 'Python', 2);
  has(/^\s*(from\s+\S+\s+)?import\s+[\w., ]+\s*$/m, 'Python', 2);
  has(/^\s*#(?!\s*(include|define|if|ifdef|ifndef|endif|pragma))/m, 'Python', 2);
  has(/\bprint\s*\(/, 'Python', 1);
  has(/\b(None|True|False)\b/, 'Python', 1);
  has(/\bself\b/, 'Python', 1);
  has(/\bexec\s*\(/, 'Python', 1);
  has(/\b(len|range)\s*\(/, 'Python', 1);
  has(/^\s*(try|except[^:\n]*|finally)\s*:/m, 'Python', 2);
  has(/\bwith\s+open\s*\(/, 'Python', 2);
  has(/\blambda\b/, 'Python', 1);
  // JavaScript
  has(/\b(const|let|var)\s+[\w$]+\s*=/, 'JavaScript', 3);
  has(/\bfunction\b/, 'JavaScript', 3);
  has(/=>/, 'JavaScript', 2);
  has(/\bconsole\.\w+/, 'JavaScript', 3);
  has(/\brequire\s*\(/, 'JavaScript', 2);
  has(/===|!==/, 'JavaScript', 2);
  has(/\bdocument\.|\bwindow\./, 'JavaScript', 2);
  has(/^[ \t]*import[ \t]+.+[ \t]from[ \t]/m, 'JavaScript', 3);
  has(/\bexport\s+(default|const|function)/, 'JavaScript', 2);
  has(/\b(async|await)\b/, 'JavaScript', 1);
  // Java
  has(/\bpublic\s+(static\s+)?(class|void|int|String)\b/, 'Java', 3);
  has(/System\.out\.print/, 'Java', 4);
  has(/\bString\[\]\s+\w+/, 'Java', 3);
  has(/^\s*import\s+java\./m, 'Java', 4);
  has(/@Override/, 'Java', 2);
  has(/\bclass\s+\w+\s*(extends\s+\w+\s*)?\{/, 'Java', 3);
  has(/\b(void|int|String|boolean|double)\s+\w+\s*\([^)]*\)\s*(throws\s+\w+\s*)?\{/, 'Java', 2);
  has(/\b(Integer|Double|Boolean|Math|System|Arrays|Collections)\.\w+/, 'Java', 2);
  has(/\bpackage\s+[\w.]+;/, 'Java', 2);
  has(/\b(private|protected)\s+(static\s+)?\w+/, 'Java', 1);
  // C / C++
  has(/#include\s*[<"]/, 'C++', 4);
  has(/\bint\s+main\s*\(/, 'C++', 3);
  has(/\b(printf|scanf)\s*\(/, 'C++', 2);
  has(/\b(malloc|free)\s*\(/, 'C++', 2);
  has(/\bstd::|\bcout\b|\bcin\b|using\s+namespace/, 'C++', 3);
  // Go
  has(/^\s*package\s+\w+\s*$/m, 'Go', 3);
  has(/\bfunc\s+(\(\w+\s+\*?\w+\)\s*)?\w+\s*\(/, 'Go', 3);
  has(/:=/, 'Go', 2);
  has(/\bfmt\.\w+/, 'Go', 3);
  // SQL
  has(/^\s*(SELECT\b[\s\S]*?\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+(TABLE|DATABASE)|GRANT\s)/im, 'SQL', 5);
  // HTML
  has(/<\/?(html|div|body|span|head|p|a|ul|li|script|style|h1|form|input|button)\b/i, 'HTML/CSS', 4);
  let best = null, top = 0;
  for (const [lang, n] of Object.entries(sc)) if (n > top) { top = n; best = lang; }
  if (best) return best;
  return /;\s*$/m.test(bare) ? 'JavaScript' : 'Python';
}

// Older page versions send a guess; if it says JavaScript but the code is clearly Python, use Python.
function fixLanguage(code, language) {
  if (language !== 'JavaScript' && language !== 'TypeScript') return language;
  const d = detectLanguage(code);
  return d === 'Python' ? 'Python' : language;
}

/* ---------- extra security rules (conservative, to avoid false alarms) ---------- */
const SEC = {
  Python: [
    ['critical', /subprocess\.\w+\([^)]*shell\s*=\s*True/, 'Shell injection risk', 'subprocess with shell=True can run injected commands. Pass a list of arguments and remove shell=True.'],
    ['critical', /\bpickle\.loads?\(/, 'Unsafe deserialization', 'pickle can execute code while loading data. Never unpickle untrusted data; use JSON instead.'],
    ['critical', /\byaml\.load\((?![^)]*SafeLoader)/, 'Unsafe YAML load', 'yaml.load can build arbitrary objects. Use yaml.safe_load instead.'],
    ['critical', /verify\s*=\s*False/, 'TLS verification disabled', 'verify=False turns off certificate checks, so the connection can be intercepted. Remove it.'],
    ['critical', /\.execute\(\s*(f["']|"[^"]*"\s*[+%]|'[^']*'\s*[+%])|f(["'])(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\{|(["'])(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\3\s*[+%]/i, 'SQL injection risk', 'The SQL text is built from variables. Use parameterized queries: cursor.execute("... WHERE id = ?", (value,)).'],
    ['warning', /hashlib\.(md5|sha1)\(/, 'Weak hash', 'MD5 and SHA-1 are broken for security use. Use SHA-256 (or bcrypt/argon2 for passwords).'],
    ['warning', /\.run\([^)]*debug\s*=\s*True/, 'Debug mode on', 'debug=True exposes an interactive debugger. Turn it off in production.'],
  ],
  JavaScript: [
    ['critical', /\beval\s*\(/, 'Unsafe eval', 'eval() runs any text as code. Parse data with JSON.parse or use real functions instead.'],
    ['critical', /\bnew\s+Function\s*\(/, 'Unsafe dynamic code', 'new Function() builds code from text, the same risk as eval().'],
    ['critical', /\b(child_process\.)?exec(Sync)?\s*\([^)]*(\+|\$\{)/, 'Command injection risk', 'A shell command is built from variables. Use execFile with an argument list.'],
    ['critical', /\b(query|execute)\s*\(\s*(["'`][^"'`]*["'`]\s*\+|`[^`]*\$\{)/, 'SQL injection risk', 'The SQL text is built from variables. Use placeholders (? or $1) and pass the values separately.'],
    ['warning', /\.innerHTML\s*\+?=(?!\s*(""|''|``)\s*;?\s*$)/, 'XSS risk (innerHTML)', 'Putting text into innerHTML can run injected scripts. Use textContent instead.'],
    ['warning', /\bdocument\.write\s*\(/, 'document.write used', 'document.write can inject scripts. Build elements with the DOM instead.'],
  ],
  Java: [
    ['critical', /Runtime\.getRuntime\(\)\.exec\s*\(/, 'Command execution', 'Running OS commands is risky if any part comes from input. Validate strictly or avoid it.'],
    ['critical', /(executeQuery|executeUpdate|prepareStatement)\s*\(\s*"[^"]*"\s*\+/, 'SQL injection risk', 'The SQL text is joined with variables. Use PreparedStatement with ? placeholders.'],
    ['warning', /MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"/i, 'Weak hash', 'MD5 and SHA-1 are broken for security use. Use SHA-256 or stronger.'],
  ],
  'C++': [
    ['critical', /\bgets\s*\(/, 'gets() is unsafe', 'gets() cannot limit input size and causes buffer overflows. Use fgets().'],
    ['critical', /\bscanf\s*\(\s*"%s"/, 'Unbounded scanf', 'scanf("%s") has no size limit. Use a width like %49s or fgets().'],
    ['critical', /\bsystem\s*\(/, 'system() call', 'system() runs a shell command and is dangerous with any outside input.'],
    ['warning', /\b(strcpy|strcat|sprintf)\s*\(/, 'Unsafe string function', 'These do not check the buffer size. Use strncpy, strncat or snprintf.'],
  ],
  Go: [
    ['critical', /\.(Query|Exec)\s*\(\s*"[^"]*"\s*\+/, 'SQL injection risk', 'The SQL text is joined with variables. Use placeholders ($1 or ?).'],
    ['critical', /InsecureSkipVerify\s*:\s*true/, 'TLS verification disabled', 'InsecureSkipVerify turns off certificate checks. Remove it.'],
    ['warning', /exec\.Command\(\s*"(sh|bash)"/, 'Shell command', 'Running a shell with built text can allow injection. Call the program directly with arguments.'],
  ],
  SQL: [
    ['warning', /\bGRANT\s+ALL\b/i, 'Over-broad GRANT', 'GRANT ALL gives every permission. Give only what is needed.'],
    ['warning', /\bDROP\s+(TABLE|DATABASE)\b/i, 'DROP statement', 'DROP permanently deletes data. Make sure this is intended and backed up.'],
  ],
  'HTML/CSS': [
    ['warning', /<script[^>]+src\s*=\s*["']http:\/\//i, 'Insecure script source', 'The script loads over http, which can be tampered with. Use https.'],
    ['warning', /target\s*=\s*["']_blank["'](?![^>]*noopener)/i, 'Missing rel="noopener"', 'Links that open a new tab should have rel="noopener noreferrer".'],
  ],
};
SEC.TypeScript = SEC.JavaScript;

function isCommentLine(line, lang) {
  const t = line.trim();
  if (lang === 'Python') return t.startsWith('#');
  if (lang === 'SQL') return t.startsWith('--');
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*');
}

function securityScan(code, language) {
  const out = [];
  const lines = code.split('\n');
  const rules = SEC[language] || [];
  lines.forEach((line, i) => {
    if (isCommentLine(line, language)) return;
    for (const [sev, re, title, msg] of rules) {
      if (re.test(line)) out.push({ line: i + 1, severity: sev, tier: 3, title, explanation: msg });
    }
  });
  if (language === 'SQL') {  // DELETE / UPDATE with no WHERE
    for (let i = 0; i < lines.length; i++) {
      if (isCommentLine(lines[i], 'SQL')) continue;
      if (/^\s*(DELETE\s+FROM|UPDATE)\b/i.test(lines[i])) {
        let stmt = '';
        for (let j = i; j < lines.length; j++) { stmt += ' ' + lines[j]; if (lines[j].includes(';')) break; }
        if (!/\bWHERE\b/i.test(stmt)) out.push({ line: i + 1, severity: 'critical', tier: 3, title: 'No WHERE clause', explanation: 'This DELETE/UPDATE has no WHERE, so it changes every row in the table.' });
      }
    }
  }
  return out;
}

function audit(code, language, depth) {
  language = !language || language === 'Auto' ? detectLanguage(code) : fixLanguage(code, language);
  const filename = FILE_FOR[language] || 'a.txt';
  const r = a.analyzePullFiles([{ filename, patch: a.fullFilePatch(code), content: code }]);
  let findings = r.findings || [];
  const issues = findings.map((f) => ({
    line: f.line, severity: severityOf(f.rule), tier: TIER[f.rule] || 5,
    title: titleOf(f.rule), explanation: stripMd(f.message),
  }));
  const takenEval = new Set(issues.filter((x) => x.title === 'Unsafe eval').map((x) => x.line));
  const takenSql = new Set(issues.filter((x) => /sql injection/i.test(x.title)).map((x) => x.line));
  for (const x of securityScan(code, language)) {
    if (x.title === 'Unsafe eval' && takenEval.has(x.line)) continue;
    if (/sql injection/i.test(x.title) && takenSql.has(x.line)) continue;
    issues.push(x);
  }
  let shown = issues;
  if (depth === 'basic') shown = issues.filter((x) => x.severity === 'critical');
  shown.sort((p, q) => p.line - q.line);
  const base = depth === 'basic' ? a.scoreOf(findings.filter((f) => severityOf(f.rule) === 'critical')) : r.score;
  const extraPen = shown.filter((x) => !findings.some((f) => f.line === x.line && titleOf(f.rule) === x.title))
    .reduce((n, x) => n + (x.severity === 'critical' ? 15 : 6), 0);
  const score = Math.max(0, base - extraPen);
  const fix = autoFix(code, language, findings);
  const sev = shown.length ? `${shown.length} issue${shown.length > 1 ? 's' : ''} found.` : 'No issues found. Code looks clean.';
  const note = FILE_FOR[language] && ['Python', 'JavaScript', 'TypeScript', 'Java', 'C++'].includes(language) ? '' : ' (security rules only for this language)';
  return { language, score, summary: `Detected: ${language}. ${sev}${note}`, issues: shown, fixedCode: fix.fixedCode, changelog: fix.changelog };
}

function newToken(email) {
  const t = crypto.randomBytes(24).toString('hex');
  tokens.set(t, { email, exp: Date.now() + 12 * HOUR });
  return t;
}
function authed(req) {
  const h = req.headers.authorization || '';
  const s = tokens.get(h.startsWith('Bearer ') ? h.slice(7) : '');
  return s && s.exp > Date.now() ? s : null;
}

// returns true if it handled the request
async function handle(req, res, url, readBody, send) {
  if (req.method !== 'POST' || !url.startsWith('/api/')) return false;
  const body = async () => { try { return JSON.parse((await readBody(req, 1000000)).toString() || '{}'); } catch (e) { return {}; } };

  if (url === '/api/auth/guest') { send(res, 200, { token: newToken('guest') }); return true; }
  if (url === '/api/auth/request') {
    const { email } = await body();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email || '')) { send(res, 400, { error: 'Enter a valid email address.' }); return true; }
    const code = String(crypto.randomInt(100000, 1000000));
    codes.set(email.toLowerCase(), { code, exp: Date.now() + 5 * 60 * 1000 });
    send(res, 200, { demoCode: code });
    return true;
  }
  if (url === '/api/auth/verify') {
    const { email, code } = await body();
    const key = String(email || '').toLowerCase();
    const c = codes.get(key);
    if (!c || c.exp < Date.now() || c.code !== String(code || '')) { send(res, 400, { error: 'Wrong or expired code.' }); return true; }
    codes.delete(key);
    send(res, 200, { token: newToken(email) });
    return true;
  }
  if (url === '/api/audit') {
    if (!authed(req)) { send(res, 401, { error: 'Please sign in again.' }); return true; }
    const { code, language, depth } = await body();
    if (!code || !String(code).trim()) { send(res, 400, { error: 'Paste some code first.' }); return true; }
    send(res, 200, audit(String(code), language || 'Python', depth || 'standard'));
    return true;
  }
  return false;
}

module.exports = { handle, audit };
      
