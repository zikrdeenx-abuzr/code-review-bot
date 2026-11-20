'use strict';
// analyzer.js - finds beginner mistakes in code. No dependencies.
// Rules: hard-coded secrets, missing error handling, swallowed errors, functions over 50 lines.

const path = require('path');
const crypto = require('crypto');

const MAX_FUNCTION_LINES = 50;

const LANG_BY_EXT = {
  '.py': 'py',
  '.js': 'js', '.jsx': 'js', '.mjs': 'js', '.cjs': 'js', '.ts': 'js', '.tsx': 'js',
  '.java': 'java',
  '.c': 'c', '.h': 'c', '.cpp': 'c', '.cc': 'c', '.hpp': 'c',
};

function langOf(filename) {
  return LANG_BY_EXT[path.extname(filename).toLowerCase()] || null;
}

/* ---------- small helpers ---------- */

function indentOf(line) {
  return line.match(/^[ \t]*/)[0].replace(/\t/g, '    ').length;
}

// returns a function: character index -> 1-based line number
function makeLineLookup(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  return (idx) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };
}

// map of '{' index -> matching '}' index (strings/comments must already be blanked)
function bracePairs(text) {
  const stack = [];
  const pairs = new Map();
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '{') stack.push(i);
    else if (text[i] === '}' && stack.length) pairs.set(stack.pop(), i);
  }
  return pairs;
}

function matchParen(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// Replace the inside of strings and comments with spaces (newlines kept),
// so later regexes do not get fooled by text inside strings/comments.
function stripNonCode(src, lang) {
  const out = src.split('');
  const n = src.length;
  const blank = (a, b) => { for (let k = a; k < b && k < n; k++) if (out[k] !== '\n') out[k] = ' '; };
  let i = 0;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (lang === 'py') {
      if (c === '#') {
        let j = i; while (j < n && src[j] !== '\n') j++;
        blank(i, j); i = j; continue;
      }
      if ((c === '"' || c === "'") && src.startsWith(c.repeat(3), i)) {
        const q = c.repeat(3);
        const end = src.indexOf(q, i + 3);
        if (end < 0) { blank(i + 3, n); i = n; } else { blank(i + 3, end); i = end + 3; }
        continue;
      }
    } else {
      if (c === '/' && d === '/') {
        let j = i; while (j < n && src[j] !== '\n') j++;
        blank(i, j); i = j; continue;
      }
      if (c === '/' && d === '*') {
        const end = src.indexOf('*/', i + 2);
        if (end < 0) { blank(i, n); i = n; } else { blank(i, end + 2); i = end + 2; }
        continue;
      }
    }
    if (c === '"' || c === "'" || (c === '`' && lang === 'js')) {
      let j = i + 1;
      while (j < n && src[j] !== c && (c === '`' || src[j] !== '\n')) {
        if (src[j] === '\\') j++;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    i++;
  }
  return out.join('');
}

/* ---------- diff parsing ---------- */

// GitHub's "patch" text -> Map(newFileLineNumber -> text) for ADDED lines only
function parsePatch(patch) {
  const added = new Map();
  let n = 0;
  for (const raw of String(patch || '').split('\n')) {
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (h) { n = parseInt(h[1], 10); continue; }
    if (raw.startsWith('+')) { added.set(n, raw.slice(1)); n++; }
    else if (raw.startsWith('-') || raw.startsWith('\\')) { /* removed line / "no newline" marker */ }
    else n++; // context line
  }
  return added;
}

// treat a whole file as "all lines added" (used by the paste-code demo page)
function fullFilePatch(content) {
  const lines = String(content).replace(/\r\n/g, '\n').split('\n');
  return `@@ -0,0 +1,${lines.length} @@\n` + lines.map((l) => '+' + l).join('\n');
}

/* ---------- rule 1: hard-coded secrets ---------- */

const PLACEHOLDER_PREFIX = /^(?:your|enter|insert|replace|example|sample|dummy|fake|changeme|change_me|todo|xxx|<|\$\{|\{\{|%[sd]|\.\.\.|\*{3})/i;
const PLACEHOLDER_EXACT = new Set(['password', 'passwd', 'secret', 'token', 'apikey', 'api_key', 'test', 'none', 'null', 'undefined', 'string', 'example']);

function isPlaceholder(value) {
  const t = String(value).trim();
  if (PLACEHOLDER_PREFIX.test(t)) return true;
  if (PLACEHOLDER_EXACT.has(t.toLowerCase())) return true;
  if (/^(.)\1+$/.test(t)) return true;      // aaaaaa, ******
  if (/\s/.test(t)) return true;            // sentences are labels, not secrets
  if (/^[\/.~]/.test(t)) return true;       // file paths
  return false;
}

const TOKEN_PATTERNS = [
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'GitHub token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Slack token', re: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/ },
  { name: 'Stripe live key', re: /\b[sr]k_live_[0-9A-Za-z]{16,}\b/ },
  { name: 'private key', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/ },
  {
    name: 'password inside a connection URL',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:\/@'"]+:([^\s@'"\/]{3,})@[^\s'"]+/i,
    ok: (m) => !isPlaceholder(m[1]),
  },
];

const ENV_LOOKUP = /process\.env|os\.environ|os\.getenv|getenv\s*\(|System\.getenv|import\.meta\.env|\bENV\[/;

const ASSIGN = /([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret[_-]?key|private[_-]?key|access[_-]?key|api[_-]?key|apikey|secret|token))["']?\s*[:=]\s*[rbuf]{0,2}(["'`])([^"'`\n]{5,})\2/i;

const SECRET_SKIP_FILE = /(?:^|\/)(?:node_modules|vendor)\/|(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$|\.(?:lock|md|svg|min\.js|min\.css|example|sample)$/i;

function scanSecrets(added) {
  const out = [];
  for (const [line, text] of added) {
    let what = null;
    for (const p of TOKEN_PATTERNS) {
      const m = p.re.exec(text);
      if (m && (!p.ok || p.ok(m))) { what = p.name; break; }
    }
    if (!what && !ENV_LOOKUP.test(text)) {
      const m = ASSIGN.exec(text);
      if (m && !isPlaceholder(m[3])) what = `value assigned to \`${m[1]}\``;
    }
    if (what) {
      out.push({
        rule: 'secret',
        line,
        message: `🔐 **Hard-coded secret** (${what}). Never commit credentials: read it from an environment variable instead, and rotate this value because it is now in git history.`,
      });
    }
  }
  return out;
}

/* ---------- rule 2: missing error handling ---------- */

const RISKY = {
  py: [
    [/(?<![\w.])open\s*\(/, 'File access can fail (missing file, no permission).'],
    [/\b(?:requests|httpx)\.(?:get|post|put|delete|patch|request)\s*\(/, 'Network calls can fail (timeout, no internet, bad status).'],
    [/\bjson\.loads?\s*\(/, 'Parsing JSON raises an error on malformed input.'],
    [/\b(?:int|float)\s*\(\s*input\s*\(/, 'Converting user input crashes when the text is not a number.'],
  ],
  js: [
    [/\bawait\s+(?:fetch|axios)\b/, 'Network calls can fail (timeout, no internet, bad status).'],
    [/\bJSON\.parse\s*\(/, 'Parsing JSON throws on malformed input.'],
    [/\bfs\.(?:readFileSync|writeFileSync|appendFileSync|unlinkSync|readdirSync)\s*\(/, 'File access can fail (missing file, no permission).'],
  ],
  java: [
    [/\b(?:Integer\.parseInt|Long\.parseLong|Double\.parseDouble)\s*\(/, 'Parsing text to a number throws NumberFormatException on bad input.'],
    [/\bnew\s+(?:FileReader|FileInputStream|FileWriter|FileOutputStream)\s*\(/, 'File access can fail (missing file, no permission).'],
    [/\bFiles\.(?:readAllLines|readString|readAllBytes|write|writeString)\s*\(/, 'File access can fail (missing file, no permission).'],
    [/\.next(?:Int|Double|Long)\s*\(/, 'Scanner throws InputMismatchException when the user types the wrong kind of value.'],
  ],
};
const TRY_WORD = { py: 'try/except', js: 'try/catch', java: 'try/catch' };

function pyTryLines(lines) {
  const covered = new Set();
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)try\s*:/.exec(lines[i]);
    if (!m) continue;
    const ind = indentOf(lines[i]);
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === '') continue;
      if (indentOf(lines[j]) <= ind) break;
      covered.add(j + 1);
    }
  }
  return covered;
}

function braceTryLines(stripped, lineOf, pairs) {
  const covered = new Set();
  const re = /\btry\s*(?:\([^)]*\)\s*)?\{/g;
  let m;
  while ((m = re.exec(stripped))) {
    const open = m.index + m[0].length - 1;
    const close = pairs.get(open);
    if (close === undefined) continue;
    for (let l = lineOf(m.index); l <= lineOf(close); l++) covered.add(l);
  }
  return covered;
}

function hasTopLevelComma(text, open, close) {
  let depth = 0;
  for (let i = open + 1; i < close; i++) {
    const c = text[i];
    if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') depth--;
    else if (c === ',' && depth === 0) return true;
  }
  return false;
}

// promise.then(...) chains that never reach a .catch(...)
function unhandledThens(stripped) {
  const hits = [];
  const skip = new Set();
  const re = /\.then\s*\(/g;
  let m;
  while ((m = re.exec(stripped))) {
    if (skip.has(m.index)) continue;
    let cur = m.index;
    let handled = false;
    for (;;) {
      const open = stripped.indexOf('(', cur);
      const close = matchParen(stripped, open);
      if (close < 0) break;
      if (hasTopLevelComma(stripped, open, close)) { handled = true; break; } // then(onOk, onError)
      const rest = /^\s*\.(then|catch|finally)\s*\(/.exec(stripped.slice(close + 1, close + 200));
      if (!rest) break;
      const dot = close + 1 + rest[0].indexOf('.');
      if (rest[1] === 'catch') { handled = true; break; }
      if (rest[1] === 'then') skip.add(dot);
      cur = dot;
    }
    if (!handled) hits.push(m.index);
  }
  return hits;
}

function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function errorHandlingFindings(stripped, lines, lang, covered, lineOf) {
  const out = [];
  const flag = (line, detail) => out.push({
    rule: 'error-handling',
    line,
    message: `⚠️ **No error handling.** ${detail}` + (TRY_WORD[lang] ? ` Wrap this in ${TRY_WORD[lang]} and decide what should happen when it fails.` : ''),
  });

  if (lang === 'c') {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = /\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:std::)?(fopen|malloc|calloc|realloc)\s*\(/.exec(line);
      if (m) {
        const v = escapeRegExp(m[1]);
        const check = new RegExp(`\\b${v}\\s*(?:==|!=)\\s*(?:NULL|nullptr|0)\\b|!\\s*${v}\\b|\\bif\\s*\\(\\s*${v}\\s*\\)|\\b(?:NULL|nullptr)\\s*(?:==|!=)\\s*${v}\\b`);
        const window = lines.slice(i, i + 5).join('\n');
        if (!check.test(window)) flag(i + 1, `\`${m[2]}\` can return NULL, but \`${m[1]}\` is used without checking it. Check for NULL before using it.`);
      } else if (/^\s*(?:std::)?scanf\s*\(/.test(line)) {
        flag(i + 1, 'The return value of `scanf` is ignored, so bad input goes unnoticed. Check that it returned the number of values you expected.');
      } else if (/\b(?:atoi|atof)\s*\(/.test(line)) {
        flag(i + 1, '`atoi`/`atof` cannot tell you the text was invalid. Use `strtol`/`strtod` and check for errors.');
      }
    }
    return out;
  }

  const rules = RISKY[lang] || [];
  for (let i = 0; i < lines.length; i++) {
    const ln = i + 1;
    if (covered.has(ln)) continue;
    for (const [re, detail] of rules) {
      if (re.test(lines[i])) { flag(ln, detail); break; }
    }
  }
  if (lang === 'js') {
    for (const idx of unhandledThens(stripped)) {
      const ln = lineOf(idx);
      if (!covered.has(ln)) flag(ln, 'This promise chain has no `.catch(...)`, so a failure becomes an unhandled rejection.');
    }
  }
  return out;
}

/* ---------- rule 3: swallowed errors ---------- */

function swallowedFindings(stripped, lines, lang, lineOf) {
  const out = [];
  const flag = (line, detail) => out.push({ rule: 'swallowed-error', line, message: `⚠️ **Error swallowed.** ${detail}` });
  const EMPTY = 'This handler does nothing, so failures disappear silently. At least log the error, or handle it.';

  if (lang === 'py') {
    for (let i = 0; i < lines.length; i++) {
      const m = /^\s*except\b([^:]*):(.*)$/.exec(lines[i]);
      if (!m) continue;
      let nextCode = m[2].trim();
      for (let j = i + 1; nextCode === '' && j < lines.length; j++) nextCode = lines[j].trim();
      if (nextCode === 'pass') flag(i + 1, EMPTY);
      else if (m[1].trim() === '') flag(i + 1, 'A bare `except:` hides every bug (even Ctrl+C). Catch a specific exception and handle it.');
    }
    return out;
  }

  const re = /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}|\.catch\s*\(\s*(?:\(\s*[\w$]*\s*\)|[\w$]+)?\s*=>\s*\{\s*\}\s*\)/g;
  let m;
  while ((m = re.exec(stripped))) flag(lineOf(m.index), EMPTY);
  return out;
}

/* ---------- rule 4: long functions ---------- */

function pyFunctions(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:async\s+)?def\s+(\w+)\s*\(/.exec(lines[i]);
    if (!m) continue;
    const ind = indentOf(lines[i]);
    let last = i;
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === '') continue;
      if (indentOf(lines[j]) <= ind && !/^\s*\)/.test(lines[j])) break;
      last = j;
    }
    const len = last - i + 1;
    if (len > MAX_FUNCTION_LINES) out.push({ name: m[1], line: i + 1, endLine: last + 1, len });
  }
  return out;
}

const CONTROL = new Set(['if', 'for', 'while', 'switch', 'catch', 'else', 'try', 'do', 'finally', 'synchronized', 'foreach', 'using', 'lock']);

function braceFunctions(stripped, lineOf, pairs) {
  const out = [];
  for (const [open, close] of pairs) {
    let b = open - 1;
    while (b >= 0 && !';{}'.includes(stripped[b])) b--;
    let start = b + 1;
    let header = stripped.slice(start, open);
    const lead = /^(?:\s+|@\w+(?:\([^)]*\))?|#[^\n]*)+/.exec(header);
    if (lead) { start += lead[0].length; header = header.slice(lead[0].length); }
    const h = header.replace(/\s+/g, ' ').trim();
    if (!h) continue;
    const first = /^[A-Za-z_]+/.exec(h);
    if (first && CONTROL.has(first[0])) continue;
    if (/\bnew\b[^()]*\([^)]*\)$/.test(h)) continue; // anonymous class body
    const looksLikeFunction = h.endsWith('=>') ||
      /\)\s*(?:(?:const|noexcept|override|final|mutable)\s+)*(?:throws\s+[\w.,\s<>]+)?(?::\s*[\w<>\[\]|,.\s?]+)?$/.test(h);
    if (!looksLikeFunction) continue;

    let m;
    let name;
    if ((m = /\bfunction\s*\*?\s*([\w$]+)\s*\(/.exec(h))) name = m[1];
    else if ((m = /([\w$]+)\s*[:=]\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>)/.exec(h))) name = m[1];
    else if (h.includes('=>') || /\bfunction\s*\(/.test(h)) name = 'anonymous callback';
    else if ((m = /(?:^|[^\w$.])([\w$~]+)\s*\(/.exec(h))) name = m[1];
    else name = 'anonymous';

    const startLine = lineOf(start);
    const endLine = lineOf(close);
    const len = endLine - startLine + 1;
    if (len > MAX_FUNCTION_LINES) out.push({ name, line: startLine, endLine, len });
  }
  return out;
}

/* ---------- putting the structural rules together ---------- */

function structuralFindings(content, lang) {
  const src = String(content).replace(/\r\n/g, '\n');
  const stripped = stripNonCode(src, lang);
  const lines = stripped.split('\n');
  const lineOf = makeLineLookup(stripped);
  let findings = [];
  let fns;
  let covered;

  if (lang === 'py') {
    covered = pyTryLines(lines);
    fns = pyFunctions(lines);
  } else {
    const pairs = bracePairs(stripped);
    covered = braceTryLines(stripped, lineOf, pairs);
    fns = braceFunctions(stripped, lineOf, pairs);
  }
  findings = findings.concat(errorHandlingFindings(stripped, lines, lang, covered, lineOf));
  findings = findings.concat(swallowedFindings(stripped, lines, lang, lineOf));
  for (const f of fns) {
    findings.push({
      rule: 'long-function',
      line: f.line,
      endLine: f.endLine,
      name: f.name,
      message: `📏 **Long function.** \`${f.name}\` is ${f.len} lines (limit ${MAX_FUNCTION_LINES}). Split it into smaller functions that each do one thing.`,
    });
  }
  return findings;
}

/* ---------- public API ---------- */

const PENALTY = { secret: 20, 'error-handling': 6, 'swallowed-error': 6, 'long-function': 8 };

function scoreOf(findings) {
  return Math.max(0, 100 - findings.reduce((s, f) => s + (PENALTY[f.rule] || 0), 0));
}

// file = { filename, patch, content? }  -> findings only on lines ADDED in the patch
function analyzeFile(file) {
  const added = parsePatch(file.patch);
  if (added.size === 0) return [];
  const findings = [];

  if (!SECRET_SKIP_FILE.test(file.filename)) findings.push(...scanSecrets(added));

  const lang = langOf(file.filename);
  if (lang && typeof file.content === 'string') {
    const addedLines = [...added.keys()].sort((a, b) => a - b);
    for (const f of structuralFindings(file.content, lang)) {
      if (f.rule === 'long-function') {
        // comment on the signature if it was changed, else on the first changed line inside the function
        if (!added.has(f.line)) {
          const inside = addedLines.find((l) => l >= f.line && l <= f.endLine);
          if (inside === undefined) continue;
          f.line = inside;
        }
      } else if (!added.has(f.line)) continue;
      findings.push(f);
    }
  }

  const seen = new Set();
  const result = [];
  for (const f of findings.sort((a, b) => a.line - b.line)) {
    f.path = file.filename;
    f.key = f.rule === 'long-function' ? `fn:${f.name}` : `${f.rule}:${(added.get(f.line) || '').trim()}`;
    const id = `${f.rule}:${f.line}`;
    if (seen.has(id)) continue; // one comment per rule per line
    seen.add(id);
    result.push(f);
  }
  return result;
}

function analyzePullFiles(files) {
  const findings = [];
  for (const f of files) if (f.patch) findings.push(...analyzeFile(f));
  return { findings, score: scoreOf(findings) };
}

// hidden marker inside each comment, used to avoid posting the same comment twice
function markerOf(f) {
  const hash = crypto.createHash('sha1').update(`${f.path}\n${f.key}`).digest('hex').slice(0, 10);
  return `crb:${f.rule}:${hash}`;
}

function formatComment(f) {
  return `${f.message}\n\n<!-- ${markerOf(f)} -->`;
}

function summarize(fresh, score) {
  const label = { secret: 'hard-coded secret', 'error-handling': 'missing error handling', 'swallowed-error': 'swallowed error', 'long-function': 'long function' };
  const counts = {};
  for (const f of fresh) counts[f.rule] = (counts[f.rule] || 0) + 1;
  const parts = Object.entries(counts).map(([r, n]) => `${n} ${label[r]}${n > 1 ? 's' : ''}`);
  return `### 🤖 Code Review Bot\n**Score: ${score}/100**\n\n${fresh.length} new issue${fresh.length > 1 ? 's' : ''}: ${parts.join(', ')}. Details are on the lines below.`;
}

module.exports = {
  MAX_FUNCTION_LINES, langOf, parsePatch, fullFilePatch, stripNonCode,
  analyzeFile, analyzePullFiles, scoreOf, markerOf, formatComment, summarize,
};
