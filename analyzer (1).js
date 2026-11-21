'use strict';
// analyzer.js - finds beginner mistakes in code. No dependencies.
// Rules: hard-coded secrets, missing error handling, swallowed errors, functions over 50 lines,
// syntax mistakes (brackets, quotes, colons, indentation, "=" vs "==", semicolons) and undefined names.
// Works on tiny snippets too (even 2 lines).

const path = require('path');
const crypto = require('crypto');
const pythonTraps = require('./python-traps.js');

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

// JS only: can a "/" at this position start a regex literal (instead of being a division)?
function regexAllowed(src, i) {
  let p = i - 1;
  while (p >= 0 && /\s/.test(src[p])) p--;
  if (p < 0) return true;
  const ch = src[p];
  if ('(,=:[!&|?{};'.includes(ch)) return true;
  if (/[A-Za-z]/.test(ch)) {
    const w = /([A-Za-z]+)$/.exec(src.slice(Math.max(0, p - 10), p + 1));
    return !!w && ['return', 'typeof', 'case', 'in', 'of', 'delete', 'void', 'throw', 'new', 'else', 'do', 'yield', 'await'].includes(w[1]);
  }
  return false;
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
      if (c === '/' && lang === 'js' && regexAllowed(src, i)) {
        let j = i + 1, inClass = false;
        while (j < n && src[j] !== '\n') {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === '[') inClass = true;
          else if (src[j] === ']') inClass = false;
          else if (src[j] === '/' && !inClass) break;
          j++;
        }
        if (j < n && src[j] === '/') { blank(i + 1, j); i = j + 1; continue; }
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

/* ---------- rule 5: syntax mistakes (works on tiny snippets) ---------- */

const OPEN_CH = '([{';
const CLOSE_CH = ')]}';

// bracket depth at the start and end of every line (Python counts ([{ ; the others count ([ only)
function depthInfo(lines, lang) {
  const open = lang === 'py' ? '([{' : '([';
  const close = lang === 'py' ? ')]}' : ')]';
  const start = [];
  const end = [];
  let d = 0;
  for (const l of lines) {
    start.push(d);
    for (const ch of l) {
      if (open.includes(ch)) d++;
      else if (close.includes(ch)) d = Math.max(0, d - 1);
    }
    end.push(d);
  }
  return { start, end };
}

// index of the first ":" that is outside brackets (":=" does not count), or -1
function topColon(s) {
  let d = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (OPEN_CH.includes(c)) d++;
    else if (CLOSE_CH.includes(c)) d--;
    else if (c === ':' && d === 0 && s[k + 1] !== '=') return k;
  }
  return -1;
}

// true if the text has a lone "=" (assignment) outside brackets: not ==, !=, <=, >=, :=, =>
function singleEqualsIndex(s) {
  let d = 0;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (OPEN_CH.includes(c)) d++;
    else if (CLOSE_CH.includes(c)) d--;
    else if (c === '=' && d === 0) {
      const prev = k > 0 ? s[k - 1] : '';
      const next = s[k + 1] || '';
      if (next === '=') { k++; continue; }
      if (next === '>') continue;
      if (prev && '=!<>:+-*/%&|^@'.includes(prev)) continue;
      return k;
    }
  }
  return -1;
}

function hasSingleEquals(s) { return singleEqualsIndex(s) >= 0; }

// put `text` right after the last real code character of a line (before any trailing comment)
function appendAtCodeEnd(origLine, strippedLine, text) {
  const col = strippedLine.replace(/\s+$/, '').length;
  return origLine.slice(0, col) + text + origLine.slice(col);
}

// lines that sit inside a triple-quoted string (their text is already blanked)
function pyDocLines(lines) {
  const inDoc = [];
  let open = false;
  for (const l of lines) {
    inDoc.push(open);
    const n = (l.match(/"""|'''/g) || []).length;
    if (n % 2) open = !open;
  }
  return inDoc;
}

function bracketProblem(stripped, lineOf) {
  const partner = { ')': '(', ']': '[', '}': '{' };
  const stack = [];
  for (let i = 0; i < stripped.length; i++) {
    const c = stripped[i];
    if (OPEN_CH.includes(c)) stack.push({ c, i });
    else if (CLOSE_CH.includes(c)) {
      const top = stack.pop();
      if (!top) return { line: lineOf(i), detail: `Extra closing \`${c}\` with no matching opening bracket.` };
      if (top.c !== partner[c]) {
        return { line: lineOf(i), detail: `\`${c}\` does not match the \`${top.c}\` opened on line ${lineOf(top.i)}. Check your brackets.` };
      }
    }
  }
  if (stack.length) {
    const top = stack[stack.length - 1];
    return { line: lineOf(top.i), detail: `Bracket \`${top.c}\` is opened here but never closed.` };
  }
  return null;
}

function pySyntax(lines, depth, flag, orig) {
  const inDoc = pyDocLines(lines);
  const stack = [0];
  let opener = null;
  let cont = false;
  let stmtInd = 0;
  const NO_BLOCK = 'Expected an indented block after this line. Indent the next line (4 spaces).';

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const t = raw.trim();
    const continuing = cont;
    cont = /\\\s*$/.test(raw);
    if (inDoc[i] || t === '') continue;
    const isStart = depth.start[i] === 0 && !continuing;

    if (isStart) {
      const ind = indentOf(raw);
      stmtInd = ind;
      let handled = false;
      if (opener) {
        if (ind > opener.ind) { stack.push(ind); handled = true; }
        else flag(opener.line, NO_BLOCK);
        opener = null;
      }
      if (!handled) {
        const top = stack[stack.length - 1];
        if (ind > top) {
          flag(i + 1, 'Unexpected indent. This line is indented more than the line before it. Remove the extra spaces.',
            ' '.repeat(top) + orig[i].trimStart());
          stack.push(ind);
        } else if (ind < top) {
          while (stack.length > 1 && stack[stack.length - 1] > ind) stack.pop();
          if (stack[stack.length - 1] !== ind) flag(i + 1, 'Indentation does not match any earlier block. Use the same number of spaces as the block you are continuing.');
        }
      }

      const kw = /^(if|elif|else|for|while|def|class|try|except|finally|with)\b/.exec(t);
      if (kw && depth.end[i] === 0 && !cont) {
        const colon = topColon(t);
        if (colon < 0) flag(i + 1, `Missing \`:\` at the end of this \`${kw[1]}\` line.`, appendAtCodeEnd(orig[i], raw, ':'));
        else if ((kw[1] === 'if' || kw[1] === 'elif' || kw[1] === 'while') && hasSingleEquals(t.slice(kw[1].length, colon))) {
          const p = raw.length - raw.trimStart().length + kw[1].length + singleEqualsIndex(t.slice(kw[1].length, colon));
          flag(i + 1, 'This condition uses `=` (assignment). To compare values use `==`.', orig[i].slice(0, p) + '==' + orig[i].slice(p + 1));
        }
      }
      if (/^else\s+if\b/.test(t)) {
        flag(i + 1, 'Python has no `else if`. Write `elif condition:` instead.', orig[i].replace(/^(\s*)else\s+if\b/, '$1elif'));
      }
      if (/^print\s+[^\s(=.,:)\]]/.test(t)) {
        flag(i + 1, 'In Python 3 `print` needs brackets: `print("text")`.',
          orig[i].includes('#') ? undefined : orig[i].replace(/^(\s*)print\s+(.*?)\s*$/, '$1print($2)'));
      }
      if (depth.end[i] === 0 && !cont && /^[A-Za-z_][\w.]*(?:\[[^\]]*\])?\s*==(?!=)/.test(t)) {
        flag(i + 1, 'This comparison does nothing because its result is thrown away. Did you mean `=` to store a value?');
      }
    }

    if (depth.end[i] === 0 && !cont && t.endsWith(':')) opener = { line: i + 1, ind: stmtInd };
  }
  if (opener) flag(opener.line, NO_BLOCK);
}

function braceSyntax(stripped, lines, lang, depth, lineOf, flag, orig) {
  // "if (x = 5)" instead of "if (x == 5)"
  const condRe = /\b(?:if|while)\s*\(/g;
  let m;
  while ((m = condRe.exec(stripped))) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(stripped, open);
    if (close < 0) continue;
    const idx = singleEqualsIndex(stripped.slice(open + 1, close));
    if (idx >= 0) {
      const ln = lineOf(m.index);
      const lineStart = stripped.lastIndexOf('\n', m.index - 1) + 1;
      const lineEnd = stripped.indexOf('\n', m.index);
      const p = open + 1 + idx - lineStart;
      const fix = (lineEnd < 0 || close < lineEnd) ? orig[ln - 1].slice(0, p) + '==' + orig[ln - 1].slice(p + 1) : undefined;
      flag(ln, 'This condition uses `=` (assignment). To compare values use `==`. If the assignment is on purpose, wrap it in extra brackets.', fix);
    }
  }

  // statement that is only a comparison, like "x == 5;"
  let prev = '';
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t === '') continue;
    if (depth.start[i] === 0 && !/[=+\-*\/&|?,(^%>]$/.test(prev) &&
        /^[A-Za-z_][\w.]*(?:\[[^\]]*\])?\s*==(?!=)[^;]*;$/.test(t)) {
      flag(i + 1, 'This comparison does nothing because its result is thrown away. Did you mean `=` to store a value?');
    }
    prev = t;
  }

  if (lang === 'java' || lang === 'c') missingSemicolons(lines, depth, flag, orig);
}

const NOT_A_STATEMENT = /^(?:if|else|for|foreach|while|do|switch|case|default|try|catch|finally|synchronized|lock|using|namespace|class|struct|enum|union|interface|typedef|template|goto)\b/;

function missingSemicolons(lines, depth, flag, orig) {
  let prev = '';
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t === '') continue;
    const before = prev;
    prev = t;
    if (depth.start[i] !== 0 || depth.end[i] !== 0) continue;
    if (t[0] === '#' || t[0] === '@' || NOT_A_STATEMENT.test(t)) continue;
    if (!/(?:\+\+|--|[\w)\]"'])$/.test(t)) continue;
    if (/[=+\-*\/&|?,(^%]$/.test(before)) continue; // previous line continues onto this one

    let next = '';
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() !== '') { next = lines[j].trim(); break; }
    }
    if (next && /^[{.+\-*\/&|?:,)=<>%^;]/.test(next)) continue; // statement continues on the next line

    const keywordStatement = /^(?:return|break|continue|throw|import|package)\b/.test(t);
    const assignment = hasSingleEquals(t);
    const call = /^[A-Za-z_]\w*(?:(?:\.|->|::)[A-Za-z_]\w*)*\s*\(.*\)$/.test(t) && !/^[A-Z][A-Z0-9_]*\s*\(/.test(t);
    if (keywordStatement || assignment || call) flag(i + 1, 'Missing `;` at the end of this statement.', appendAtCodeEnd(orig[i], lines[i], ';'));
  }
}

function syntaxFindings(stripped, lines, lang, ext, lineOf, depth, orig) {
  const out = [];
  const flag = (line, detail, fix) => out.push({ rule: 'syntax', line, message: `🛑 **Syntax mistake.** ${detail}`, fix });

  if (ext !== '.jsx' && ext !== '.tsx') {
    const bp = bracketProblem(stripped, lineOf);
    if (bp) flag(bp.line, bp.detail);
  }

  if (lang === 'py' || lang === 'java' || lang === 'c') {
    const inDoc = lang === 'py' ? pyDocLines(lines) : [];
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (inDoc[i] || /\\\s*$/.test(l) || /"""|'''/.test(l) || l.trim()[0] === '#') continue;
      const dq = (l.match(/"/g) || []).length;
      const sq = (l.match(/'/g) || []).length;
      if (dq % 2 || sq % 2) flag(i + 1, 'Unclosed quote: this text starts with a quote but never ends it on the same line.');
    }
  }

  if (lang === 'py') pySyntax(lines, depth, flag, orig);
  else braceSyntax(stripped, lines, lang, depth, lineOf, flag, orig);
  return out;
}

/* ---------- rule 6: undefined names (Python) ---------- */

const PY_KEYWORDS = new Set(('False None True and as assert async await break class continue def del elif else except finally for from ' +
  'global if import in is lambda nonlocal not or pass raise return try while with yield match case').split(/\s+/));

const PY_BUILTINS = new Set(('abs aiter all anext any ascii bin bool breakpoint bytearray bytes callable chr classmethod compile complex ' +
  'copyright credits delattr dict dir divmod enumerate eval exec exit filter float format frozenset getattr globals hasattr hash help hex id ' +
  'input int isinstance issubclass iter len license list locals map max memoryview min next object oct open ord pow print property quit range ' +
  'repr reversed round set setattr slice sorted staticmethod str sum super tuple type vars zip __import__ __name__ __file__ __doc__ ' +
  '__builtins__ __spec__ __package__ __loader__ __class__ __debug__ NotImplemented Ellipsis _ ' +
  'BaseException BaseExceptionGroup Exception ExceptionGroup ArithmeticError AssertionError AttributeError BlockingIOError BrokenPipeError ' +
  'BufferError BytesWarning ChildProcessError ConnectionAbortedError ConnectionError ConnectionRefusedError ConnectionResetError ' +
  'DeprecationWarning EOFError EncodingWarning EnvironmentError FileExistsError FileNotFoundError FloatingPointError FutureWarning ' +
  'GeneratorExit IOError ImportError ImportWarning IndentationError IndexError InterruptedError IsADirectoryError KeyError ' +
  'KeyboardInterrupt LookupError MemoryError ModuleNotFoundError NameError NotADirectoryError NotImplementedError OSError OverflowError ' +
  'PendingDeprecationWarning PermissionError ProcessLookupError RecursionError ReferenceError ResourceWarning RuntimeError RuntimeWarning ' +
  'StopAsyncIteration StopIteration SyntaxError SyntaxWarning SystemError SystemExit TabError TimeoutError TypeError UnboundLocalError ' +
  'UnicodeDecodeError UnicodeEncodeError UnicodeError UnicodeTranslateError UnicodeWarning UserWarning ValueError Warning ZeroDivisionError').split(/\s+/));

function editDistance(a, b) {
  const row = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let diag = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return row[b.length];
}

function closestName(name, candidates) {
  if (name.length < 3) return null;
  const limit = name.length <= 4 ? 1 : 2;
  const lower = name.toLowerCase();
  let best = null;
  let bestD = Infinity;
  for (const c of candidates) {
    if (c === name || c.length < 3) continue;
    const d = editDistance(lower, c.toLowerCase());
    if (d <= limit && d < bestD) { best = c; bestD = d; }
  }
  return best;
}

function splitTop(text) {
  const parts = [];
  let d = 0, last = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (OPEN_CH.includes(c)) d++;
    else if (CLOSE_CH.includes(c)) d--;
    else if (c === ',' && d === 0) { parts.push(text.slice(last, i)); last = i + 1; }
  }
  parts.push(text.slice(last));
  return parts;
}

// pieces of a line that sit left of a top-level "=" (assignment targets)
function assignTargets(line) {
  const segs = [];
  let d = 0, last = 0;
  for (let k = 0; k < line.length; k++) {
    const c = line[k];
    if (OPEN_CH.includes(c)) d++;
    else if (CLOSE_CH.includes(c)) d--;
    else if (c === '=' && d === 0) {
      const prev = k > 0 ? line[k - 1] : '';
      const next = line[k + 1] || '';
      if (next === '=') { k++; continue; }
      if (prev && '=!<>:+-*/%&|^@'.includes(prev)) continue;
      segs.push(line.slice(last, k));
      last = k + 1;
    }
  }
  return segs;
}

// every name the file creates: assignments, loops, functions, classes, imports, parameters ...
function pyDefinedNames(stripped) {
  const defined = new Set();
  let star = false;
  let m;
  const addTargets = (s) => {
    for (const x of s.matchAll(/(?<![\w.])[A-Za-z_]\w*(?![\w.(\[])/g)) defined.add(x[0]);
  };

  for (const x of stripped.matchAll(/\b(?:def|class)\s+([A-Za-z_]\w*)/g)) defined.add(x[1]);

  const defRe = /\bdef\s+[A-Za-z_]\w*\s*\(/g;
  while ((m = defRe.exec(stripped))) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(stripped, open);
    if (close < 0) continue;
    for (const part of splitTop(stripped.slice(open + 1, close))) {
      const p = /^\s*\*{0,2}\s*([A-Za-z_]\w*)/.exec(part);
      if (p) defined.add(p[1]);
    }
  }
  for (const x of stripped.matchAll(/\blambda\b([^:\n]*):/g)) {
    for (const part of splitTop(x[1])) {
      const p = /^\s*\*{0,2}\s*([A-Za-z_]\w*)/.exec(part);
      if (p) defined.add(p[1]);
    }
  }
  for (const x of stripped.matchAll(/\bfor\s+([^\n]+?)\s+in\b/g)) addTargets(x[1]);
  for (const x of stripped.matchAll(/\bas\s+([A-Za-z_]\w*)/g)) defined.add(x[1]);
  for (const x of stripped.matchAll(/([A-Za-z_]\w*)\s*:=/g)) defined.add(x[1]);
  for (const x of stripped.matchAll(/\b(?:global|nonlocal)\s+([^\n;]+)/g)) {
    for (const id of x[1].matchAll(/[A-Za-z_]\w*/g)) defined.add(id[0]);
  }

  for (const x of stripped.matchAll(/(?:^|;|:)[ \t]*import\s+([^\n;]+)/gm)) {
    for (const part of x[1].split(',')) {
      const p = /^\s*([\w.]+)(?:\s+as\s+(\w+))?/.exec(part);
      if (p) defined.add(p[2] || p[1].split('.')[0]);
    }
  }
  for (const x of stripped.matchAll(/(?:^|;|:)[ \t]*from\s+[.\w]+\s+import\s+(\([^)]*\)|[^\n;]*)/gm)) {
    const names = x[1].replace(/[()]/g, '');
    if (names.includes('*')) star = true;
    for (const part of names.split(',')) {
      const p = /^\s*(\w+)(?:\s+as\s+(\w+))?/.exec(part);
      if (p) defined.add(p[2] || p[1]);
    }
  }

  for (const line of stripped.split('\n')) {
    for (let s of assignTargets(line)) {
      const c = topColon(s);
      if (/^\s*(?:if|elif|else|for|while|with|try|except|finally|def|class)\b/.test(s)) {
        if (c < 0) continue;
        s = s.slice(c + 1);
      } else if (c >= 0) {
        s = s.slice(0, c);
      }
      addTargets(s);
    }
    const ann = /^\s*([A-Za-z_]\w*)\s*:(?!=)/.exec(line);
    if (ann) defined.add(ann[1]);
  }
  return { defined, star };
}

function undefinedNameFindings(stripped, lines, depth, orig) {
  // dynamic code: we cannot know the names, so stay quiet
  if (/^\s*match\s.+:\s*$/m.test(stripped) || /\b(?:globals|locals|exec)\s*\(/.test(stripped)) return [];
  const { defined, star } = pyDefinedNames(stripped);
  if (star) return [];
  const known = new Set([...defined, ...PY_BUILTINS]);
  const out = [];

  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const line = lines[i].replace(/\bfrom\s+[.\w]+\s+import\b[^;]*|\bimport\b[^;]*/g, (s) => ' '.repeat(s.length));
    const missing = [];
    const occ = [];
    const re = /(?<![\w.])[A-Za-z_]\w*/g;
    let m;
    while ((m = re.exec(line))) {
      const name = m[0];
      if (known.has(name) || PY_KEYWORDS.has(name)) continue;
      const end = m.index + name.length;
      if (/^[rRbBuUfF]{1,2}$/.test(name) && /["']/.test(line[end] || '')) continue; // string prefix like f"..."
      if (/^\s*=(?!=)/.test(line.slice(end))) {
        // keyword argument name inside a call, like f(sep="-")
        let d = depth.start[i];
        const before = line.slice(0, m.index);
        for (const ch of before) { if (OPEN_CH.includes(ch)) d++; else if (CLOSE_CH.includes(ch)) d--; }
        if (d > 0 && /(?:^|[(,])\s*$/.test(before)) continue;
      }
      occ.push({ index: m.index, name });
      if (!missing.includes(name)) missing.push(name);
    }
    if (!missing.length) continue;
    const guesses = {};
    const parts = missing.map((n) => {
      const guess = closestName(n, known);
      if (guess) guesses[n] = guess;
      return guess ? `\`${n}\` (did you mean \`${guess}\`?)` : `\`${n}\``;
    });
    let fix;
    if (occ.every((o) => guesses[o.name])) {
      fix = orig[i];
      for (const o of occ.sort((a, b) => b.index - a.index)) {
        fix = fix.slice(0, o.index) + guesses[o.name] + fix.slice(o.index + o.name.length);
      }
    }
    out.push({
      fix,
      rule: 'undefined-name',
      line: i + 1,
      message: `🔎 **Undefined name.** ${parts.join(', ')} ${missing.length > 1 ? 'are' : 'is'} used here but never created in this file. Check the spelling: names are case-sensitive.`,
    });
  }
  return out;
}

/* ---------- putting the structural rules together ---------- */

function structuralFindings(content, lang, ext) {
  const src = String(content).replace(/\r\n/g, '\n');
  const stripped = stripNonCode(src, lang);
  const lines = stripped.split('\n');
  const origLines = src.split('\n');
  const lineOf = makeLineLookup(stripped);
  const depth = depthInfo(lines, lang);
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
  findings = findings.concat(syntaxFindings(stripped, lines, lang, ext, lineOf, depth, origLines));
  if (lang === 'py') findings = findings.concat(undefinedNameFindings(stripped, lines, depth, origLines));
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

const PENALTY = { secret: 20, syntax: 20, 'undefined-name': 15, 'error-handling': 6, 'swallowed-error': 6, 'long-function': 8 };
Object.assign(PENALTY, pythonTraps.PENALTY);

function scoreOf(findings) {
  let score = Math.max(0, 100 - findings.reduce((s, f) => s + (PENALTY[f.rule] || 0), 0));
  if (findings.some((f) => f.rule === 'unsafe-eval')) score = Math.min(score, 70);
  return score;
}

// file = { filename, patch, content? }  -> findings only on lines ADDED in the patch
function analyzeFile(file) {
  const added = parsePatch(file.patch);
  if (added.size === 0) return [];
  const findings = [];

  if (!SECRET_SKIP_FILE.test(file.filename)) findings.push(...scanSecrets(added));

  const lang = langOf(file.filename);
  if (lang && typeof file.content === 'string') {
    const ext = path.extname(file.filename).toLowerCase();
    const addedLines = [...added.keys()].sort((a, b) => a - b);
    for (const f of structuralFindings(file.content, lang, ext)) {
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
    if (lang === 'py') {
      for (const f of pythonTraps.trapFindings(file.content)) {
        if (!added.has(f.line)) continue;
        findings.push(f);
      }
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
  // GitHub turns a ```suggestion block into a one-click "Commit suggestion" button
  const fixBlock = typeof f.fix === 'string' ? `\n\n\`\`\`suggestion\n${f.fix}\n\`\`\`` : '';
  return `${f.message}${fixBlock}\n\n<!-- ${markerOf(f)} -->`;
}

function summarize(fresh, score) {
  const label = Object.assign({
    secret: 'hard-coded secret',
    syntax: 'syntax mistake',
    'undefined-name': 'undefined name',
    'error-handling': 'missing error handling',
    'swallowed-error': 'swallowed error',
    'long-function': 'long function',
  }, pythonTraps.LABEL);
  const counts = {};
  for (const f of fresh) counts[f.rule] = (counts[f.rule] || 0) + 1;
  const parts = Object.entries(counts).map(([r, n]) => `${n} ${label[r] || r}${n > 1 ? 's' : ''}`);
  return `### 🤖 CodePulse AI\n**Score: ${score}/100**\n\n${fresh.length} new issue${fresh.length > 1 ? 's' : ''}: ${parts.join(', ')}. Details are on the lines below.`;
}

module.exports = {
  MAX_FUNCTION_LINES, langOf, parsePatch, fullFilePatch, stripNonCode,
  analyzeFile, analyzePullFiles, scoreOf, markerOf, formatComment, summarize,
};
