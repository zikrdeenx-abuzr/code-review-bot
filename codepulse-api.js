'use strict';
// codepulse-api.js - login + /api/audit for the CodePulse AI web page. No dependencies.
const crypto = require('crypto');
const a = require('./analyzer.js');

const tokens = new Map();   // token -> { email, exp }
const codes = new Map();    // email -> { code, exp }
const HOUR = 3600 * 1000;

const FILE_BY_LANG = { Python: 'a.py', Java: 'A.java', 'C++': 'a.c', JavaScript: 'a.js', TypeScript: 'a.js' };
const SEVERITY = {
  critical: ['syntax', 'secret', 'unsafe-eval', 'unsafe-os-system', 'undefined-name', 'unbound-local', 'self-append', 'unhashable-key'],
  optimization: ['long-function'],
  style: ['shadow-builtin', 'none-compare', 'type-compare', 'mixed-indentation', 'scope-leak', 'unreachable-code'],
};
const TIER = { syntax: 1, 'undefined-name': 2, secret: 3, 'unsafe-eval': 3, 'unsafe-os-system': 3, 'long-function': 4 };

function severityOf(rule) {
  for (const [s, rules] of Object.entries(SEVERITY)) if (rules.includes(rule)) return s;
  return 'warning';
}
function titleOf(rule) { return rule.replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase()); }
function stripMd(s) { return String(s).replace(/\*\*/g, '').replace(/`/g, ''); }

// safe, line-level auto fixes only
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
  if (needsOs && !lines.some((l) => /^\s*import\s+os\b/.test(l))) {
    lines.unshift('import os');
    log.push({ change: 'Added `import os` at the top', reason: 'Needed for os.getenv() used by the secret fixes.' });
  }
  return { fixedCode: lines.join('\n'), changelog: log };
}

function audit(code, language, depth) {
  const filename = FILE_BY_LANG[language];
  if (!filename) {
    return { score: 100, summary: `${language} is not covered by the rule engine yet. Supported: Python, Java, C++/C, JavaScript.`, issues: [], fixedCode: code, changelog: [] };
  }
  const r = a.analyzePullFiles([{ filename, patch: a.fullFilePatch(code), content: code }]);
  let findings = r.findings || [];
  if (depth === 'basic') findings = findings.filter((f) => severityOf(f.rule) === 'critical');
  const issues = findings.map((f) => ({
    line: f.line, severity: severityOf(f.rule), tier: TIER[f.rule] || 5,
    title: titleOf(f.rule), explanation: stripMd(f.message),
  }));
  const fix = autoFix(code, language, findings);
  const score = depth === 'basic' ? a.scoreOf(findings) : r.score;
  const summary = issues.length ? `${issues.length} issue${issues.length > 1 ? 's' : ''} found.` : 'No issues found. Code looks clean.';
  return { score, summary, issues, fixedCode: fix.fixedCode, changelog: fix.changelog };
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
