'use strict';
// test.js - run with: node test.js
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { analyzeFile, fullFilePatch, parsePatch, scoreOf, formatComment } = require('./analyzer');
const { reviewPullRequest } = require('./review');
const gh = require('./github');

let passed = 0;
function test(name, fn) {
  return Promise.resolve().then(fn).then(
    () => { passed++; console.log('ok   ' + name); },
    (e) => { console.log('FAIL ' + name + '\n     ' + e.message); process.exitCode = 1; }
  );
}

// fake secrets are built from pieces so this file itself never contains a real-looking key
const STRIPE = ['sk', 'live', 'abcdef1234567890abcd'].join('_');
const GHTOKEN = 'gh' + 'p_' + 'a'.repeat(36);
const AWS = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP';

const run = (filename, content) => analyzeFile({ filename, content, patch: fullFilePatch(content) });
const at = (findings, rule) => findings.filter((f) => f.rule === rule).map((f) => f.line);

(async () => {
  await test('python: secrets, errors, swallowed, long function', () => {
    const src = [
      'import requests, json',                  // 1
      `API_KEY = "${STRIPE}"`,                  // 2
      'password = "hunter2024"',                // 3
      '',                                       // 4
      'def fetch(url):',                        // 5
      '    r = requests.get(url)',              // 6
      '    data = json.loads(r.text)',          // 7
      '    return data',                        // 8
      '',                                       // 9
      'def safe(url):',                         // 10
      '    try:',                               // 11
      '        r = requests.get(url)',          // 12
      '    except Exception:',                  // 13
      '        pass',                           // 14
      '    return r',                           // 15
      '',                                       // 16
      'def big():',                             // 17
      '    x = 0',
      ...Array(54).fill('    x += 1'),
    ].join('\n');
    const f = run('a.py', src);
    assert.deepStrictEqual(at(f, 'secret'), [2, 3]);
    assert.deepStrictEqual(at(f, 'error-handling'), [6, 7]);
    assert.deepStrictEqual(at(f, 'swallowed-error'), [13]);
    assert.deepStrictEqual(at(f, 'long-function'), [17]);
  });

  await test('python: bare except, input conversion, with open inside try is fine', () => {
    const src = [
      'n = int(input("age: "))',       // 1 flagged
      'try:',                          // 2
      '    m = int(input("x"))',       // 3 covered
      '    with open("f") as fh:',     // 4 covered
      '        pass',
      'except:',                       // 6 bare
      '    print("bad")',
    ].join('\n');
    const f = run('b.py', src);
    assert.deepStrictEqual(at(f, 'error-handling'), [1]);
    assert.deepStrictEqual(at(f, 'swallowed-error'), [6]);
  });

  await test('javascript: secrets, fetch/JSON.parse, promise chains, empty catch', () => {
    const src = [
      "const express = require('express');",                  // 1
      'const db = { password: "hunter2024" };',               // 2
      'async function load(url) {',                           // 3
      '  const res = await fetch(url);',                      // 4 flagged
      '  const data = JSON.parse(res.body);',                 // 5 flagged
      '  return data;',
      '}',
      'function ok(s) {',                                     // 8
      '  try {',
      '    return JSON.parse(s);',                            // 10 covered
      '  } catch (e) {',
      '    console.error(e);',
      '  }',
      '}',
      "fetch('/x').then(r => r.json());",                     // 15 flagged
      "fetch('/y').then(r => r.json()).catch(console.error);",// 16 ok
      'try { risky(); } catch (e) {}',                        // 17 swallowed
    ].join('\n');
    const f = run('a.js', src);
    assert.deepStrictEqual(at(f, 'secret'), [2]);
    assert.deepStrictEqual(at(f, 'error-handling'), [4, 5, 15]);
    assert.deepStrictEqual(at(f, 'swallowed-error'), [17]);
    assert.deepStrictEqual(at(f, 'long-function'), []);
  });

  await test('javascript: multi-line then chain with catch is fine', () => {
    const src = [
      'fetch(url)',
      '  .then((r) => {',
      '    return r.json();',
      '  })',
      '  .then((d) => use(d))',
      '  .catch((e) => console.error(e));',
    ].join('\n');
    assert.deepStrictEqual(at(run('c.js', src), 'error-handling'), []);
  });

  await test('javascript: then(onOk, onError) counts as handled', () => {
    assert.deepStrictEqual(at(run('d.js', 'p.then((r) => use(r), (e) => log(e));'), 'error-handling'), []);
  });

  await test('java: secret, parseInt, empty catch', () => {
    const src = [
      'public class A {',                                                 // 1
      '    private static final String PASSWORD = "supersecret1";',       // 2
      '    public static void main(String[] args) {',                     // 3
      '        int n = Integer.parseInt(args[0]);',                       // 4 flagged
      '        try {',
      '            int m = Integer.parseInt(args[1]);',                   // 6 covered
      '        } catch (NumberFormatException e) {',                      // 7 swallowed
      '        }',
      '    }',
      '}',
    ].join('\n');
    const f = run('A.java', src);
    assert.deepStrictEqual(at(f, 'secret'), [2]);
    assert.deepStrictEqual(at(f, 'error-handling'), [4]);
    assert.deepStrictEqual(at(f, 'swallowed-error'), [7]);
  });

  await test('c: unchecked fopen and scanf, checked malloc is fine', () => {
    const src = [
      '#include <stdio.h>',                          // 1
      '#include <stdlib.h>',                         // 2
      'int main() {',                                // 3
      '    FILE *fp = fopen("data.txt", "r");',      // 4 flagged
      '    char *buf = malloc(100);',                // 5
      '    if (buf == NULL) { return 1; }',          // 6
      '    int x;',
      '    scanf("%d", &x);',                        // 8 flagged
      '    fclose(fp);',
      '    return 0;',
      '}',
    ].join('\n');
    assert.deepStrictEqual(at(run('m.c', src), 'error-handling'), [4, 8]);
  });

  await test('long function limit: exactly 50 lines ok, 51 flagged (js, py, java)', () => {
    const js = (n) => ['function f() {', ...Array(n - 2).fill('  x++;'), '}'].join('\n');
    assert.deepStrictEqual(at(run('a.js', js(50)), 'long-function'), []);
    assert.deepStrictEqual(at(run('a.js', js(51)), 'long-function'), [1]);
    const py = (n) => ['def f():', ...Array(n - 1).fill('    x = 1')].join('\n');
    assert.deepStrictEqual(at(run('a.py', py(50)), 'long-function'), []);
    assert.deepStrictEqual(at(run('a.py', py(51)), 'long-function'), [1]);
    const java = (n) => ['class A {', '  public void f() {', ...Array(n - 2).fill('    x++;'), '  }', '}'].join('\n');
    // java(n): the method f spans exactly n lines
    assert.deepStrictEqual(at(run('A.java', java(50)), 'long-function'), []);
    assert.deepStrictEqual(at(run('A.java', java(51)), 'long-function'), [2]);
  });

  await test('braces inside strings and comments do not confuse function length', () => {
    const src = [
      'function f() {',
      '  const s = "}}}}";',
      '  // }',
      '  return s;',
      '}',
      ...Array(60).fill('x = 1;'),
    ].join('\n');
    assert.deepStrictEqual(at(run('a.js', src), 'long-function'), []);
  });

  await test('clean code: bot stays quiet', () => {
    assert.deepStrictEqual(run('a.js', 'function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n'), []);
    assert.deepStrictEqual(run('a.py', 'def add(a, b):\n    return a + b\n'), []);
    const env = run('a.py', 'import os\npassword = os.environ["DB_PASSWORD"]\ntoken = "your-token-here"\nlabel_password = "Password"\n');
    assert.deepStrictEqual(env, []);
  });

  await test('secret patterns: aws, github, private key, connection url', () => {
    const src = [
      `a = "${AWS}"`,
      `b = "${GHTOKEN}"`,
      '-----BEGIN RSA ' + 'PRIVATE KEY-----',
      'url = "postgres://admin:s3cretpw@db.example.com/app"',
      'url2 = "postgres://admin:${DB_PASS}@db.example.com/app"',
    ].join('\n');
    assert.deepStrictEqual(at(run('x.txt', src), 'secret'), [1, 2, 3, 4]);
  });

  await test('only ADDED lines get comments (diff mapping)', () => {
    const content = ['import json', 'a = json.loads(x)', 'b = json.loads(y)', 'c = 1'].join('\n');
    const patch = '@@ -1,3 +1,4 @@\n import json\n a = json.loads(x)\n+b = json.loads(y)\n+c = 1\n';
    // line 2 is old (context), line 3 is new
    assert.deepStrictEqual([...parsePatch(patch).keys()], [3, 4]);
    const f = analyzeFile({ filename: 'a.py', content, patch });
    assert.deepStrictEqual(at(f, 'error-handling'), [3]);
  });

  await test('long function: comment lands on a changed line inside it', () => {
    const body = Array(60).fill('  x++;');
    const content = ['function big() {', ...body, '}'].join('\n'); // lines 1..62
    const patch = '@@ -30,1 +30,2 @@\n   x++;\n+  y++;\n';
    const f = analyzeFile({ filename: 'a.js', content, patch });
    assert.deepStrictEqual(at(f, 'long-function'), [31]);
  });

  await test('score and comment marker', () => {
    assert.strictEqual(scoreOf([]), 100);
    assert.strictEqual(scoreOf([{ rule: 'secret' }, { rule: 'long-function' }]), 72);
    const f = run('a.py', 'password = "hunter2024"')[0];
    assert.ok(formatComment(f).includes('<!-- crb:secret:'));
  });

  await test('webhook signature check', () => {
    const body = Buffer.from('{"a":1}');
    const good = 'sha256=' + crypto.createHmac('sha256', 's3').update(body).digest('hex');
    assert.strictEqual(gh.verifySignature('s3', body, good), true);
    assert.strictEqual(gh.verifySignature('s3', body, good.slice(0, -1) + '0'), false);
    assert.strictEqual(gh.verifySignature('', body, good), false);
    assert.strictEqual(gh.verifySignature('s3', body, undefined), false);
  });

  await test('GitHub App JWT is signed RS256', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs1', format: 'pem' });
    const jwt = gh.appJwt(12345, pem);
    const [h, p, s] = jwt.split('.');
    assert.ok(crypto.createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s, 'base64url')));
    assert.strictEqual(JSON.parse(Buffer.from(p, 'base64url')).iss, '12345');
  });

  // ---- review flow with a fake GitHub ----
  const makePayload = () => ({
    action: 'opened',
    installation: { id: 1 },
    repository: { full_name: 'o/r' },
    pull_request: { number: 7, head: { sha: 'abc123' } },
  });
  function fakeGh(files, contents, existing = []) {
    const calls = { reviews: [], single: [] };
    return {
      calls,
      installationToken: async () => 't',
      listPullFiles: async () => files,
      getFileRaw: async (o, r, p) => contents[p],
      listReviewComments: async () => existing,
      createReview: async (u, t, review) => { calls.reviews.push(review); return {}; },
      createReviewComment: async (u, t, c) => { calls.single.push(c); return {}; },
    };
  }
  const badPy = 'import json\nx = json.loads(s)\npassword = "hunter2024"\n';
  const badFile = { filename: 'a.py', status: 'added', additions: 3, patch: fullFilePatch(badPy) };

  await test('review: posts one review with line comments', async () => {
    const g = fakeGh([badFile], { 'a.py': badPy });
    const res = await reviewPullRequest(makePayload(), { gh: g, log: () => {} });
    assert.strictEqual(res.posted, 2);
    assert.strictEqual(g.calls.reviews.length, 1);
    const r = g.calls.reviews[0];
    assert.strictEqual(r.commit_id, 'abc123');
    assert.strictEqual(r.event, 'COMMENT');
    assert.deepStrictEqual(r.comments.map((c) => [c.path, c.line, c.side]), [['a.py', 2, 'RIGHT'], ['a.py', 3, 'RIGHT']]);
    assert.ok(r.body.includes('Score: 74/100'));
  });

  await test('review: clean PR posts nothing', async () => {
    const good = 'def add(a, b):\n    return a + b\n';
    const g = fakeGh([{ filename: 'a.py', status: 'added', additions: 2, patch: fullFilePatch(good) }], { 'a.py': good });
    const res = await reviewPullRequest(makePayload(), { gh: g, log: () => {} });
    assert.strictEqual(res.posted, 0);
    assert.strictEqual(g.calls.reviews.length, 0);
  });

  await test('review: second push does not repeat old comments', async () => {
    const first = fakeGh([badFile], { 'a.py': badPy });
    await reviewPullRequest(makePayload(), { gh: first, log: () => {} });
    const existing = first.calls.reviews[0].comments.map((c) => ({ body: c.body }));
    const second = fakeGh([badFile], { 'a.py': badPy }, existing);
    const res = await reviewPullRequest(makePayload(), { gh: second, log: () => {} });
    assert.strictEqual(res.posted, 0);
    assert.strictEqual(second.calls.reviews.length, 0);
  });

  await test('review: falls back to single comments if the review is rejected', async () => {
    const g = fakeGh([badFile], { 'a.py': badPy });
    g.createReview = async () => { throw new Error('422'); };
    const res = await reviewPullRequest(makePayload(), { gh: g, log: () => {} });
    assert.strictEqual(res.posted, 2);
    assert.strictEqual(g.calls.single.length, 2);
  });

  await test('review: deleted files and files without a patch are ignored', async () => {
    const g = fakeGh([{ filename: 'a.py', status: 'removed', additions: 0, patch: '@@ -1 +0,0 @@\n-x' }, { filename: 'img.png', status: 'added', additions: 0 }], {});
    const res = await reviewPullRequest(makePayload(), { gh: g, log: () => {} });
    assert.strictEqual(res.posted, 0);
  });

  // ---- real server ----
  const server = require('./server');
  await new Promise((r) => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;

  await test('server: /health, /analyze, bad webhook signature', async () => {
    assert.deepStrictEqual(await (await fetch(base + '/health')).json(), { ok: true });
    const r = await fetch(base + '/analyze', { method: 'POST', body: JSON.stringify({ filename: 'a.py', content: badPy }) });
    const d = await r.json();
    assert.strictEqual(d.findings.length, 2);
    assert.strictEqual(d.score, 74);
    const w = await fetch(base + '/webhook', { method: 'POST', body: '{}', headers: { 'x-hub-signature-256': 'sha256=00' } });
    assert.strictEqual(w.status, 401);
    const home = await fetch(base + '/');
    assert.ok((await home.text()).includes('Code Review Bot'));
  });

  await test('server: signed ping webhook is accepted', async () => {
    process.env.WEBHOOK_SECRET = 'topsecret';
    const body = JSON.stringify({ zen: 'hi' });
    const sig = 'sha256=' + crypto.createHmac('sha256', 'topsecret').update(body).digest('hex');
    const w = await fetch(base + '/webhook', { method: 'POST', body, headers: { 'x-hub-signature-256': sig, 'x-github-event': 'ping' } });
    assert.strictEqual(w.status, 202);
  });

  server.close();
  console.log(`\n${passed} tests passed` + (process.exitCode ? ' (some FAILED)' : ''));
})();
