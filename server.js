'use strict';
// server.js - web server for the GitHub App webhook, plus a paste-code demo page.

const http = require('http');
const fs = require('fs');
const path = require('path');
const gh = require('./github');
const { analyzeFile, fullFilePatch, scoreOf } = require('./analyzer');
const { reviewPullRequest } = require('./review');

const PR_ACTIONS = new Set(['opened', 'synchronize', 'reopened', 'ready_for_review']);

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function send(res, status, body, type = 'application/json') {
  res.writeHead(status, { 'Content-Type': type + '; charset=utf-8' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];

    if (req.method === 'GET' && url === '/health') return send(res, 200, { ok: true });

    if (req.method === 'GET' && url === '/') {
      return send(res, 200, fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'), 'text/html');
    }

    // paste code in the demo page -> findings (same analyzer the bot uses)
    if (req.method === 'POST' && url === '/analyze') {
      const data = JSON.parse((await readBody(req, 300000)).toString() || '{}');
      const filename = String(data.filename || 'sample.py');
      const content = String(data.content || '');
      const findings = analyzeFile({ filename, content, patch: fullFilePatch(content) });
      return send(res, 200, {
        score: scoreOf(findings),
        findings: findings.map((f) => ({ line: f.line, rule: f.rule, message: f.message })),
      });
    }

    // GitHub sends pull request events here
    if (req.method === 'POST' && url === '/webhook') {
      const raw = await readBody(req, 5000000);
      if (!gh.verifySignature(process.env.WEBHOOK_SECRET, raw, req.headers['x-hub-signature-256'])) {
        return send(res, 401, { error: 'bad signature' });
      }
      send(res, 202, { ok: true }); // answer fast; GitHub gives up after 10 seconds
      if (req.headers['x-github-event'] === 'pull_request') {
        const payload = JSON.parse(raw.toString());
        if (PR_ACTIONS.has(payload.action)) {
          reviewPullRequest(payload).catch((e) => console.error('review failed:', e.message));
        }
      }
      return;
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('request failed:', e.message);
    if (!res.headersSent) send(res, 400, { error: 'bad request' });
  }
});

const port = process.env.PORT || 3000;
if (require.main === module) {
  server.listen(port, () => console.log(`Code Review Bot listening on :${port}`));
}

module.exports = server;
