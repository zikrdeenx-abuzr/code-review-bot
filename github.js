'use strict';
// github.js - talks to GitHub. Uses only Node built-ins (crypto + fetch).

const crypto = require('crypto');

const API = 'https://api.github.com';

// Check that a webhook really came from GitHub (HMAC-SHA256 of the raw body).
function verifySignature(secret, rawBody, header) {
  if (!secret || !header) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(String(header));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// A GitHub App proves who it is with a short-lived JWT signed by its private key.
function appJwt(appId, privateKeyPem) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const head = enc({ alg: 'RS256', typ: 'JWT' });
  const body = enc({ iat: now - 60, exp: now + 9 * 60, iss: String(appId) });
  const sig = crypto.createSign('RSA-SHA256').update(`${head}.${body}`).sign(privateKeyPem).toString('base64url');
  return `${head}.${body}.${sig}`;
}

async function api(method, url, token, body, accept = 'application/vnd.github+json') {
  let res;
  try {
    res = await fetch(url.startsWith('http') ? url : API + url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: accept,
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'code-review-bot',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new Error(`could not reach GitHub (${method} ${url}): ${e.message}`);
  }
  if (!res.ok) {
    const text = await res.text();
    const err = new Error(`GitHub ${method} ${url} -> ${res.status}: ${text.slice(0, 300)}`);
    err.status = res.status;
    throw err;
  }
  return accept.includes('raw') ? res.text() : res.json();
}

const tokenCache = new Map(); // installationId -> { token, expires }

async function installationToken(installationId) {
  const cached = tokenCache.get(installationId);
  if (cached && cached.expires - Date.now() > 120000) return cached.token;
  const appId = process.env.APP_ID;
  const pem = (process.env.PRIVATE_KEY || '').replace(/\\n/g, '\n');
  if (!appId || !pem) throw new Error('APP_ID or PRIVATE_KEY is not set');
  const data = await api('POST', `/app/installations/${installationId}/access_tokens`, appJwt(appId, pem));
  tokenCache.set(installationId, { token: data.token, expires: new Date(data.expires_at).getTime() });
  return data.token;
}

async function paged(url, token, maxPages = 5) {
  const all = [];
  for (let page = 1; page <= maxPages; page++) {
    const items = await api('GET', `${url}${url.includes('?') ? '&' : '?'}per_page=100&page=${page}`, token);
    all.push(...items);
    if (items.length < 100) break;
  }
  return all;
}

const listPullFiles = (pullUrl, token) => paged(`${pullUrl}/files`, token);
const listReviewComments = (pullUrl, token) => paged(`${pullUrl}/comments`, token);

function getFileRaw(owner, repo, filePath, ref, token) {
  const p = filePath.split('/').map(encodeURIComponent).join('/');
  return api('GET', `/repos/${owner}/${repo}/contents/${p}?ref=${encodeURIComponent(ref)}`, token, null, 'application/vnd.github.raw+json');
}

const createReview = (pullUrl, token, review) => api('POST', `${pullUrl}/reviews`, token, review);
const createReviewComment = (pullUrl, token, comment) => api('POST', `${pullUrl}/comments`, token, comment);

module.exports = {
  verifySignature, appJwt, installationToken,
  listPullFiles, listReviewComments, getFileRaw, createReview, createReviewComment,
};
