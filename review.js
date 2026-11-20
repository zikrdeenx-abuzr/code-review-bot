'use strict';
// review.js - what happens when a pull request is opened or updated.

const realGithub = require('./github');
const { langOf, analyzePullFiles, markerOf, formatComment, summarize } = require('./analyzer');

const MAX_FILE_CHARS = 300000;

// Changed files, plus the full text of code files (needed to measure functions).
async function collectInputs(gh, token, pullUrl, pr, owner, repo, log) {
  const files = await gh.listPullFiles(pullUrl, token);
  const inputs = [];
  for (const f of files) {
    if (f.status === 'removed' || !f.patch) continue;
    let content = null;
    if (langOf(f.filename) && f.additions > 0) {
      try {
        content = await gh.getFileRaw(owner, repo, f.filename, pr.head.sha, token);
        if (content.length > MAX_FILE_CHARS) content = null;
      } catch (e) {
        log(`could not read ${f.filename}: ${e.message}`);
      }
    }
    inputs.push({ filename: f.filename, patch: f.patch, content });
  }
  return inputs;
}

// Findings we have not already commented on during an earlier push.
async function onlyNewFindings(gh, token, pullUrl, findings) {
  const existing = await gh.listReviewComments(pullUrl, token);
  const seen = new Set();
  for (const c of existing) {
    const m = /<!-- (crb:[a-z-]+:[0-9a-f]+) -->/.exec(c.body || '');
    if (m) seen.add(m[1]);
  }
  return findings.filter((f) => !seen.has(markerOf(f)));
}

// One review with line-level comments; if GitHub rejects it, post the comments one by one.
async function postReview(gh, token, pullUrl, pr, fresh, score, log) {
  const comments = fresh.map((f) => ({ path: f.path, line: f.line, side: 'RIGHT', body: formatComment(f) }));
  try {
    await gh.createReview(pullUrl, token, {
      commit_id: pr.head.sha,
      event: 'COMMENT',
      body: summarize(fresh, score),
      comments,
    });
    return;
  } catch (e) {
    log(`review rejected (${e.message}); posting comments one by one`);
  }
  for (const c of comments) {
    try {
      await gh.createReviewComment(pullUrl, token, { ...c, commit_id: pr.head.sha });
    } catch (err) {
      log(`skipped ${c.path}:${c.line}: ${err.message}`);
    }
  }
}

async function reviewPullRequest(payload, deps = {}) {
  const gh = deps.gh || realGithub;
  const log = deps.log || console.log;
  const pr = payload.pull_request;
  const [owner, repo] = payload.repository.full_name.split('/');
  const token = await gh.installationToken(payload.installation.id);
  const pullUrl = `/repos/${owner}/${repo}/pulls/${pr.number}`;

  const inputs = await collectInputs(gh, token, pullUrl, pr, owner, repo, log);
  const { findings, score } = analyzePullFiles(inputs);
  if (findings.length === 0) {
    log(`PR #${pr.number}: code is fine, staying quiet`);
    return { posted: 0 };
  }
  const fresh = await onlyNewFindings(gh, token, pullUrl, findings);
  if (fresh.length === 0) {
    log(`PR #${pr.number}: nothing new to say, staying quiet`);
    return { posted: 0 };
  }
  await postReview(gh, token, pullUrl, pr, fresh, score, log);
  log(`PR #${pr.number}: posted ${fresh.length} comment(s), score ${score}`);
  return { posted: fresh.length, score };
}

module.exports = { reviewPullRequest };
