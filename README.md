# Code Review Bot (Code Fuzion 2026, problem M7)

A GitHub App that comments on pull requests with **line-level feedback** for common beginner mistakes, plus a simple score. If the code is fine, it stays completely quiet.

## What it detects

| Rule | Examples | Score penalty |
|---|---|---|
| Hard-coded secrets | AWS/GitHub/Stripe/Google/Slack tokens, private keys, `password = "..."`, passwords inside connection URLs | -20 |
| Missing error handling | Python `open`, `requests.get`, `json.loads`, `int(input())`; JS `await fetch`, `JSON.parse`, `fs.*Sync`, `.then` without `.catch`; Java `parseInt`, file streams, `Scanner.nextInt`; C `fopen`/`malloc` without a NULL check, unchecked `scanf` | -6 |
| Swallowed errors | empty `catch {}`, `except: pass`, bare `except:` | -6 |
| Long functions | any function over 50 lines (Python, JS/TS, Java, C/C++) | -8 |

Score = 100 minus penalties (minimum 0).

## How it works

1. GitHub sends a `pull_request` webhook (opened / synchronize / reopened / ready_for_review) to `POST /webhook`.
2. The server checks the HMAC signature, then fetches the PR's changed files and the full text of code files.
3. `analyzer.js` finds problems, but only reports lines **added** by the PR (it never nags about old code).
4. Findings are posted as ONE review with a comment on each exact line. Each comment carries a hidden marker, so pushing again never repeats a comment.
5. No findings, or nothing new: nothing is posted.

No external dependencies: only Node.js built-ins (`http`, `crypto`, `fetch`).

## Files

- `analyzer.js` - the rules (the part to explain in the viva)
- `github.js` - webhook signature check, App JWT, GitHub API calls
- `review.js` - the pull request flow
- `server.js` - web server (`/webhook`, `/analyze`, `/health`, demo page)
- `index.html` - paste-code demo page
- `test.js` - `npm test`

## Setup

Environment variables: `APP_ID`, `PRIVATE_KEY` (the App's .pem text), `WEBHOOK_SECRET`.
Start: `npm start`. Test: `npm test`.

## Honest limits

- Checks are pattern-based (regex plus brace/indent tracking), not a full parser. Rare syntax, such as a regex literal containing quotes, can confuse it.
- Error-handling rules cover a fixed list of risky calls, not every possible one.
- A call inside `try` is treated as handled, even if the `catch` is weak.

## AI use declaration

(To be filled in before submission: which AI tools were used and for which parts.)
