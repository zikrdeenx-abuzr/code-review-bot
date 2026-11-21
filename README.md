# CodePulse AI
## Newer rules: syntax and undefined names

| Rule | Examples | Score penalty |
|---|---|---|
| Syntax mistakes | missing `:` or `;`, `=` instead of `==`, `else if` instead of `elif`, Python 2 `print "hi"`, wrong indentation, a bracket or quote that is never closed | see `analyzer.js` |
| Undefined names (Python) | a misspelled variable such as `mark` instead of `marks`, with a "did you mean ...?" hint | see `analyzer.js` |

Because of these rules, even a very short piece of code no longer passes by default.

## Suggested fixes

For many findings the bot also builds the corrected line. On a pull request it is posted as a GitHub `suggestion` block, so the author can apply it with one click ("Commit suggestion"). The web page shows the same line under **Suggested fix**.

## Web page

Open the Render page, paste code, pick the language and press **Review code**.

- **Copy** copies everything in the box.
- **X** clears the whole box in one tap.
- Both buttons hide when the box is empty.

## Tests

`run-tests.js` checks the analyzer on 46 small samples: 24 with a known mistake and 22 correct ones.

| Measure | Result |
|---|---|
| Mistakes caught on the right line | 24/24 |
| Correct code left alone (no false alarm) | 22/22 |

Run it yourself:

```
node run-tests.js
```

The full table is in `TEST_REPORT.md`.
