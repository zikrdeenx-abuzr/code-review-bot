# Test Report - CodePulse AI analyzer

The analyzer was run on **46 small code samples** (24 with a known mistake, 22 correct).

| Measure | Result |
|---|---|
| Mistakes caught on the right line | **24/24 (100%)** |
| Correct code left alone (no false alarm) | **22/22 (100%)** |

Run it yourself: `node run-tests.js`

## Samples with a mistake (bot must comment)

| # | Sample | File type | Caught |
|---|---|---|---|
| 1 | Misspelled variable (mark vs marks) | py | Yes |
| 2 | Wrong capital letter in name | py | Yes |
| 3 | Misspelled print | py | Yes |
| 4 | Calling a function never defined | py | Yes |
| 5 | Missing colon after if | py | Yes |
| 6 | Missing colon after def | py | Yes |
| 7 | Missing colon after for | py | Yes |
| 8 | else if instead of elif | py | Yes |
| 9 | Python 2 print statement | py | Yes |
| 10 | = instead of == in if | py | Yes |
| 11 | Unexpected indent | py | Yes |
| 12 | Missing indented block | py | Yes |
| 13 | Bracket never closed | py | Yes |
| 14 | String never closed | py | Yes |
| 15 | Hard-coded API key | py | Yes |
| 16 | File opened without try/except | py | Yes |
| 17 | Bare except swallows errors | py | Yes |
| 18 | Java: missing semicolon | java | Yes |
| 19 | Java: = instead of == in if | java | Yes |
| 20 | Java: parseInt without try | java | Yes |
| 21 | C: missing semicolon after printf | c | Yes |
| 22 | C: malloc result not checked | c | Yes |
| 23 | JS: bracket never closed | js | Yes |
| 24 | JS: = instead of == in if | js | Yes |

## Correct samples (bot must stay quiet)

| # | Sample | File type | Quiet |
|---|---|---|---|
| 1 | Hello world | py | Yes |
| 2 | Variables and print | py | Yes |
| 3 | Function with loop | py | Yes |
| 4 | Class with methods | py | Yes |
| 5 | List comprehension and lambda | py | Yes |
| 6 | File read inside try/except | py | Yes |
| 7 | Imports and keyword arguments | py | Yes |
| 8 | f-string and dictionary | py | Yes |
| 9 | if / elif / else | py | Yes |
| 10 | while loop with counter | py | Yes |
| 11 | Recursion | py | Yes |
| 12 | Text with = and quotes inside strings | py | Yes |
| 13 | Multi-line call and docstring | py | Yes |
| 14 | Global variable in function | py | Yes |
| 15 | Java: hello world | java | Yes |
| 16 | Java: loop and if | java | Yes |
| 17 | Java: enum and method | java | Yes |
| 18 | Java: string over two lines | java | Yes |
| 19 | C: hello world | c | Yes |
| 20 | C: loop | c | Yes |
| 21 | JS: arrow function and regex | js | Yes |
| 22 | JS: template literal and loop | js | Yes |

## Limits (honest note)

- This is a rule-based bot, not a compiler. It reads the code as text, so very unusual code can slip through.
- The "undefined name" check works for Python only.
- The samples were written by the project team, so real-world results on unseen code may be lower than 100%.
- These samples are small on purpose: the bot is built to catch beginner mistakes, including in very short programs.
