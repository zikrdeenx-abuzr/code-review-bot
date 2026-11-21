'use strict';
// run-tests.js - checks the analyzer against known-bad and known-good code.
// Usage: node run-tests.js            (prints results)
//        node run-tests.js --report   (also writes TEST_REPORT.md)
const fs = require('fs');
const a = require('./analyzer.js');

// BAD cases: the bot MUST report the expected rule on the expected line.
const BAD = [
  ['Misspelled variable (mark vs marks)', 'a.py', 'marks = 80\nprint(mark)', 'undefined-name', 2],
  ['Wrong capital letter in name', 'a.py', 'name = "Ali"\nprint(Name)', 'undefined-name', 2],
  ['Misspelled print', 'a.py', 'pritn("hello")', 'undefined-name', 1],
  ['Calling a function never defined', 'a.py', 'total = add(2, 3)\nprint(total)', 'undefined-name', 1],
  ['Missing colon after if', 'a.py', 'x = 5\nif x > 3\n    print(x)', 'syntax', 2],
  ['Missing colon after def', 'a.py', 'def hello()\n    print("hi")', 'syntax', 1],
  ['Missing colon after for', 'a.py', 'for i in range(3)\n    print(i)', 'syntax', 1],
  ['else if instead of elif', 'a.py', 'x = 1\nif x == 1:\n    pass\nelse if x == 2:\n    pass', 'syntax', 4],
  ['Python 2 print statement', 'a.py', 'print "hello"', 'syntax', 1],
  ['= instead of == in if', 'a.py', 'x = 5\nif x = 5:\n    print(x)', 'syntax', 2],
  ['Unexpected indent', 'a.py', 'x = 1\n    y = 2\nprint(x, y)', 'syntax', 2],
  ['Missing indented block', 'a.py', 'def f():\nprint(1)', 'syntax', 1],
  ['Bracket never closed', 'a.py', 'print("hi"', 'syntax', 1],
  ['String never closed', 'a.py', 'name = "abc\nprint(name)', 'syntax', 1],
  ['Hard-coded API key', 'a.py', 'API_KEY = "sk-test-1234567890abcdef"', 'secret', 1],
  ['File opened without try/except', 'a.py', 'f = open("data.txt")\nprint(f.read())', 'error-handling', 1],
  ['Bare except swallows errors', 'a.py', 'try:\n    x = 1 / 0\nexcept:\n    pass', 'swallowed-error', 3],
  ['Java: missing semicolon', 'A.java', 'class A {\n  void f() {\n    int x = 5\n  }\n}', 'syntax', 3],
  ['Java: = instead of == in if', 'A.java', 'class A {\n  void f(int x) {\n    if (x = 5) { }\n  }\n}', 'syntax', 3],
  ['Java: parseInt without try', 'A.java', 'class A {\n  void f(String s) {\n    int n = Integer.parseInt(s);\n  }\n}', 'error-handling', 3],
  ['C: missing semicolon after printf', 'a.c', '#include <stdio.h>\nint main() {\n  printf("hi")\n  return 0;\n}', 'syntax', 3],
  ['C: malloc result not checked', 'a.c', '#include <stdlib.h>\nint main() {\n  int *p = malloc(10);\n  *p = 1;\n  return 0;\n}', 'error-handling', 3],
  ['JS: bracket never closed', 'a.js', 'let x = (1 + 2;\nconsole.log(x);', 'syntax', 1],
  ['JS: = instead of == in if', 'a.js', 'let x = 3;\nif (x = 4) { console.log(x); }', 'syntax', 2],
];

// GOOD cases: correct code. The bot must stay completely quiet.
const GOOD = [
  ['Hello world', 'a.py', 'print("hello world")'],
  ['Variables and print', 'a.py', 'marks = 80\nprint(marks)'],
  ['Function with loop', 'a.py', 'def total(nums):\n    s = 0\n    for n in nums:\n        s += n\n    return s\n\nprint(total([1, 2, 3]))'],
  ['Class with methods', 'a.py', 'class Dog:\n    def __init__(self, name):\n        self.name = name\n\n    def speak(self):\n        return self.name + " says woof"\n\nprint(Dog("Tom").speak())'],
  ['List comprehension and lambda', 'a.py', 'squares = [n * n for n in range(5)]\ndouble = lambda v, w=2: v * w\nprint(squares, double(4))'],
  ['File read inside try/except', 'a.py', 'try:\n    with open("data.txt") as f:\n        text = f.read()\nexcept FileNotFoundError as e:\n    print(e)\n    text = ""\nprint(text)'],
  ['Imports and keyword arguments', 'a.py', 'import os\nfrom math import sqrt as root, pi\n\nprint(os.getcwd(), root(16), pi, sep="-", end="\\n")'],
  ['f-string and dictionary', 'a.py', 'user = {"name": "Ali", "age": 20}\nprint(f"{user[\'name\']} is {user[\'age\']}")'],
  ['if / elif / else', 'a.py', 'x = 7\nif x > 10:\n    print("big")\nelif x > 5:\n    print("medium")\nelse:\n    print("small")'],
  ['while loop with counter', 'a.py', 'i = 0\nwhile i < 3:\n    print(i)\n    i += 1'],
  ['Recursion', 'a.py', 'def fact(n):\n    if n <= 1:\n        return 1\n    return n * fact(n - 1)\n\nprint(fact(5))'],
  ['Text with = and quotes inside strings', 'a.py', 'msg = "x = 5 and y == 6 (not closed"\n# it\'s a comment with "quotes\nprint(msg)'],
  ['Multi-line call and docstring', 'a.py', 'def f(a,\n      b=2):\n    """Add numbers.\n    Second line.\n    """\n    return (a +\n            b)\n\nprint(f(1,\n        b=3))'],
  ['Global variable in function', 'a.py', 'count = 0\n\ndef inc():\n    global count\n    count += 1\n\ninc()\nprint(count)'],
  ['Java: hello world', 'A.java', 'public class A {\n  public static void main(String[] args) {\n    System.out.println("Hello");\n  }\n}'],
  ['Java: loop and if', 'A.java', 'public class A {\n  public static void main(String[] args) {\n    int sum = 0;\n    for (int i = 0; i < 5; i++) {\n      if (i % 2 == 0) {\n        sum += i;\n      }\n    }\n    System.out.println(sum);\n  }\n}'],
  ['Java: enum and method', 'A.java', 'public class A {\n  enum Color { RED(1), GREEN(2) }\n  static int twice(int x) {\n    return x * 2;\n  }\n}'],
  ['Java: string over two lines', 'A.java', 'public class A {\n  static String s() {\n    String t = "a"\n      + "b";\n    return t;\n  }\n}'],
  ['C: hello world', 'a.c', '#include <stdio.h>\nint main() {\n  printf("hello\\n");\n  return 0;\n}'],
  ['C: loop', 'a.c', '#include <stdio.h>\nint main() {\n  int sum = 0;\n  for (int i = 0; i < 5; i++) {\n    sum += i;\n  }\n  printf("%d", sum);\n  return 0;\n}'],
  ['JS: arrow function and regex', 'a.js', 'const add = (a, b) => a + b;\nconst ok = /[a-z]+\\/"/.test("abc");\nconsole.log(add(1, 2), ok);'],
  ['JS: template literal and loop', 'a.js', 'const name = "Ali";\nfor (let i = 0; i < 2; i++) {\n  console.log(`${name} ${i}`);\n}'],
];

function check(file, code) {
  return a.analyzePullFiles([{ filename: file, patch: a.fullFilePatch(code), content: code }]);
}

let caught = 0;
let quiet = 0;
const rows = [];
const misses = [];

for (const [name, file, code, rule, line] of BAD) {
  const r = check(file, code);
  const hit = r.findings.some((f) => f.rule === rule && f.line === line);
  if (hit) caught++; else misses.push(`BAD not caught: ${name} -> got ${JSON.stringify(r.findings.map((f) => f.rule + '@' + f.line))}`);
  rows.push({ kind: 'bad', name, file, ok: hit, score: r.score });
}
for (const [name, file, code] of GOOD) {
  const r = check(file, code);
  const clean = r.findings.length === 0;
  if (clean) quiet++; else misses.push(`GOOD got false alarm: ${name} -> ${JSON.stringify(r.findings.map((f) => f.rule + '@' + f.line + ' ' + f.message.slice(0, 60)))}`);
  rows.push({ kind: 'good', name, file, ok: clean, score: r.score });
}

const pct = (n, d) => Math.round((n / d) * 100);
console.log(`Mistakes caught : ${caught}/${BAD.length} (${pct(caught, BAD.length)}%)`);
console.log(`Correct code left alone (no false alarm): ${quiet}/${GOOD.length} (${pct(quiet, GOOD.length)}%)`);
for (const m of misses) console.log(' !', m);

if (process.argv.includes('--report')) {
  const lines = [];
  lines.push('# Test Report - LineLens-LPU analyzer');
  lines.push('');
  lines.push(`The analyzer was run on **${BAD.length + GOOD.length} small code samples** (${BAD.length} with a known mistake, ${GOOD.length} correct).`);
  lines.push('');
  lines.push('| Measure | Result |');
  lines.push('|---|---|');
  lines.push(`| Mistakes caught on the right line | **${caught}/${BAD.length} (${pct(caught, BAD.length)}%)** |`);
  lines.push(`| Correct code left alone (no false alarm) | **${quiet}/${GOOD.length} (${pct(quiet, GOOD.length)}%)** |`);
  lines.push('');
  lines.push('Run it yourself: `node run-tests.js`');
  lines.push('');
  lines.push('## Samples with a mistake (bot must comment)');
  lines.push('');
  lines.push('| # | Sample | File type | Caught |');
  lines.push('|---|---|---|---|');
  rows.filter((r) => r.kind === 'bad').forEach((r, i) => lines.push(`| ${i + 1} | ${r.name} | ${r.file.split('.').pop()} | ${r.ok ? 'Yes' : 'No'} |`));
  lines.push('');
  lines.push('## Correct samples (bot must stay quiet)');
  lines.push('');
  lines.push('| # | Sample | File type | Quiet |');
  lines.push('|---|---|---|---|');
  rows.filter((r) => r.kind === 'good').forEach((r, i) => lines.push(`| ${i + 1} | ${r.name} | ${r.file.split('.').pop()} | ${r.ok ? 'Yes' : 'No'} |`));
  lines.push('');
  lines.push('## Limits (honest note)');
  lines.push('');
  lines.push('- This is a rule-based bot, not a compiler. It reads the code as text, so very unusual code can slip through.');
  lines.push('- The "undefined name" check works for Python only.');
  lines.push('- The samples were written by the project team, so real-world results on unseen code may be lower than 100%.');
  lines.push('- These samples are small on purpose: the bot is built to catch beginner mistakes, including in very short programs.');
  fs.writeFileSync('TEST_REPORT.md', lines.join('\n') + '\n');
  console.log('Wrote TEST_REPORT.md');
}
process.exitCode = misses.length ? 1 : 0;
