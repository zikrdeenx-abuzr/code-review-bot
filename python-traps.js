'use strict';
// python-traps.js - deep Python-only traps that a plain syntax checker misses:
// security (eval/exec), identity-vs-equality bugs, scope leaks, mutable defaults,
// and other "the code runs, but it's a landmine" patterns.
// No dependencies. Standalone: does not require analyzer.js (keeps the two decoupled).
// Called with the FULL file content; the caller (analyzer.js) keeps only findings
// whose line number is inside the PR's added lines.

/* ---------- local helpers (kept self-contained on purpose) ---------- */

function indentOf(line) {
  return line.match(/^[ \t]*/)[0].replace(/\t/g, '    ').length;
}

function rawIndent(line) {
  return line.match(/^[ \t]*/)[0];
}

function matchParen(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function lineOfIndex(text, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

// blank out the inside of strings/comments (keep delimiters + newlines), Python only
function stripPy(src) {
  const out = src.split('');
  const n = src.length;
  const blank = (a, b) => { for (let k = a; k < b && k < n; k++) if (out[k] !== '\n') out[k] = ' '; };
  let i = 0;
  while (i < n) {
    const c = src[i];
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
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== '\n') { if (src[j] === '\\') j++; j++; }
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    i++;
  }
  return out.join('');
}

const PY_KEYWORDS = new Set(('False None True and as assert async await break class continue def del elif else except finally for from ' +
  'global if import in is lambda nonlocal not or pass raise return try while with yield match case').split(/\s+/));

const PY_BUILTINS = new Set(('abs aiter all anext any ascii bin bool breakpoint bytearray bytes callable chr classmethod compile complex ' +
  'copyright credits delattr dict dir divmod enumerate eval exec exit filter float format frozenset getattr globals hasattr hash help hex id ' +
  'input int isinstance issubclass iter len license list locals map max memoryview min next object oct open ord pow print property quit range ' +
  'repr reversed round set setattr slice sorted staticmethod str sum super tuple type vars zip __name__ __file__ __doc__ self cls ' +
  'True False None NotImplemented Ellipsis _').split(/\s+/));

const COMMON_SHADOWABLE = new Set(['input', 'len', 'type', 'list', 'dict', 'str', 'int', 'set', 'tuple', 'print', 'id', 'min', 'max',
  'sum', 'map', 'filter', 'open', 'range', 'bool', 'float', 'sorted', 'any', 'all', 'zip', 'next', 'iter', 'vars', 'object', 'super',
  'hash', 'format', 'repr', 'dir', 'enumerate', 'isinstance', 'round', 'abs', 'slice', 'frozenset', 'bytes', 'bytearray']);

// a lightweight "every name this file creates" pass, used only by short-circuit-undefined
function collectDefinedNames(stripped) {
  const defined = new Set();
  let m;

  for (const x of stripped.matchAll(/\b(?:def|class)\s+(\w+)/g)) defined.add(x[1]);

  const defRe = /\bdef\s+\w+\s*\(/g;
  while ((m = defRe.exec(stripped))) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(stripped, open);
    if (close < 0) continue;
    for (const part of stripped.slice(open + 1, close).split(',')) {
      const p = /^\s*\*{0,2}\s*(\w+)/.exec(part);
      if (p) defined.add(p[1]);
    }
  }
  for (const x of stripped.matchAll(/\bfor\s+([\w, ()]+?)\s+in\b/g)) {
    for (const n of x[1].matchAll(/\w+/g)) defined.add(n[0]);
  }
  for (const x of stripped.matchAll(/\bas\s+(\w+)/g)) defined.add(x[1]);
  for (const x of stripped.matchAll(/^\s*(\w+)\s*=(?!=)/gm)) defined.add(x[1]);
  for (const x of stripped.matchAll(/\bimport\s+(\w+)/g)) defined.add(x[1]);
  for (const x of stripped.matchAll(/\bimport\s+[\w.]+\s+as\s+(\w+)/g)) defined.add(x[1]);
  for (const x of stripped.matchAll(/\bfrom\s+[\w.]+\s+import\s+([^\n]+)/g)) {
    for (const part of x[1].replace(/[()]/g, '').split(',')) {
      const p = /^\s*(\w+)(?:\s+as\s+(\w+))?/.exec(part);
      if (p) defined.add(p[2] || p[1]);
    }
  }
  return defined;
}

/* ================= individual trap checks ================= */

// 1. eval()/exec() - mandatory heavy penalty + score cap (handled by caller via PENALTY + a special
//    'unsafe-eval' marker analyzer.js looks for to cap the final score at 70)
function checkUnsafeEval(lines, flag) {
  const re = /(?<![\w.])(eval|exec)\s*\(/;
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i]);
    if (m) {
      flag('unsafe-eval', i + 1,
        `🚨 **Unsafe \`${m[1]}()\`.** Running dynamic/untrusted code with \`${m[1]}()\` is a serious security risk (arbitrary code execution) — the score for this file is capped at 70/100 while this is present. Remove it, or replace it with a safe, specific alternative (e.g. \`ast.literal_eval\` for plain data).`);
    }
  }
}

// 2. == None / != None instead of is / is not
function checkNoneCompare(lines, orig, flag) {
  for (let i = 0; i < lines.length; i++) {
    if (/==\s*None\b/.test(lines[i]) || /\bNone\s*==/.test(lines[i])) {
      const fix = orig[i].replace(/==(\s*)None\b/, 'is$1None').replace(/\bNone(\s*)==/, 'None$1is');
      flag('none-compare', i + 1,
        '🧩 **Comparing to `None` with `==`.** Use `is None` instead: `==` can be fooled by a custom `__eq__`, while `is` correctly checks identity for the single `None` object.',
        fix !== orig[i] ? fix : undefined);
    } else if (/!=\s*None\b/.test(lines[i]) || /\bNone\s*!=/.test(lines[i])) {
      const fix = orig[i].replace(/!=(\s*)None\b/, 'is not$1None').replace(/\bNone(\s*)!=/, 'None$1is not');
      flag('none-compare', i + 1,
        '🧩 **Comparing to `None` with `!=`.** Use `is not None` instead, for the same reason `==` is unsafe for `None`.',
        fix !== orig[i] ? fix : undefined);
    }
  }
}

// 3. type(x) == SomeType instead of isinstance
function checkTypeCompare(lines, flag) {
  for (let i = 0; i < lines.length; i++) {
    if (/\btype\s*\([^()]*\)\s*==/.test(lines[i]) || /==\s*type\s*\(/.test(lines[i])) {
      flag('type-compare', i + 1,
        '🧬 **`type(x) ==` instead of `isinstance`.** This rejects subclasses, which `isinstance(x, SomeType)` would correctly accept. Use `isinstance` for type checks.');
    }
  }
}

// 4. `is` used to compare values (floats, big ints, strings, nan) instead of identity
function checkIsLiteral(lines, flag) {
  const reFloat = /\bis(?:\s+not)?\s+-?\d+\.\d+/;
  const reBigInt = /\bis(?:\s+not)?\s+-?\d{4,}\b/;
  const reNan = /\bis(?:\s+not)?\s+float\s*\(\s*['"]nan['"]\s*\)/i;
  const reStr = /\bis(?:\s+not)?\s+["']/;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (reFloat.test(l) || reBigInt.test(l) || reNan.test(l) || reStr.test(l)) {
      flag('is-literal', i + 1,
        '⚖️ **`is` used to compare a value, not an identity.** Floats, large integers, strings and `float(\'nan\')` are not reliably cached by Python, so `is` can silently give the wrong answer here (and `nan is nan` can even be `False`). Use `==` to compare values.');
    }
  }
}

// 5. reassigning a built-in name (input, len, list, type, ...)
function checkShadowBuiltin(lines, flag) {
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    let m = /^\s*def\s+(\w+)\s*\(/.exec(l);
    if (!m) m = /^\s*(\w+)\s*=(?!=)/.exec(l);
    if (m && COMMON_SHADOWABLE.has(m[1])) {
      flag('shadow-builtin', i + 1,
        `🧱 **Shadowing the built-in \`${m[1]}\`.** Reassigning \`${m[1]}\` hides Python's real \`${m[1]}\` for the rest of this scope — any later code that expected the original (even in a different function, if it's at module level) breaks in a confusing way. Rename it to something more specific.`);
      continue;
    }
    const forM = /^\s*for\s+(\w+)\s+in\b/.exec(l);
    if (forM && COMMON_SHADOWABLE.has(forM[1])) {
      flag('shadow-builtin', i + 1,
        `🧱 **Loop variable \`${forM[1]}\` shadows the built-in \`${forM[1]}\`.** Rename it so the real \`${forM[1]}\` is still usable inside the loop.`);
    }
  }
}

// 6. def f(x=[]) / def f(x={}) - mutable default argument
function checkMutableDefault(stripped, flag) {
  const defRe = /\bdef\s+\w+\s*\(/g;
  let m;
  while ((m = defRe.exec(stripped))) {
    const open = m.index + m[0].length - 1;
    const close = matchParen(stripped, open);
    if (close < 0) continue;
    const params = stripped.slice(open + 1, close);
    const mutRe = /=\s*(\[\]|\{\}|set\(\)|dict\(\)|list\(\))/g;
    let mm;
    while ((mm = mutRe.exec(params))) {
      const line = lineOfIndex(stripped, open + 1 + mm.index);
      const kind = /\{\}|dict/.test(mm[1]) ? 'dict' : (/set/.test(mm[1]) ? 'set' : 'list');
      flag('mutable-default', line,
        `⚠️ **Mutable default argument (\`${mm[1]}\`).** It is created ONCE when the function is defined and then shared across every call, so old data silently leaks between calls. Use \`None\` as the default and create the empty ${kind} inside the function body instead.`);
    }
  }
}

// 7. list.append(list) - self-referencing structure
function checkSelfAppend(lines, flag) {
  const re = /\b(\w+)\.append\s*\(\s*\1\s*\)/;
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i]);
    if (m) {
      flag('self-append', i + 1,
        `♾️ **\`${m[1]}.append(${m[1]})\` — self-referencing list.** This makes \`${m[1]}\` contain itself, an infinite nested structure. Printing it, deep-copying it, or even just \`json.dumps\` will crash or hang. Append a copy instead: \`${m[1]}.append(list(${m[1]}))\`.`);
    }
  }
}

// 8. "text" * True / "text" * -1 - boolean/negative multiplier
function checkStringBoolMultiply(lines, flag) {
  const re = /(["'])(?:[^"'\\]|\\.)*?\1\s*\*\s*(True|False|-\d+)\b|\b(True|False|-\d+)\s*\*\s*(["'])(?:[^"'\\]|\\.)*?\4/;
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      flag('string-bool-multiply', i + 1,
        '✖️ **String multiplied by a `bool`/negative number.** `"text" * True` only "works" because `True` secretly equals `1` — and `* False` or a negative number silently gives `\'\'` instead of raising an error. Multiply by an explicit, intentional integer instead.');
    }
  }
}

// 9. missing comma between adjacent string literals in a list -> implicit concatenation
function checkImplicitConcat(lines, flag) {
  // lines are already stripped: string insides are blank, only the quote marks remain.
  // Pair the quotes into string spans and look for two spans with only spaces between them.
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (ln.includes('"""') || ln.includes("'''")) continue;
    let hit = false;
    for (const m of ln.matchAll(/\[[^\[\]]*\]/g)) {
      const seg = m[0];
      const spans = [];
      let p = 0;
      while (p < seg.length) {
        const c = seg[p];
        if (c === '"' || c === "'") {
          const q = seg.indexOf(c, p + 1);
          if (q < 0) break;
          spans.push([p, q]);
          p = q + 1;
        } else p++;
      }
      for (let k = 0; k + 1 < spans.length; k++) {
        const between = seg.slice(spans[k][1] + 1, spans[k + 1][0]);
        if (between.length > 0 && /^\s+$/.test(between)) { hit = true; break; }
      }
      if (hit) break;
    }
    if (hit) {
      flag('implicit-concat', i + 1,
        '🔗 **Missing comma between strings in a list.** `["Apple" "Banana"]` silently becomes a single merged string `["AppleBanana"]` — Python concatenates adjacent string literals with no operator between them. Add the missing comma.');
    }
  }
}

// 10. tab/space mixed indentation - warning only (penalty 0)
function checkMixedIndentation(orig, flag) {
  for (let i = 0; i < orig.length; i++) {
    const ws = rawIndent(orig[i]);
    if (ws.includes(' ') && ws.includes('\t')) {
      flag('mixed-indentation', i + 1,
        '⚠️ **Mixed tabs and spaces in indentation.** This line\'s leading whitespace mixes tabs and spaces. Python 3 rejects ambiguous mixes (`TabError`) and editors can render this differently. Use spaces only, consistently.');
    }
  }
}

// 11. os.system(...) with a non-literal argument - warning only (penalty 0)
function checkUnsafeOsSystem(lines, flag) {
  const re = /\bos\.system\s*\(([^)]*)\)/;
  for (let i = 0; i < lines.length; i++) {
    const m = re.exec(lines[i]);
    if (!m) continue;
    const isPlainLiteral = /^\s*(["'])(?:[^"'\\]|\\.)*?\1\s*$/.test(m[1]);
    if (!isPlainLiteral) {
      flag('unsafe-os-system', i + 1,
        '🛡️ **`os.system()` built from a variable/expression.** If any part of this command can come from user input, this opens the door to shell command injection. Prefer `subprocess.run([...])` with a list of arguments (no shell), and validate any input first.');
    }
  }
}

// 12. a list/dict used as a dict key or set element -> unhashable type at runtime
function checkUnhashableKey(lines, flag) {
  const reDictKey = /\{\s*\[[^\]]*\]\s*:/;
  const reSubscript = /\w+\s*\[\s*\[[^\]]*\]\s*\]/;
  for (let i = 0; i < lines.length; i++) {
    if (reDictKey.test(lines[i]) || reSubscript.test(lines[i])) {
      flag('unhashable-key', i + 1,
        '🔑 **A list used as a dictionary key / set element.** Lists (and dicts) are unhashable and mutable — this raises `TypeError: unhashable type: \'list\'` at runtime. Use a tuple instead if you need a fixed, hashable key.');
    }
  }
}

// 13. code right after return/break/continue/raise, at the same indentation -> unreachable
function checkUnreachableCode(lines, flag) {
  const STOP = /^(return\b.*|break|continue|raise\b.*)$/;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!STOP.test(t)) continue;
    const ind = indentOf(lines[i]);
    for (let j = i + 1; j < lines.length; j++) {
      const t2 = lines[j].trim();
      if (t2 === '') continue;
      const ind2 = indentOf(lines[j]);
      if (ind2 === ind && !/^(elif|else|except|finally)\b/.test(t2)) {
        const kw = t.split(/\s+/)[0];
        flag('unreachable-code', j + 1,
          `💀 **Unreachable code.** This line can never run: the line above always \`${kw}\`s out of this block before execution reaches here. Remove it, or move it before the \`${kw}\`.`);
      }
      break; // only the very next real line matters
    }
  }
}

// 14. tuple holding a list, then the list inside it gets mutated in place
function checkTupleListMutation(stripped, lines, flag) {
  const tupleVars = new Set();
  for (let i = 0; i < lines.length; i++) {
    const am = /^\s*(\w+)\s*=\s*\(.*\[[^\]]*\].*,.*\)\s*$/.exec(lines[i]) ||
                /^\s*(\w+)\s*=\s*\(.*,.*\[[^\]]*\].*\)\s*$/.exec(lines[i]);
    if (am) tupleVars.add(am[1]);
  }
  if (!tupleVars.size) return;
  for (let i = 0; i < lines.length; i++) {
    for (const v of tupleVars) {
      const re = new RegExp(`\\b${v}\\s*\\[\\s*\\d+\\s*\\]\\s*(?:\\+=|\\.append\\s*\\()`);
      if (re.test(lines[i])) {
        flag('tuple-list-mutation', i + 1,
          `📦 **Mutating a list stored inside a tuple (\`${v}\`).** The tuple's *slots* can't be reassigned, but a mutable list sitting inside one of those slots can still be changed in place — this quietly mutates data that looks "immutable" from the outside. Make sure this is intentional, or store a list of lists instead of a tuple.`);
      }
    }
  }
}

// 15. a name read in this function before its first (local) assignment in that same function
function checkUnboundLocal(lines, flag) {
  const defRe = /^(\s*)def\s+(\w+)\s*\(([^)]*)\)\s*:/;
  for (let i = 0; i < lines.length; i++) {
    const dm = defRe.exec(lines[i]);
    if (!dm) continue;
    const defIndent = dm[1].length;
    const params = new Set(dm[3].split(',').map((p) => p.trim().replace(/^\*{1,2}/, '').split(/[:=]/)[0].trim()).filter(Boolean));

    let end = i;
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === '') { end = j; continue; }
      if (indentOf(lines[j]) <= defIndent) break;
      end = j;
    }
    if (end === i) continue;

    const bodyText = lines.slice(i + 1, end + 1).join('\n');
    if (/\b(global|nonlocal)\b/.test(bodyText)) continue; // be conservative: skip if explicit scope control is used

    const firstAssign = new Map();
    for (let j = i + 1; j <= end; j++) {
      const text = lines[j];
      let m;
      if ((m = /^\s*(\w+)\s*=(?!=)/.exec(text)) && !params.has(m[1]) && !firstAssign.has(m[1])) firstAssign.set(m[1], j);
      if ((m = /^\s*for\s+(\w+)\s+in\b/.exec(text)) && !firstAssign.has(m[1])) firstAssign.set(m[1], j);
      if ((m = /\bas\s+(\w+)\b/.exec(text)) && !firstAssign.has(m[1])) firstAssign.set(m[1], j);
    }
    if (!firstAssign.size) continue;

    for (let j = i + 1; j <= end; j++) {
      const text = lines[j];
      const re = /\b[A-Za-z_]\w*\b/g;
      let m;
      let flagged = false;
      while (!flagged && (m = re.exec(text))) {
        const name = m[0];
        if (!firstAssign.has(name)) continue;
        const fLine = firstAssign.get(name);
        if (j > fLine) continue;
        if (j === fLine) {
          const assignCol = text.indexOf('=');
          if (assignCol < 0 || m.index < assignCol) continue;
        }
        flag('unbound-local', j + 1,
          `🌀 **\`${name}\` used before it's assigned in this function.** Because \`${name}\` is assigned somewhere else inside this same function, Python treats it as local for the *entire* function — reading it here, before that assignment actually runs, raises \`UnboundLocalError\` even if a variable with the same name exists outside. Assign \`${name}\` before this line, or add \`global ${name}\` if you meant the outer variable.`);
        flagged = true;
      }
    }
  }
}

// 16. a name hidden behind `or` / `and` that is never defined anywhere in the file
function checkShortCircuitUndefined(stripped, lines, flag) {
  if (/\b(?:globals|locals|exec)\s*\(/.test(stripped) || /\bimport\s+\*/.test(stripped) || /\bfrom\s+[\w.]+\s+import\s+\*/.test(stripped)) return;
  const defined = collectDefinedNames(stripped);
  const known = new Set([...defined, ...PY_BUILTINS]);
  const re = /\b(?:or|and)\s+([A-Za-z_]\w*)\b/g;
  for (let i = 0; i < lines.length; i++) {
    let m;
    const lineRe = new RegExp(re.source, 'g');
    while ((m = lineRe.exec(lines[i]))) {
      const name = m[1];
      if (known.has(name) || PY_KEYWORDS.has(name)) continue;
      flag('short-circuit-undefined', i + 1,
        `👻 **Possibly-undefined name \`${name}\` hidden behind \`or\`/\`and\`.** Short-circuit evaluation means this only gets touched at runtime when the left-hand side is falsy/truthy, so a typo or missing definition here is very easy to miss while testing. Make sure \`${name}\` is defined before this line.`);
    }
  }
}

// 17. loop variable read after the loop, but only when it wasn't already defined before the loop
function checkScopeLeak(lines, flag) {
  const forRe = /^(\s*)for\s+([\w, ()]+?)\s+in\b.*:\s*$/;
  for (let i = 0; i < lines.length; i++) {
    const m = forRe.exec(lines[i]);
    if (!m) continue;
    const ind = m[1].length;
    const names = [...m[2].matchAll(/\w+/g)].map((x) => x[0]);

    let end = i;
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === '') { end = j; continue; }
      if (indentOf(lines[j]) <= ind) break;
      end = j;
    }
    if (end === i) continue;

    const before = lines.slice(0, i).join('\n');
    for (const name of names) {
      const definedBefore = new RegExp(`^\\s*${name}\\s*=(?!=)|\\bdef\\s+${name}\\b|\\bfor\\s+${name}\\b|\\bas\\s+${name}\\b`, 'm').test(before);
      if (definedBefore) continue;

      for (let j = end + 1; j < lines.length; j++) {
        const t = lines[j].trim();
        if (t === '') continue;
        if (indentOf(lines[j]) > ind) break;
        if (new RegExp(`\\b${name}\\b`).test(lines[j])) {
          flag('scope-leak', j + 1,
            `🧯 **Loop variable \`${name}\` used after the loop ends.** \`${name}\` only reliably exists if the loop body ran at least once (e.g. the sequence wasn't empty) — relying on it outside the loop is fragile. Initialize \`${name}\` before the loop, or compute what you need differently.`);
        }
        break;
      }
    }
  }
}

/* ================= public API ================= */

const PENALTY = {
  'unbound-local': 15,
  'unhashable-key': 15,
  'is-literal': 15,
  'shadow-builtin': 15,
  'mutable-default': 15,
  'unreachable-code': 6,
  'unsafe-eval': 30,
  'none-compare': 4,
  'short-circuit-undefined': 15,
  'type-compare': 8,
  'implicit-concat': 15,
  'self-append': 15,
  'tuple-list-mutation': 20,
  'string-bool-multiply': 10,
  'mixed-indentation': 0,
  'unsafe-os-system': 0,
  'scope-leak': 10,
};

const LABEL = {
  'unbound-local': 'variable used before assignment',
  'unhashable-key': 'unhashable dict/set key',
  'is-literal': '`is` used on a value instead of an identity',
  'shadow-builtin': 'built-in name shadowed',
  'mutable-default': 'mutable default argument',
  'unreachable-code': 'unreachable code',
  'unsafe-eval': 'unsafe eval/exec',
  'none-compare': '`== None` instead of `is None`',
  'short-circuit-undefined': 'possibly-undefined name after or/and',
  'type-compare': '`type(x) ==` instead of isinstance',
  'implicit-concat': 'missing comma (implicit string concat)',
  'self-append': 'self-referencing list',
  'tuple-list-mutation': 'mutable list inside a tuple mutated',
  'string-bool-multiply': 'string multiplied by bool/negative',
  'mixed-indentation': 'mixed tabs/spaces',
  'unsafe-os-system': 'os.system with dynamic input',
  'scope-leak': 'loop variable used after the loop',
};

function trapFindings(content) {
  const src = String(content).replace(/\r\n/g, '\n');
  const stripped = stripPy(src);
  const lines = stripped.split('\n');
  const orig = src.split('\n');
  const out = [];
  const flag = (rule, line, message, fix) => out.push({ rule, line, message, fix });

  checkUnsafeEval(lines, flag);
  checkNoneCompare(lines, orig, flag);
  checkTypeCompare(lines, flag);
  checkIsLiteral(lines, flag);
  checkShadowBuiltin(lines, flag);
  checkMutableDefault(stripped, flag);
  checkSelfAppend(lines, flag);
  checkStringBoolMultiply(lines, flag);
  checkImplicitConcat(lines, flag);
  checkMixedIndentation(orig, flag);
  checkUnsafeOsSystem(lines, flag);
  checkUnhashableKey(lines, flag);
  checkUnreachableCode(lines, flag);
  checkTupleListMutation(stripped, lines, flag);
  checkUnboundLocal(lines, flag);
  checkShortCircuitUndefined(stripped, lines, flag);
  checkScopeLeak(lines, flag);

  return out;
}

module.exports = { trapFindings, PENALTY, LABEL };
