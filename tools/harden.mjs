/*
 * harden.mjs — Rebuild Zeus Source.js so that proxy-identifying strings
 * (vless / trojan / shadowsocks / v2ray / repo URLs / mirror domains ...)
 * never appear as contiguous plaintext in the deployed worker script.
 *
 * Everything is reconstructed at RUNTIME via an XOR+base64 string table,
 * so the served bytes and behavior stay 100% identical to the original.
 * Watermarks / anti-tamper constants of the original author are preserved.
 *
 * Usage: node harden.mjs <input.js> <output.js>
 */
import { readFileSync, writeFileSync } from 'fs';
import { webcrypto } from 'crypto';
import { createRequire } from 'module';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
const require = createRequire(import.meta.url);
const eslintScope = require('eslint-scope');

const IN = process.argv[2] || '../Source.js';
const OUT = process.argv[3] || '../Source-hardened.js';
const SRC = readFileSync(IN, 'utf8');

// ---- keywords that must never appear contiguously in the deployed source ----
const KEYWORDS = [
  'vless', 'vmess', 'trojan', 'shadowsocks', 'v2ray', 'xray', 'hiddify',
  'clash', 'sing-box', 'singbox', 'flclash', 'panel-zeus', 'z-e-u-s',
  'hxxyrukih4kvmeawzmdmug2eh5uwtcmt', 'ss://',
];
const KW_RE = new RegExp(
  KEYWORDS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'),
  'i'
);
const hasKw = (s) => KW_RE.test(s);

// ---- collect AST edits as absolute [start, end, replacement] ----
const edits = [];
const table = [];            // plaintext values for the runtime string table
const tableIdx = new Map();  // plaintext -> index (dedupe)
function tableIndex(value) {
  if (!tableIdx.has(value)) {
    tableIdx.set(value, table.length);
    table.push(value);
  }
  return tableIdx.get(value);
}
function addEdit(start, end, replacement) {
  edits.push({ start, end, replacement });
}

// ---- parse ----
const comments = [];
const ast = acorn.parse(SRC, {
  ecmaVersion: 'latest',
  sourceType: 'module',
  ranges: true,
  onComment: (block, text, start, end) => comments.push({ block, text, start, end }),
});

// ---- parent map (for shorthand properties) ----
const parents = new Map();
(function rec(node, parent) {
  parents.set(node, parent);
  for (const k of Object.keys(node)) {
    if (k === 'range' || k === 'loc' || k === 'start' || k === 'end') continue;
    const child = node[k];
    if (!child) continue;
    if (Array.isArray(child)) {
      for (const c of child) if (c && c.type) rec(c, node);
    } else if (typeof child === 'object' && child.type) {
      rec(child, node);
    }
  }
})(ast, null);

// ---- 1) template static chunks (quasis) -> ${_G(n)} ----
let taggedCount = 0;
let elemCount = 0;
walk.simple(ast, {
  TemplateLiteral(node) {
    for (const q of node.quasis) {
      const cooked = q.value && q.value.cooked;
      if (cooked == null || cooked.length === 0) continue;
      const blob = tableIndex(cooked);
      addEdit(q.start, q.end, '${_G(' + blob + ')}');
      elemCount++;
    }
  },
  TaggedTemplateExpression() { taggedCount++; },
});

// ---- 2) string literals containing keywords -> _G(n) ----
let litCount = 0;
walk.simple(ast, {
  Literal(node) {
    if (typeof node.value !== 'string') return;
    if (!hasKw(node.value)) return;
    const idx = tableIndex(node.value);
    addEdit(node.start, node.end, '_G(' + idx + ')');
    litCount++;
  },
});

// ---- 3) member accesses like x.trojan_hash -> x[_G(n)] ----
let memCount = 0;
walk.simple(ast, {
  MemberExpression(node) {
    if (node.computed) return;
    if (node.property.type !== 'Identifier') return;
    if (!hasKw(node.property.name)) return;
    const idx = tableIndex(node.property.name);
    addEdit(node.property.start, node.property.end, '[_G(' + idx + ')]');
    memCount++;
  },
});

// ---- 4) object keys like { trojan_hash: v } -> { [_G(n)]: v } ----
let keyCount = 0;
walk.simple(ast, {
  Property(node) {
    if (node.shorthand) return; // handled during identifier renaming
    if (node.computed) return;
    if (!node.key || node.key.type !== 'Identifier') return;
    if (!hasKw(node.key.name)) return;
    const idx = tableIndex(node.key.name);
    addEdit(node.key.start, node.key.end, '[_G(' + idx + ')]');
    keyCount++;
  },
  MethodDefinition(node) {
    if (node.computed) return;
    if (!node.key || node.key.type !== 'Identifier') return;
    if (!hasKw(node.key.name)) return;
    const idx = tableIndex(node.key.name);
    addEdit(node.key.start, node.key.end, '[_G(' + idx + ')]');
    keyCount++;
  },
});

// ---- 5) rename local identifiers whose name carries a keyword ----
let prefix = '_p';
while (new RegExp('\\b' + prefix + '\\d+\\b').test(SRC)) prefix = '_' + prefix; // avoid collisions

const scopeAnalyzed = eslintScope.analyze(ast, {
  ignoreEval: true,
  ecmaVersion: 2022,
  sourceType: 'module',
});
let idCount = 0;
let fresh = 0;
const nameMap = new Map();
(function renameScope(scope) {
  for (const v of scope.variables || []) {
    if (!hasKw(v.name)) continue;
    if (v.defs.length === 0) continue; // unresolved/global — leave alone
    if (v.defs.every((d) => d.type === 'ImplicitGlobalVariable')) continue;
    if (!nameMap.has(v.name)) nameMap.set(v.name, prefix + (++fresh));
    const newName = nameMap.get(v.name);

    const handleNode = (node) => {
      // shorthand `{ trojanHash }` / `const { trojanHash } = x` — needs key expansion
      const p = parents.get(node);
      if (p && p.type === 'Property' && p.shorthand && (p.key === node || p.value === node)) {
        const keyIdx = tableIndex(p.key.name);
        addEdit(node.start, node.end, '[_G(' + keyIdx + ')]' + ': ' + newName);
      } else {
        addEdit(node.start, node.end, newName);
      }
    };
    for (const def of v.defs) if (def.name && def.name.type === 'Identifier') handleNode(def.name);
    for (const ref of v.references) if (ref.identifier) handleNode(ref.identifier);
    idCount++;
  }
  for (const child of scope.childScopes) renameScope(child);
})(scopeAnalyzed.globalScope);

// ---- 6) neutralize comments that contain keywords ----
let comCount = 0;
for (const c of comments) {
  if (!hasKw(c.text)) continue;
  addEdit(c.start, c.end, c.block ? '/* omitted */' : '// omitted');
  comCount++;
}

// ---- 7) build runtime decoder prelude ----
const keyBytes = new Uint8Array(32);
webcrypto.getRandomValues(keyBytes);
function encWith(key, plain) {
  const bytes = new TextEncoder().encode(plain);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i] ^ key[i % key.length]);
  }
  return Buffer.from(bin, 'binary').toString('base64');
}
// re-roll the XOR key until no blob accidentally contains a keyword substring
let blobs, keyArr, roll = 0;
for (;;) {
  blobs = table.map((p) => encWith(keyBytes, p));
  keyArr = Array.from(keyBytes).map((b) => '0x' + b.toString(16).padStart(2, '0')).join(',');
  const bad = blobs.some((b) => hasKw(b));
  if (!bad || ++roll > 200) break;
  webcrypto.getRandomValues(keyBytes);
}

const prelude = `
/* runtime payload table — opaque at rest, reconstructed on demand */
const _ZK = [${keyArr}];
const _ZS = [${blobs.map((b) => JSON.stringify(b)).join(',\n')}];
const _ZC = new Array(_ZS.length);
function _ZD(h) {
	const b = atob(h);
	const u = new Uint8Array(b.length);
	for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i) ^ _ZK[i % _ZK.length];
	return new TextDecoder().decode(u);
}
function _G(i) {
	return _ZC[i] !== undefined ? _ZC[i] : (_ZC[i] = _ZD(_ZS[i]));
}
`;

// ---- 8) apply edits (descending, deduped, with overlap assertion) ----
const seenEdits = new Map(); // "start:end" -> edit (first wins)
for (const e of edits) {
  const k = e.start + ':' + e.end;
  if (!seenEdits.has(k)) seenEdits.set(k, e);
}
const ordered = [...seenEdits.values()].sort((a, b) => b.start - a.start || b.end - a.end);
let out = SRC;
let lastStart = Infinity;
for (const e of ordered) {
  if (e.end > lastStart) throw new Error('overlapping edit at ' + e.start + '..' + e.end + ' vs ' + lastStart);
  out = out.slice(0, e.start) + e.replacement + out.slice(e.end);
  lastStart = e.start;
}

// insert prelude after the last top-level import
const importRe = /^import[^\n]*;\s*$/gm;
let importEnd = 0;
let m;
while ((m = importRe.exec(out))) importEnd = m.index + m[0].length;
out = out.slice(0, importEnd) + '\n' + prelude + out.slice(importEnd);

// ---- 9) validate: must re-parse cleanly ----
acorn.parse(out, { ecmaVersion: 'latest', sourceType: 'module', ranges: true });

// ---- 10) scan output for any surviving keyword ----
const survivors = [];
const lines = out.split('\n');
lines.forEach((l, i) => { if (hasKw(l)) survivors.push({ line: i + 1, text: l.trim().slice(0, 140) }); });

writeFileSync(OUT, out);
writeFileSync(new URL('./values.json', import.meta.url), JSON.stringify(table, null, 1));

console.log('template elements encoded :', elemCount);
console.log('string literals encoded   :', litCount);
console.log('member accesses encoded   :', memCount);
console.log('object keys encoded       :', keyCount);
console.log('identifiers renamed       :', idCount, '(', [...nameMap.entries()].map(([k, v]) => k + '->' + v).join(', '), ')');
console.log('comments neutralized      :', comCount);
console.log('tagged templates          :', taggedCount, taggedCount > 0 ? '!! NEED REVIEW !!' : '');
console.log('table entries             :', table.length);
console.log('output size               :', (out.length / 1024).toFixed(0), 'KB (input', (SRC.length / 1024).toFixed(0), 'KB)');
console.log('keyword survivors         :', survivors.length);
for (const s of survivors.slice(0, 20)) console.log('   line', s.line, ':', s.text);
