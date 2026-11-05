import fs from 'node:fs';
import assert from 'node:assert/strict';

export const source = fs.readFileSync(new URL('../../Source.js', import.meta.url), 'utf8');

// Execute the production definitions without maintaining a second implementation.
export function section(start, end, text = source) {
  const first = text.indexOf(start);
  const last = text.indexOf(end, first + start.length);
  assert(first >= 0 && last > first, `Production source section exists: ${start}`);
  return text.slice(first, last);
}

export function nativeLinks(text) {
  return text.split('\n').filter(line => /^(vless|trojan|ss):\/\//.test(line))
    .filter(line => new URL(line).hostname !== '0.0.0.0');
}
