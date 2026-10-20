import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { fixture, username, vless, application, connected, until } from './helpers/worker-fixture.mjs';
import { nativeLinks } from './helpers/source.mjs';
function ws(f) {
  const listeners = new Map();
  const server = { readyState: 1, accept() {}, send() {},
    addEventListener(k, fn) { listeners.set(k, fn); },
    emit(data) { return listeners.get('message')({ data }); },
    close() { if (this.readyState === 3) return; this.readyState = 3; listeners.get('close')?.(); } };
  f.context.WebSocketPair = class { constructor() { return { 0: {}, 1: server }; } };
  f.context.Response = function(body, init) { return init?.status === 101 ? { status: 101 } : new Response(body, init); };
  return { server, open(data) {
    const headers = { Upgrade: 'websocket' };
    if (data !== undefined) headers['Sec-WebSocket-Protocol'] = typeof data === 'string' ? data : data.toString('base64url');
    return f.context.worker.fetch(new Request(`https://test.invalid/stream/PANEL_ZEUS/${f.uuid.split('-')[4]}`, { headers }), f.env, { waitUntil() {} });
  } };
}
for (const kind of ['vless', 'trojan']) test(`${kind} early data authenticates and writes application bytes once`, async t => {
  const f = fixture(t, { connection_type: kind }), s = ws(f);
  if (kind === 'trojan') {
    const prepare = f.env.DB.prepare;
    f.env.DB.prepare = sql => {
      const query = prepare(sql);
      if (sql.includes('trojan_hash')) query.first = async () => ({ ...f.user, trojan_hash: createHash('sha224').update(f.uuid).digest('hex') });
      return query;
    };
  }
  const packet = kind === 'vless' ? vless(f.uuid) : Buffer.concat([
    Buffer.from(createHash('sha224').update(f.uuid).digest('hex') + '\r\n'),
    Buffer.from([1, 3, 11]), Buffer.from('example.com'), Buffer.from([1, 187, 13, 10]), application]);
  assert.equal((await s.open(packet)).status, 101);
  const socket = await connected(f); assert.equal(socket.uploads.length, 1);
  socket.eof(); s.server.close(); await f.settle();
});
test('early prefix followed by ordinary WS frame stays ordered', async t => {
  const f = fixture(t), s = ws(f), packet = vless(f.uuid);
  assert.equal((await s.open(packet.subarray(0, 10))).status, 101);
  await s.server.emit(packet.subarray(10));
  const socket = await connected(f); socket.eof(); s.server.close();
});
test('ordinary WebSocket clients remain supported', async t => {
  const f = fixture(t), s = ws(f); assert.equal((await s.open()).status, 101);
  await s.server.emit(vless(f.uuid)); const socket = await connected(f); socket.eof(); s.server.close();
});
for (const [label, override, invalid] of [ ['bad UUID', {}, true], ['disabled', { is_active: 0 }], ['quota', { limit_gb: 1, used_gb: 1 }], ['expired', { expiry_days: 1, created_at: '2020-01-01' }] ]) {
  test(`early data cannot bypass ${label}`, async t => {
    const f = fixture(t, override), s = ws(f);
    await s.open(vless(invalid ? randomUUID() : f.uuid));
    await until(() => s.server.readyState === 3, 'Rejected connection is closed');
    assert.equal(f.sockets.length, 0);
  });
}
for (const header of ['invalid,value', '!', 'a', Buffer.alloc(2561).toString('base64url'), 'A'.repeat(9000)]) {
  test(`rejects malformed or oversize early data (${header.length})`, async t => {
    const f = fixture(t), s = ws(f); assert.equal((await s.open(header)).status, 400); assert.equal(f.sockets.length, 0);
  });
}
test('both subscription formats put every Smart node first, then contiguous countries', async t => {
  const f = fixture(t, { connection_type: 'vless,trojan,shadowsocks', port: '443,8443,2096',
    ips: '198.51.100.1\n198.51.100.2', enable_direct: 1,
    user_socks5: JSON.stringify(['DE','US','CA','TR','GB','AE','IR'].map(country => ({ country, proxy: `socks5://${country.toLowerCase()}.invalid:1080` }))) }, { env: { SMART_ROUTING: 'true' } });
  const response = await f.subscription('feed', 'true');
  const links = nativeLinks(Buffer.from(await response.text(), 'base64').toString());
  assert.equal(links.length, 216);
  const labels = links.map(uri => decodeURIComponent(new URL(uri).hash.slice(1)).split(' | ')[1]);
  assert(labels.slice(0, 24).every(x => x.includes('Smart')));
  assert(labels.slice(24).every(x => !x.includes('Smart')));
  const runs = labels.filter((x, i) => i === 0 || x !== labels[i - 1]);
  assert.equal(new Set(runs).size, runs.length, 'Every country has a single contiguous block');
  for (const uri of links) {
    const u = new URL(uri);
    if (['vless:', 'trojan:'].includes(u.protocol)) {
      assert.equal(u.username, f.uuid);
      if (u.searchParams.get('type') === 'ws') assert(u.searchParams.get('path').endsWith('?ed=2560'));
    }
  }
  const yaml = await (await f.subscription('yaml', 'true')).text();
  const blocks = yaml.split('\n\nproxy-groups:')[0].split(/(?=^  - name: )/m).filter(x => x.startsWith('  - name:'));
  assert.equal(blocks.length, 216);
  assert(blocks.slice(0,24).every(x => x.split('\n')[0].includes('Smart')));
  assert(blocks.slice(24).every(x => !x.split('\n')[0].includes('Smart')));
  assert.equal((yaml.match(/max-early-data: 2560/g) || []).length, 108);
});
test('compact and standard exports preserve identity, all routes and account limits without DB writes', async t => {
  const settings = { connection_type: 'vless,trojan,shadowsocks', port: '443,8443,2096',
    ips: '198.51.100.1\n198.51.100.2', enable_direct: 1, limit_gb: 100, expiry_days: 30,
    advanced_frag: 'synthetic', cipher_suites: 'synthetic', tls_mask: 'synthetic', frag_len: '200-3000', frag_int: '1-2',
    user_socks5: JSON.stringify(['DE','US','CA','TR','GB','AE','IR'].map(country => ({ country, proxy: `socks5://${country.toLowerCase()}.invalid:1080` }))) };
  const f = fixture(t, settings, { env: { SMART_ROUTING: 'true' } });
  const baseline = await f.subscription('feed', 'true');
  const response = await f.context.worker.fetch(new Request(`https://test.invalid/feed/${username}?profile=compact&client=standard`), f.env, { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('subscription-userinfo'), baseline.headers.get('subscription-userinfo'));
  const links = nativeLinks(Buffer.from(await response.text(), 'base64').toString());
  assert.equal(links.length, 27);
  const routes = new Set();
  for (const uri of links) {
    const u = new URL(uri); assert.equal(u.protocol, 'vless:'); assert.equal(u.port, '443'); assert.equal(u.username, f.uuid);
    for (const key of ['mask','fm','cs','fragment']) assert.equal(u.searchParams.has(key), false);
    routes.add(decodeURIComponent(uri).match(/\/loc-(auto|\d+)/)?.[1] || 'direct');
  }
  assert.equal(routes.size, 9); assert.equal(f.user.tls_mask, 'synthetic');
  assert.equal(f.writes.filter(x => /^(UPDATE users SET|INSERT INTO users)/i.test(x.sql) && /limit_gb|expiry_days|tls_mask|connection_type|user_socks5/i.test(x.sql)).length, 0);
});
test('compact never enables an account protocol that was disabled', async t => {
  const f = fixture(t, { connection_type: 'trojan', port: '443', ips: '198.51.100.1', enable_direct: 1 });
  const r = await f.context.worker.fetch(new Request(`https://test.invalid/feed/${username}?profile=compact`), f.env, { waitUntil() {} });
  const links = nativeLinks(Buffer.from(await r.text(),'base64').toString());
  assert(links.length > 0); assert(links.every(uri => uri.startsWith('trojan://')));
});
