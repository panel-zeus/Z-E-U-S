// Smart routing through the full Worker, without external network access.
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { nativeLinks } from './helpers/source.mjs';
import { fixture, username, application, downstream, until, grpcHunk, decodeGrpc } from './helpers/worker-fixture.mjs';

const countries = ['IR', 'AE', 'CA', 'US', 'DE', 'TR', 'GB'];
const configuredExits = countries.map(country => ({ country, proxy: `socks5://synthetic-${country.toLowerCase()}.invalid:1080` }));
const userSettings = {
  connection_type: 'vless,trojan,shadowsocks', port: '443,8443,2096', ips: '198.51.100.10',
  user_socks5: JSON.stringify(configuredExits), enable_direct: 1, auto_rotate_ip: 0,
};
const smartOptions = { env: { SMART_ROUTING: 'true', HTTP_TRANSPORTS: 'true' } };
function packet(uuid, hostname, payload = application) {
  const target = Buffer.from(hostname);
  return Buffer.concat([Buffer.from([0]), Buffer.from(uuid.replaceAll('-', ''), 'hex'),
    Buffer.from([0, 1, 1, 187, 2, target.length]), target, payload]);
}
const route = (f, location = 'auto', kind = 'xhttp') => `/stream/PANEL_ZEUS/${f.uuid.split('-')[4]}/${kind}/loc-${location}${kind === 'grpc' ? '/Tun' : ''}`;
function proxyMocks(f, { failAll = false, failFirst = false, waitForOpen = false, failLaterWrite = false } = {}) {
  const attempts = [], direct = [];
  f.context.connectDirect = async (...args) => { direct.push(args); throw new Error('Direct fallback forbidden in Smart tests'); };
  f.context.connectProxy = async (proxy, address, port, initialData, signal) => {
    attempts.push({ proxy, address, port, initialData, signal });
    assert.equal(initialData, null, 'Handshake selection receives no application payload');
    if (failAll || (failFirst && attempts.length === 1)) throw new Error('Synthetic proxy handshake failure');
    const socket = f.context.connect({ hostname: address, port });
    if (failLaterWrite) socket.writable = new WritableStream({ write(bytes) {
      if (socket.uploads.length > 0) throw new Error('Synthetic write failure after initial application data');
      socket.uploads.push(Buffer.from(bytes));
    } });
    socket.selectedProxy = proxy;
    if (waitForOpen) await socket.opened;
    return socket;
  };
  return { attempts, direct };
}
async function finishResponse(f, session, kind = 'xhttp') {
  const response = await session.response;
  assert.equal(response.status, 200);
  await until(() => f.sockets.length > 0 && f.sockets[0].uploads.length > 0, 'Selected exit receives application payload');
  const socket = f.sockets[0], result = response.arrayBuffer();
  socket.reply(downstream); socket.eof();
  const output = Buffer.from(await result);
  assert.deepEqual(kind === 'grpc' ? decodeGrpc(output) : output, Buffer.concat([Buffer.from([0, 0]), downstream]));
  await f.settle();
  return socket;
}
async function feed(f) {
  const response = await f.subscription('feed', 'true'); assert.equal(response.status, 200);
  return nativeLinks(Buffer.from(await response.text(), 'base64').toString('utf8'));
}
function yamlParts(text) {
  const proxies = /\nproxies:\n([\s\S]*?)\n\nproxy-groups:\n/.exec(text);
  const groups = /\n\nproxy-groups:\n([\s\S]*?)\nrules:\n/.exec(text);
  assert(proxies && groups);
  return { proxies: proxies[1].split(/(?=^  - name: )/m).filter(block => block.startsWith('  - name: ')).map(block => block.trimEnd()), groups: groups[1] };
}
async function yaml(f) {
  const response = await f.subscription('yaml', 'true'); assert.equal(response.status, 200);
  return yamlParts(await response.text());
}
function smartUri(uri) {
  const params = new URL(uri).searchParams;
  return ['path', 'serviceName', 'plugin'].some(key => params.get(key)?.includes('/loc-auto'));
}

for (const flag of [undefined, true, 'true']) {
  test(`status-page embedded export matches subscription feature flags: ${JSON.stringify(flag)}`, async t => {
    const f = fixture(t, userSettings, { env: { SMART_ROUTING: flag, HTTP_TRANSPORTS: flag } });
    const feedResponse = await f.subscription('feed', flag);
    assert.equal(feedResponse.status, 200);
    const expected = nativeLinks(Buffer.from(await feedResponse.text(), 'base64').toString('utf8'));
    const statusResponse = await f.subscription('status', flag);
    assert.equal(statusResponse.status, 200);
    assert.match(statusResponse.headers.get('Content-Type'), /^text\/html/);
    const html = await statusResponse.text();
    const hidden = /<!-- HIDDEN_CONFIGS -->\s*<div[^>]*>\s*([\s\S]*?)\s*<\/div>/.exec(html);
    assert(hidden, 'Status-page export contains subscription links');
    assert.deepEqual(nativeLinks(hidden[1]), expected, 'Embedded export preserves all enabled connection profiles');
    assert.equal(expected.some(smartUri), flag !== undefined);
    assert.equal(expected.some(uri => new URL(uri).searchParams.get('type') === 'xhttp'), flag !== undefined);
  });
}

test('Smart WebSocket close interrupts a pending initial upload and cleans accounting without replay', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, smartOptions);
  const listeners = new Map(), client = {};
  const server = {
    readyState: 1,
    accept() {},
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(callback);
    },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    emit(type, event = {}) { return Promise.all([...listeners.get(type) || []].map(callback => callback(event))); },
    send() {},
    close() {
      if (this.readyState === 3) return;
      this.readyState = 3;
      void this.emit('close');
    },
  };
  f.context.WebSocketPair = class { constructor() { return { 0: client, 1: server }; } };
  f.context.Response = function (body, init) {
    return init?.status === 101 ? { status: 101, webSocket: init.webSocket } : new Response(body, init);
  };
  const attempts = [];
  let socket, rejectWrite, messageTask;
  f.context.connectProxy = async (proxy, address, port, initialData) => {
    attempts.push(proxy);
    assert.equal(initialData, null, 'Smart selection never supplies application bytes to a handshake');
    socket = f.context.connect({ hostname: address, port });
    socket.writable = new WritableStream({ write(bytes) {
      socket.uploads.push(Buffer.from(bytes));
      return new Promise((resolve, reject) => { rejectWrite = reject; });
    } });
    const close = socket.close.bind(socket);
    socket.close = () => { close(); rejectWrite?.(new Error('Synthetic TCP closed during write')); };
    return socket;
  };
  t.after(async () => { socket?.close(); await messageTask; });
  const response = await f.context.worker.fetch(new Request(
    `https://test.invalid/stream/PANEL_ZEUS/${f.uuid.split('-')[4]}/loc-auto`,
    { headers: { Upgrade: 'websocket' } }), f.env, { waitUntil() {} });
  assert.equal(response.status, 101);
  assert.equal(response.webSocket, client);
  messageTask = server.emit('message', { data: packet(f.uuid, 'chatgpt.com') });
  await until(() => rejectWrite !== undefined, 'First application write is still awaiting upstream progress');
  assert.equal(f.state.active.get(username), 1);
  server.close();
  assert(socket.closeCount > 0, 'Client close interrupts the selected TCP socket before its write settles');
  await messageTask;
  await f.settle();
  assert.equal(f.state.active.get(username) || 0, 0);
  assert.equal(f.state.activeIPs.get(username)?.size || 0, 0);
  assert.equal(attempts.length, 1, 'A cancelled application write never triggers another handshake');
  assert.deepEqual(socket.uploads, [application], 'Initial application bytes are attempted once');
});

test('Smart flag adds exactly12 native URI nodes and preserves all96 manual URI strings', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, { env: { HTTP_TRANSPORTS: 'true' } });
  const original = await feed(f);
  assert.equal(original.length, 96);
  assert.equal(original.filter(smartUri).length, 0);
  f.env.SMART_ROUTING = 'true';
  const enabled = await feed(f), smart = enabled.filter(smartUri), manual = enabled.filter(uri => !smartUri(uri));
  assert.equal(enabled.length, 108);
  assert.equal(new Set(enabled).size, 108, 'Every native URI is unique');
  assert.equal(smart.length, 12);
  assert.deepEqual(manual, original, 'Manual URI values and relative ordering remain unchanged');
  assert(smart.every(uri => decodeURIComponent(new URL(uri).hash.slice(1)).includes('Smart')));
  f.env.SMART_ROUTING = 'false';
  assert.deepEqual(await feed(f), original, 'Disabling the flag removes only Smart entries');
  assert.equal(f.sockets.length, 0);
});

test('Smart flag adds12 unique YAML nodes and preserves all96 manual YAML blocks and names', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, { env: { HTTP_TRANSPORTS: 'true' } });
  const original = await yaml(f);
  assert.equal(original.proxies.length, 96);
  f.env.SMART_ROUTING = 'true';
  const enabled = await yaml(f);
  assert.equal(enabled.proxies.length, 108);
  const names = enabled.proxies.map(block => /^  - name: "(.+)"$/m.exec(block)?.[1]);
  assert.equal(new Set(names).size, 108);
  const manual = enabled.proxies.filter(block => !block.includes('/loc-auto'));
  const smart = enabled.proxies.filter(block => block.includes('/loc-auto'));
  assert.equal(smart.length, 12);
  assert.deepEqual(manual, original.proxies, 'Every preexisting manual name and configuration remains identical');
  const smartNames = smart.map(block => /^  - name: "(.+)"$/m.exec(block)[1]);
  assert(smartNames.every(name => enabled.groups.includes('      - "' + name + '"')));
  f.env.SMART_ROUTING = 'false';
  assert.deepEqual((await yaml(f)).proxies, original.proxies);
});

test('disabled Smart flag rejects loc-auto before user authentication or outbound connection', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, { env: { HTTP_TRANSPORTS: 'true', SMART_ROUTING: 'false' } }), mocks = proxyMocks(f);
  const session = await f.open('xhttp', { route: route(f) });
  assert.equal((await session.response).status, 404);
  assert.equal(mocks.attempts.length, 0); assert.equal(mocks.direct.length, 0);
  assert(!f.queries.some(query => query.sql.includes('FROM users WHERE uuid')));
});

for (const [destination, country, kind] of [['portal.example.ir', 'IR', 'xhttp'], ['chatgpt.com', 'US', 'xhttp'], ['chatgpt.com', 'US', 'grpc']]) {
  test(`authenticated Smart ${kind} ${destination} selects ${country}`, { timeout: 5000 }, async t => {
    const f = fixture(t, userSettings, smartOptions), mocks = proxyMocks(f);
    const session = await f.open(kind, { route: route(f, 'auto', kind) });
    const input = packet(f.uuid, destination);
    session.send(kind === 'grpc' ? grpcHunk(input) : input);
    const socket = await finishResponse(f, session, kind);
    assert.equal(mocks.attempts.length, 1);
    assert.equal(mocks.attempts[0].proxy, configuredExits.find(item => item.country === country).proxy);
    assert.equal(mocks.attempts[0].address, destination); assert.equal(mocks.attempts[0].port, 443);
    assert(mocks.attempts[0].signal instanceof AbortSignal);
    assert.deepEqual(Buffer.concat(socket.uploads), application);
    assert.equal(mocks.direct.length, 0);
  });
}

test('manual loc-index remains authoritative even with Smart enabled', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, smartOptions), mocks = proxyMocks(f);
  const session = await f.open('xhttp', { route: route(f, '3') });
  session.send(packet(f.uuid, 'portal.example.ir'));
  await finishResponse(f, session);
  assert.equal(mocks.attempts.length, 1);
  assert.equal(mocks.attempts[0].proxy, configuredExits[3].proxy, 'The explicit US exit stays selected for an Iran destination');
  assert.equal(mocks.direct.length, 0);
});

test('Smart handshake failure tries the next ranked exit and sends application bytes exactly once', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, smartOptions), mocks = proxyMocks(f, { failFirst: true });
  const session = await f.open('xhttp', { route: route(f) });
  session.send(packet(f.uuid, 'portal.example.ir'));
  const socket = await finishResponse(f, session);
  assert.deepEqual(mocks.attempts.map(attempt => attempt.proxy), [configuredExits[0].proxy, configuredExits[5].proxy]);
  assert.equal(f.sockets.length, 1);
  assert.equal(socket.uploads.length, 1); assert.deepEqual(socket.uploads[0], application);
  assert.equal(mocks.direct.length, 0);
});

test('failure of every attempted Smart exit closes the response without direct fallback or payload replay', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, smartOptions), mocks = proxyMocks(f, { failAll: true });
  const session = await f.open('xhttp', { route: route(f) });
  session.send(packet(f.uuid, 'portal.example.ir'));
  const response = await session.response;
  assert.equal(response.status, 200);
  await response.arrayBuffer().catch(() => {}); await f.settle();
  assert.equal(mocks.attempts.length, 3, 'Smart attempts are bounded');
  assert.equal(f.sockets.length, 0); assert.equal(mocks.direct.length, 0);
  assert.equal(f.state.active.size, 0);
});

test('Smart write failure after initial application bytes closes instead of reconnecting or replaying', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, smartOptions), mocks = proxyMocks(f, { failLaterWrite: true });
  const session = await f.open('xhttp', { route: route(f) });
  session.send(packet(f.uuid, 'chatgpt.com'));
  const response = await session.response;
  assert.equal(response.status, 200);
  await until(() => f.sockets.length === 1 && f.sockets[0].uploads.length === 1, 'Initial application bytes are written');
  assert.deepEqual(f.sockets[0].uploads[0], application);
  session.send(Buffer.from('a later application message that must never be replayed'));
  await until(() => mocks.attempts.length > 1 || f.state.active.size === 0, 'Write failure either closes or incorrectly reconnects');
  assert.equal(mocks.attempts.length, 1, 'No new proxy handshake after application bytes were already sent');
  await response.arrayBuffer().catch(() => {}); await f.settle();
  assert.equal(f.sockets.length, 1);
  assert.equal(f.sockets[0].uploads.length, 1);
  assert(f.sockets[0].closeCount > 0);
  assert.equal(f.state.active.size, 0); assert.equal(mocks.direct.length, 0);
});

for (const [label, overrides, invalidUuid] of [
  ['invalid UUID', {}, true], ['disabled user', { is_active: 0 }, false],
  ['traffic quota', { limit_gb: 1, used_gb: 1 }, false], ['request quota', { limit_req: 1, used_req: 1 }, false],
]) {
  test(`Smart ${label} rejection opens no outbound route`, { timeout: 5000 }, async t => {
    const f = fixture(t, { ...userSettings, ...overrides }, smartOptions), mocks = proxyMocks(f);
    const session = await f.open('xhttp', { route: route(f) });
    const credential = invalidUuid ? randomUUID().slice(0, 24) + f.uuid.slice(24) : f.uuid;
    session.send(packet(credential, 'chatgpt.com')); session.end();
    assert.equal((await session.response).status, 403);
    assert.equal(mocks.attempts.length, 0); assert.equal(mocks.direct.length, 0); assert.equal(f.sockets.length, 0);
  });
}

test('late cancellation aborts the selected Smart handshake, closes its eventual socket and sends no application bytes', { timeout: 5000 }, async t => {
  const f = fixture(t, userSettings, { ...smartOptions, deferConnect: true }), mocks = proxyMocks(f, { waitForOpen: true });
  const session = await f.open('xhttp', { route: route(f) });
  session.send(packet(f.uuid, 'chatgpt.com'));
  const response = await session.response;
  assert.equal(response.status, 200);
  await until(() => f.sockets.length === 1, 'Selected Smart socket is pending');
  const socket = f.sockets[0];
  await response.body.cancel();
  assert.equal(mocks.attempts[0].signal.aborted, true);
  socket.completeOpen();
  await until(() => socket.closeCount > 0, 'Late selected socket is closed'); await f.settle();
  assert.equal(socket.uploads.length, 0); assert.equal(mocks.attempts.length, 1); assert.equal(mocks.direct.length, 0);
  assert.equal(f.state.active.size, 0); assert.equal(f.state.activeHttp(), 0);
});
