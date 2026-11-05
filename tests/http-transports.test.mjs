// Exercise the production Worker with synthetic D1, sockets and credentials.
import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { nativeLinks } from './helpers/source.mjs';
import { fixture, username, application, downstream, tick, until, vless, grpcHunk, decodeGrpc, connected } from './helpers/worker-fixture.mjs';

for (const flag of [undefined, false, 'false', '', 'TRUE']) {
  test(`HTTP ingress requires explicit opt-in: ${JSON.stringify(flag)}`, async t => {
    const f = fixture(t, {}, { env: { HTTP_TRANSPORTS: flag } });
    for (const kind of ['xhttp', 'grpc']) {
      const session = await f.open(kind);
      assert.equal((await session.response).status, 404);
    }
    assert.equal(f.sockets.length, 0);
    assert(!f.queries.some(query => query.sql.includes('FROM users WHERE uuid')));
  });
}

for (const kind of ['xhttp', 'grpc']) {
  test(`${kind}: fragmented VLESS authenticates, emits correct downstream framing, preserves accounting`, { timeout: 5000 }, async t => {
    const f = fixture(t), session = await f.open(kind);
    const packet = vless(f.uuid), encoded = kind === 'grpc' ? grpcHunk(packet) : packet;
    for (const byte of encoded) session.send(Buffer.from([byte]));
    const response = await session.response;
    assert.equal(response.status, 200);
    const socket = await connected(f);
    const result = response.arrayBuffer();
    socket.reply(downstream); socket.eof();
    const output = Buffer.from(await result);
    assert.deepEqual(kind === 'grpc' ? decodeGrpc(output) : output, Buffer.concat([Buffer.from([0, 0]), downstream]));
    await f.settle();
    assert.equal(f.state.active.size, 0, 'Connection count is released on destination EOF');
    assert.equal(f.state.activeIPs.size, 0);
    assert.equal(f.state.traffic.get(username), packet.length + downstream.length, 'Account raw VLESS/TCP bytes, excluding HTTP/gRPC envelopes');
    assert.equal(f.state.requests.get(username), 1);
    assert.equal(f.writes.filter(q => q.sql.startsWith('UPDATE users SET used_gb = used_gb +')).length, 0,
      'Small connection uses existing cache/write thresholds');
  });
}

test('XHTTP path treats application/grpc content type as raw bytes', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open('xhttp', { contentType: 'application/grpc' });
  session.send(vless(f.uuid));
  const response = await session.response;
  assert.equal(response.status, 200);
  const socket = await connected(f), result = response.arrayBuffer();
  socket.reply(downstream); socket.eof();
  assert.deepEqual(Buffer.from(await result), Buffer.concat([Buffer.from([0, 0]), downstream]));
});

for (const contentType of ['application/grpc+proto', 'application/grpc-web', 'application/grpc-web+proto']) {
  for (const kind of ['grpc', 'xhttp']) {
    test(`${kind}: binary MIME ${contentType} retains route-defined framing`, { timeout: 5000 }, async t => {
      const f = fixture(t), session = await f.open(kind, { contentType });
      const packet = vless(f.uuid);
      session.send(kind === 'grpc' ? grpcHunk(packet) : packet);
      const response = await session.response;
      assert.equal(response.status, 200);
      const socket = await connected(f), result = response.arrayBuffer();
      socket.reply(downstream); socket.eof();
      const bytes = Buffer.from(await result);
      assert.deepEqual(kind === 'grpc' ? decodeGrpc(bytes) : bytes, Buffer.concat([Buffer.from([0, 0]), downstream]));
    });
  }
}

for (const contentType of ['application/grpc-web-text', 'application/json']) {
  for (const kind of ['grpc', 'xhttp']) {
    test(`${kind}: unsupported MIME ${contentType} is rejected before authentication`, { timeout: 5000 }, async t => {
      const f = fixture(t), session = await f.open(kind, { contentType });
      const response = await session.response;
      assert.equal(response.status, 415);
      assert.equal(f.sockets.length, 0);
      assert(!f.queries.some(query => query.sql.includes('FROM users WHERE uuid')));
      assert.equal(f.state.activeHttp(), 0);
    });
  }
}

for (const [label, overrides, options, wrongUUID] of [
  ['unknown UUID', {}, {}, true],
  ['disabled user', { is_active: 0 }, {}, false],
  ['exhausted traffic', { limit_gb: 1, used_gb: 1 }, {}, false],
  ['exhausted request quota', { limit_req: 1, used_req: 1 }, {}, false],
  ['expired user', { expiry_days: 1, created_at: Date.now() - 172800000 }, {}, false],
  ['VLESS disabled', { connection_type: 'trojan' }, {}, false],
  ['D1 authentication failure', {}, { failUserRead: true }, false],
]) {
  test(`HTTP bridge fails closed for ${label}`, { timeout: 5000 }, async t => {
    const f = fixture(t, overrides, options), session = await f.open();
    const credential = wrongUUID ? randomUUID().slice(0, 24) + f.uuid.slice(24) : f.uuid;
    session.send(vless(credential)); session.end();
    const response = await session.response;
    assert.equal(response.status, 403, 'Generic rejection does not reveal account existence or limits');
    await response.arrayBuffer();
    await f.settle();
    assert.equal(f.sockets.length, 0, 'Authentication/account eligibility precedes outbound connection');
    assert.equal(f.state.active.size, 0);
  });
}

for (const failedWrite of [false, true]) {
  test(`existing close-time accounting ${failedWrite ? 'restores cached bytes on write failure' : 'commits both traffic and request count'}`, { timeout: 5000 }, async t => {
    const f = fixture(t, {}, { failAccounting: failedWrite }), session = await f.open();
    const packet = vless(f.uuid); session.send(packet);
    const response = await session.response;
    const socket = await connected(f), result = response.arrayBuffer();
    socket.reply(downstream);
    await until(() => f.state.traffic.get(username) === packet.length + downstream.length, 'Bytes reach accounting cache');
    f.state.lastWrite.set(username, 0);
    socket.eof(); await result; await f.settle();
    const committed = f.writes.filter(q => q.sql.startsWith('UPDATE users SET used_gb = used_gb +'));
    assert.equal(committed.length, 1);
    assert.equal(committed[0].args[0] * 1024 ** 3, packet.length + downstream.length);
    assert.equal(committed[0].args[1], committed[0].args[0], 'Lifetime usage increments together');
    assert.equal(committed[0].args[2], 1);
    assert.equal(committed[0].args[4], username);
    assert.equal(f.state.traffic.get(username), failedWrite ? packet.length + downstream.length : 0);
    assert.equal(f.state.requests.get(username), failedWrite ? 1 : 0);
    assert(!f.state.locks.get(username), 'Accounting lock is released');
  });
}

test('response cancellation closes remote socket and releases active state', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open(); session.send(vless(f.uuid));
  const response = await session.response;
  const socket = await connected(f);
  await response.body.cancel(); await f.settle();
  assert(socket.closeCount > 0, 'Client cancellation must close TCP');
  assert.equal(f.state.active.size, 0);
  assert.equal(f.state.activeIPs.size, 0);
});

test('cancellation before TCP open sends no application bytes when open later completes', { timeout: 5000 }, async t => {
  const f = fixture(t, {}, { deferConnect: true }), session = await f.open();
  session.send(vless(f.uuid));
  const response = await session.response;
  assert.equal(response.status, 200, 'Authentication completes independently of TCP open');
  await until(() => f.sockets.length === 1, 'TCP connection is pending');
  const socket = f.sockets[0];
  assert.equal(socket.uploads.length, 0);
  await response.body.cancel();
  socket.completeOpen();
  await until(() => socket.closeCount > 0, 'Late-open TCP connection is closed after cancellation');
  await f.settle();
  assert.equal(socket.uploads.length, 0, 'No initial application payload may be sent after cancellation');
  assert.equal(f.state.active.size, 0);
  assert.equal(f.state.activeIPs.size, 0);
  assert.equal(f.state.activeHttp(), 0);
});

test('malformed compressed gRPC frame fails closed', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open('grpc');
  const frame = grpcHunk(vless(f.uuid)); frame[0] = 1; session.send(frame); session.end();
  const response = await session.response;
  assert.equal(response.status, 400);
  await response.arrayBuffer(); await f.settle();
  assert.equal(f.sockets.length, 0);
  assert.equal(f.state.active.size, 0);
});

test('request EOF preserves downstream until remote completion', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open();
  session.send(vless(f.uuid)); session.end();
  const response = await session.response, socket = await connected(f);
  await f.settle();
  assert.equal(socket.closeCount, 0, 'Upload EOF alone must not close the downstream');
  const result = response.arrayBuffer(); socket.reply(downstream); socket.eof();
  assert.deepEqual(Buffer.from(await result), Buffer.concat([Buffer.from([0, 0]), downstream]));
});

test('request abort closes TCP and removes active state', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open(); session.send(vless(f.uuid));
  const response = await session.response, socket = await connected(f);
  const result = response.arrayBuffer().catch(() => null);
  session.abort(); await result; await f.settle();
  assert(socket.closeCount > 0);
  assert.equal(f.state.active.size, 0);
});

test('declared gRPC message above 1 MiB is rejected before payload allocation or authentication', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open('grpc'), header = Buffer.alloc(5);
  header.writeUInt32BE(1024 * 1024 + 1, 1); session.send(header); session.end();
  const response = await session.response;
  assert.equal(response.status, 400); await response.arrayBuffer(); await f.settle();
  assert.equal(f.sockets.length, 0);
  assert(!f.queries.some(query => query.sql.includes('FROM users WHERE uuid')));
});

for (const cut of [1, 4, 5, 7]) {
  test(`truncated gRPC framing at byte ${cut} is rejected on upload EOF`, { timeout: 5000 }, async t => {
    const f = fixture(t), session = await f.open('grpc');
    session.send(grpcHunk(vless(f.uuid)).subarray(0, cut)); session.end();
    const response = await session.response;
    assert.equal(response.status, 400); await response.arrayBuffer(); await f.settle();
    assert.equal(f.sockets.length, 0);
  });
}

test('malformed protobuf length cannot carry VLESS outside its field boundary', { timeout: 5000 }, async t => {
  const f = fixture(t), session = await f.open('grpc'), frame = grpcHunk(vless(f.uuid));
  frame[6] = 1;
  session.send(frame); session.end();
  const response = await session.response;
  assert.equal(response.status, 400); await response.arrayBuffer(); await f.settle();
  assert.equal(f.sockets.length, 0);
});

for (const kind of ['xhttp', 'grpc']) {
  test(`${kind}: one large initial upload chunk cannot trip the VLESS header limit`, { timeout: 5000 }, async t => {
    const f = fixture(t), session = await f.open(kind), large = Buffer.alloc(256 * 1024, 0x57);
    const packet = vless(f.uuid, large);
    session.send(kind === 'grpc' ? grpcHunk(packet) : packet);
    const response = await session.response;
    assert.equal(response.status, 200);
    const socket = await connected(f, large), result = response.arrayBuffer();
    socket.reply(downstream); socket.eof();
    const output = Buffer.from(await result);
    assert.deepEqual(kind === 'grpc' ? decodeGrpc(output) : output, Buffer.concat([Buffer.from([0, 0]), downstream]));
    await f.settle();
    assert.equal(f.state.traffic.get(username), packet.length + downstream.length);
  });
}

function isolatedAdapter(f, grpc = false) {
  const request = new Request('https://test.invalid/offline-adapter', {
    method: 'POST', body: new ReadableStream(), duplex: 'half',
  });
  return f.context.createZeusHttpTransport(request, grpc);
}

test('HTTP output applies awaited backpressure and emits chunks bounded at 64 KiB', { timeout: 5000 }, async t => {
  const f = fixture(t), adapter = isolatedAdapter(f);
  t.after(() => adapter.socket.close());
  adapter.authenticated();
  const response = await adapter.response(), sent = Buffer.alloc(192 * 1024, 0x67);
  let released = false;
  const write = adapter.socket.send(sent).then(() => { released = true; });
  await tick();
  assert.equal(released, false, 'Sender waits above the 128 KiB output watermark');
  assert.equal(adapter.socket.bufferedAmount, sent.length);
  const reader = response.body.getReader(), chunks = [];
  for (let i = 0; i < 3; i++) {
    const { value, done } = await reader.read();
    assert.equal(done, false); assert(value.byteLength <= 64 * 1024); chunks.push(Buffer.from(value));
  }
  await write;
  assert.equal(adapter.socket.bufferedAmount, 0);
  assert.deepEqual(Buffer.concat(chunks), sent);
  await reader.cancel();
  assert.equal(f.state.activeHttp(), 0);
});

test('HTTP output overflow rejects synchronously and releases its capacity slot', { timeout: 5000 }, async t => {
  const f = fixture(t), adapter = isolatedAdapter(f);
  assert.equal(f.state.activeHttp(), 1);
  assert.throws(() => adapter.socket.send(new Uint8Array(2 * 1024 * 1024 + 1)), /queue limit/);
  assert.equal(adapter.socket.readyState, 3);
  assert.equal(adapter.socket.bufferedAmount, 0);
  assert.equal(f.state.activeHttp(), 0);
  assert.equal((await adapter.response()).status, 503);
});

test('normal HTTP close retains its capacity slot until all queued response bytes drain', { timeout: 5000 }, async t => {
  const f = fixture(t), adapter = isolatedAdapter(f), sent = Buffer.alloc(96 * 1024, 0x73);
  adapter.authenticated();
  const response = await adapter.response();
  t.after(() => response.body.cancel().catch(() => {}));
  await adapter.socket.send(sent);
  adapter.socket.close();
  assert.equal(adapter.socket.readyState, 3);
  assert.equal(adapter.socket.bufferedAmount, sent.length);
  assert.equal(f.state.activeHttp(), 1, 'An unread closed response still consumes capacity');
  const reader = response.body.getReader();
  const first = await reader.read();
  assert.equal(first.done, false);
  assert.equal(first.value.byteLength, 64 * 1024);
  assert.equal(adapter.socket.bufferedAmount, 32 * 1024);
  assert.equal(f.state.activeHttp(), 1, 'Partial consumption must not release capacity');
  const second = await reader.read();
  assert.equal(second.done, false);
  assert.deepEqual(Buffer.concat([Buffer.from(first.value), Buffer.from(second.value)]), sent);
  assert.equal(adapter.socket.bufferedAmount, 0);
  assert.equal(f.state.activeHttp(), 0, 'Final drain releases exactly one slot');
  assert.equal((await reader.read()).done, true);
  reader.releaseLock();
  adapter.socket.close();
  assert.equal(f.state.activeHttp(), 0, 'Repeated close cannot release capacity twice');
});

test('late response cancellation after normal HTTP close discards the queue and releases capacity', { timeout: 5000 }, async t => {
  const f = fixture(t), adapter = isolatedAdapter(f);
  adapter.authenticated();
  const response = await adapter.response();
  await adapter.socket.send(Buffer.alloc(96 * 1024, 0x75));
  adapter.socket.close();
  assert.equal(adapter.socket.readyState, 3);
  assert.equal(f.state.activeHttp(), 1);
  assert.equal(adapter.socket.bufferedAmount, 96 * 1024);
  await response.body.cancel();
  assert.equal(adapter.socket.bufferedAmount, 0, 'Cancellation drops retained response bytes');
  assert.equal(f.state.activeHttp(), 0);
  await response.body.cancel();
  adapter.socket.close();
  assert.equal(f.state.activeHttp(), 0, 'Late cancellation is idempotent');
});

test('HTTP capacity cap rejects a seventeenth tunnel before opening TCP', { timeout: 5000 }, async t => {
  const f = fixture(t), adapters = Array.from({ length: 16 }, () => isolatedAdapter(f));
  t.after(() => adapters.forEach(adapter => adapter.socket.close()));
  assert.equal(f.state.activeHttp(), 16);
  const session = await f.open();
  assert.equal((await session.response).status, 503);
  assert.equal(f.sockets.length, 0);
  adapters.forEach(adapter => adapter.socket.close());
  assert.equal(f.state.activeHttp(), 0);
});

const subscriptionUser = {
  connection_type: 'vless,trojan,shadowsocks',
  port: '443,8443,2096', ips: '198.51.100.10\n198.51.100.11',
  enable_direct: 1, auto_rotate_ip: 0,
  user_socks5: JSON.stringify([
    { proxy: 'socks5://synthetic-de.invalid:1080', country: 'DE' },
    { proxy: 'https://synthetic-ir.invalid:443/relay', country: 'IR' },
  ]),
};
const testCountries = [{ flag: '🇩🇪', suffix: '/loc-0' }, { flag: '🇮🇷', suffix: '/loc-1' }, { flag: '🌐', suffix: '' }];
async function nativeFeed(f, flag) {
  const response = await f.subscription('feed', flag);
  assert.equal(response.status, 200);
  return nativeLinks(Buffer.from(await response.text(), 'base64').toString('utf8'));
}
function yamlSections(text) {
  const proxies = /\nproxies:\n([\s\S]*?)\n\nproxy-groups:\n/.exec(text);
  const groups = /\n\nproxy-groups:\n([\s\S]*?)\nrules:\n/.exec(text);
  assert(proxies && groups, 'Generated YAML contains native proxies and group sections');
  const entries = section => section.split(/(?=^  - name: )/m).filter(part => part.startsWith('  - name: ')).map(block => block.trimEnd())
    .map(block => ({ name: /^  - name: "(.+)"$/m.exec(block)?.[1], block,
      field(key) { return new RegExp('^    ' + key + ': (.*)$', 'm').exec(block)?.[1]; },
    }));
  return { proxies: entries(proxies[1]), groups: entries(groups[1]) };
}
async function nativeYaml(f, flag) {
  const response = await f.subscription('yaml', flag);
  assert.equal(response.status, 200);
  return yamlSections(await response.text());
}

test('native subscription routes keep HTTP additions disabled by default and for non-true flags', { timeout: 5000 }, async t => {
  const f = fixture(t, subscriptionUser), feed = await nativeFeed(f), yaml = await nativeYaml(f);
  assert.equal(feed.length, 54);
  assert.equal(yaml.proxies.length, 54);
  for (const flag of ['false', '', 'TRUE', false]) {
    assert.deepEqual(await nativeFeed(f, flag), feed, `Flag ${JSON.stringify(flag)} must not opt in`);
    assert.deepEqual((await nativeYaml(f, flag)).proxies.map(node => node.block), yaml.proxies.map(node => node.block));
  }
  assert(feed.every(link => new URL(link).searchParams.get('type') === 'ws' || link.startsWith('ss:')));
  assert.equal(f.sockets.length, 0, 'Predeclared countries do not require network lookup');
  assert.deepEqual(await nativeFeed(f, true), await nativeFeed(f, 'true'), 'Both explicit supported true values opt in');
});

test('native feed appends HTTP nodes with verified TLS, matching country routes, and original WS entries intact', { timeout: 5000 }, async t => {
  const f = fixture(t, subscriptionUser), baseline = await nativeFeed(f), enabled = await nativeFeed(f, 'true');
  assert.equal(enabled.length, 72);
  assert.deepEqual(enabled.filter(link => baseline.includes(link)), baseline, 'Existing WS URI order and all parameters are unchanged');
  const added = enabled.filter(link => !baseline.includes(link)).map(link => new URL(link));
  assert.equal(added.length, 18);
  const identities = new Set();
  for (const node of added) {
    const params = node.searchParams, network = params.get('type'), name = decodeURIComponent(node.hash.slice(1));
    assert.equal(node.username, f.uuid);
    assert.equal(node.port, '443');
    assert.equal(params.get('security'), 'tls');
    assert.equal(params.get('alpn'), 'h2');
    assert.equal(params.get('sni'), 'test.invalid');
    assert.equal(params.get('allowInsecure'), '0');
    assert.equal(params.get('insecure'), '0');
    assert(['198.51.100.10', '198.51.100.11'].includes(node.hostname));
    const country = testCountries.find(item => name.includes(item.flag));
    assert(country, 'Every HTTP node carries its original country label');
    const base = `/stream/PANEL_ZEUS/${f.uuid.split('-')[4]}`;
    if (network === 'xhttp') {
      assert.equal(node.protocol, 'vless:');
      assert.equal(params.get('mode'), 'stream-one');
      assert.equal(params.get('path'), base + '/xhttp' + country.suffix);
    } else {
      assert.equal(network, 'grpc');
      assert(['vless:', 'trojan:'].includes(node.protocol));
      assert.equal(params.get('mode'), 'gun');
      assert.equal(params.get('serviceName'), base.slice(1) + '/grpc' + country.suffix);
      const path = '/' + params.get('serviceName') + '/Tun';
      assert.equal(f.context.zeusHttpTransportKind(new Request('https://test.invalid' + path, { method: 'POST' }), path), 'grpc');
    }
    assert(/443/.test(name) && /xhttp|grpc/i.test(name), 'HTTP names distinguish transport and port');
    identities.add([node.hostname, node.protocol, network, country.flag].join('|'));
  }
  assert.equal(identities.size, 18, 'Each IP/country/protocol/transport combination appears once');
  assert.equal(f.sockets.length, 0);
});

test('native YAML appends unique HTTP names while preserving WS names, parameters, and country groups', { timeout: 5000 }, async t => {
  const f = fixture(t, subscriptionUser), baseline = await nativeYaml(f), enabled = await nativeYaml(f, 'true');
  assert.equal(enabled.proxies.length, 72);
  assert.deepEqual(enabled.proxies.filter(node => baseline.proxies.some(old => old.block === node.block)).map(node => node.block), baseline.proxies.map(node => node.block));
  assert.equal(new Set(enabled.proxies.map(node => node.name)).size, 72, 'All YAML proxy names remain unique');
  const additions = enabled.proxies.filter(node => !baseline.proxies.some(old => old.block === node.block));
  assert.equal(additions.length, 18);
  const unquote = value => value?.startsWith('"') ? JSON.parse(value) : value;
  for (const node of additions) {
    assert.equal(node.field('port'), '443');
    assert.equal(node.field('tls'), 'true');
    assert.equal(node.field('skip-cert-verify'), 'false');
    assert.equal(node.field('alpn'), '[h2]');
    assert.equal(node.field('udp'), 'false');
    const protocol = node.field('type'), network = node.field('network');
    assert.equal(unquote(node.field(protocol === 'vless' ? 'uuid' : 'password')), f.uuid);
    assert.equal(unquote(node.field(protocol === 'vless' ? 'servername' : 'sni')), 'test.invalid');
    assert(['198.51.100.10', '198.51.100.11'].includes(unquote(node.field('server'))));
    const country = testCountries.find(item => node.name.includes(item.flag));
    assert(country);
    const base = `/stream/PANEL_ZEUS/${f.uuid.split('-')[4]}`;
    if (network === 'xhttp') {
      assert.equal(protocol, 'vless');
      assert(node.block.includes('    xhttp-opts:\n'));
      assert.equal(unquote(/^      path: (.*)$/m.exec(node.block)?.[1]), base + '/xhttp' + country.suffix);
      assert.equal(unquote(/^      host: (.*)$/m.exec(node.block)?.[1]), 'test.invalid');
      assert.equal(unquote(/^      mode: (.*)$/m.exec(node.block)?.[1]), 'stream-one');
    } else {
      assert.equal(network, 'grpc');
      assert(['vless', 'trojan'].includes(protocol));
      assert(node.block.includes('    grpc-opts:\n'));
      assert.equal(unquote(/^      grpc-service-name: (.*)$/m.exec(node.block)?.[1]), base.slice(1) + '/grpc' + country.suffix);
    }
  }
  assert.equal(enabled.groups.length, 4, 'One selector plus the original three country groups');
  assert.deepEqual(enabled.groups.map(group => group.name), baseline.groups.map(group => group.name));
  const groupedNames = [];
  for (const country of testCountries) {
    const group = enabled.groups.find(item => item.name.startsWith(country.flag + ' '));
    assert(group, `Country group ${country.flag} exists`);
    const names = [...group.block.matchAll(/^      - "(.+)"$/gm)].map(match => match[1]);
    const expectedNames = enabled.proxies.filter(node => node.name.includes(country.flag)).map(node => node.name);
    assert.deepEqual(names, expectedNames, 'Country selector includes old and new nodes in their emitted order');
    assert.equal(names.length, 24);
    groupedNames.push(...names);
  }
  assert.equal(new Set(groupedNames).size, 72, 'Each proxy belongs to exactly one country group');
  assert.equal(f.sockets.length, 0);
});

for (const [protocol, expectedWs, expectedHttp, schemes] of [
  ['vless', 18, 12, ['vless:']], ['trojan', 18, 6, ['trojan:']], ['shadowsocks', 18, 0, []],
]) {
  test(`native HTTP feed additions respect ${protocol}-only users`, { timeout: 5000 }, async t => {
    const f = fixture(t, { ...subscriptionUser, connection_type: protocol });
    const before = await nativeFeed(f), after = await nativeFeed(f, 'true');
    assert.equal(before.length, expectedWs);
    assert.equal(after.length, expectedWs + expectedHttp);
    assert.deepEqual(after.filter(link => before.includes(link)), before);
    assert(after.filter(link => !before.includes(link)).every(link => schemes.includes(new URL(link).protocol)));
    const oldYaml = await nativeYaml(f), newYaml = await nativeYaml(f, 'true');
    assert.equal(newYaml.proxies.length, expectedWs + expectedHttp);
    assert.deepEqual(newYaml.proxies.filter(node => oldYaml.proxies.some(old => old.block === node.block)).map(node => node.block), oldYaml.proxies.map(node => node.block));
  });
}
