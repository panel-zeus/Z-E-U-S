// Offline integration tests of the production Worker; all credentials are synthetic.
import { source } from './source.mjs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { randomUUID, webcrypto } from 'node:crypto';

const executable = source.replace(/^import .*cloudflare:sockets.*;\s*/m, '')
  .replace('export default {', 'globalThis.worker = {') + `
globalThis.__test = {
  traffic: GLOBAL_TRAFFIC_CACHE, requests: USER_REQ_CACHE,
  lastWrite: GLOBAL_LAST_DB_WRITE, active: ACTIVE_CONNECTIONS_COUNT,
  activeIPs: GLOBAL_ACTIVE_IPS, locks: GLOBAL_WRITE_LOCK,
  activeHttp() { return ZEUS_HTTP_ACTIVE; }
};`;
const username = 'offline-synthetic-user';
const destination = Buffer.from('example.com');
const application = Buffer.from('synthetic application bytes');
const downstream = Buffer.from('synthetic destination reply');
const tick = () => new Promise(resolve => setImmediate(resolve));
async function until(predicate, message) {
  for (let i = 0; i < 400; i++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 2));
  }
  assert.fail(message);
}
function vless(uuid, data = application) {
  return Buffer.concat([Buffer.from([0]), Buffer.from(uuid.replaceAll('-', ''), 'hex'),
    Buffer.from([0, 1, 1, 187, 2, destination.length]), destination, data]);
}
function varint(number) {
  const out = [];
  do { out.push((number & 127) | (number > 127 ? 128 : 0)); number >>>= 7; } while (number);
  return Buffer.from(out);
}
function grpcHunk(bytes) {
  const hunk = Buffer.concat([Buffer.from([10]), varint(bytes.length), bytes]);
  const header = Buffer.alloc(5); header.writeUInt32BE(hunk.length, 1);
  return Buffer.concat([header, hunk]);
}
function decodeGrpc(bytes) {
  const out = [];
  for (let offset = 0; offset < bytes.length;) {
    assert(bytes.length - offset >= 5, 'Complete gRPC frame header');
    assert.equal(bytes[offset], 0, 'No unnegotiated compression');
    const length = bytes.readUInt32BE(offset + 1); offset += 5;
    const end = offset + length;
    assert(end <= bytes.length, 'Complete gRPC message');
    assert.equal(bytes[offset++], 10, 'Hunk.data is protobuf field 1, wire type 2');
    let size = 0, shift = 0, b;
    do { assert(offset < end && shift <= 28); b = bytes[offset++]; size += (b & 127) * 2 ** shift; shift += 7; } while (b & 128);
    assert.equal(offset + size, end, 'Single complete data field');
    out.push(bytes.subarray(offset, end)); offset = end;
  }
  return Buffer.concat(out);
}
function fixture(t, overrides = {}, options = {}) {
  const uuid = randomUUID();
  const user = { username, uuid, connection_type: 'vless', is_active: 1,
    limit_gb: null, used_gb: 0, limit_req: null, used_req: 0,
    expiry_days: null, created_at: Date.now(), user_socks5: null, ...overrides };
  const queries = [], writes = [], sockets = [], pending = [], timers = new Set(), logs = [];
  let networkCalls = 0;
  const env = { HTTP_TRANSPORTS: 'true', ...options.env, DB: { prepare(sql) {
    const query = { sql, args: [] }; queries.push(query);
    return { bind(...args) { query.args = args; return this; },
      async run() { writes.push(query); if (options.failAccounting && sql.startsWith('UPDATE users SET used_gb = used_gb +')) throw new Error('Synthetic accounting failure'); return {}; },
      async all() { return { results: [] }; },
      async first() {
        if (sql.includes('FROM users WHERE username') && sql.includes('OR uuid')) {
          return query.args[0] === username || query.args[1] === uuid ? { ...user } : null;
        }
        if (sql.includes('FROM users WHERE uuid')) {
          if (options.failUserRead) throw new Error('Synthetic authentication read failure');
          return String(query.args[0]).toLowerCase() === uuid.toLowerCase() ? { ...user } : null;
        }
        if (sql.includes("key = 'req_last_date'")) return { value: new Date().toISOString().split('T')[0] };
        return null;
      },
    };
  } } };
  function connect(address) {
    let controller, resolveClosed, resolveOpened;
    const socket = { address, uploads: [], closeCount: 0, ended: false,
      opened: options.deferConnect ? new Promise(resolve => { resolveOpened = resolve; }) : Promise.resolve(),
      completeOpen() { resolveOpened?.(); }, closed: new Promise(resolve => { resolveClosed = resolve; }),
      readable: new ReadableStream({ start(c) { controller = c; }, cancel() { socket.cancelled = true; } }),
      writable: new WritableStream({ write(bytes) { socket.uploads.push(Buffer.from(bytes)); }, close() { socket.writeClosed = true; } }),
      reply(bytes) { assert(!socket.ended); controller.enqueue(new Uint8Array(bytes)); },
      eof() { if (!socket.ended) { socket.ended = true; controller.close(); resolveClosed(); } },
      close() { socket.closeCount++; if (!socket.ended) { socket.ended = true; try { controller.close(); } catch {} resolveClosed(); } },
    };
    sockets.push(socket); return socket;
  }
  const context = vm.createContext({ TextEncoder, TextDecoder, Request, Response, Headers, URL, URLSearchParams,
    ReadableStream, WritableStream, TransformStream, AbortController, AbortSignal,
    Uint8Array, ArrayBuffer, DataView, Uint32Array, atob, btoa, crypto: webcrypto, queueMicrotask,
    WebSocket: { OPEN: 1, CLOSING: 2, CLOSED: 3 },
    WebSocketPair: class { constructor() { throw new Error('HTTP routes must not construct WebSocketPair'); } },
    console: { log(...args) { logs.push(args); }, error(...args) { logs.push(args); }, warn(...args) { logs.push(args); } },
    setTimeout(fn, delay, ...args) { const timer = setTimeout(() => { timers.delete(timer); fn(...args); }, delay); timer.unref(); timers.add(timer); return timer; },
    clearTimeout(timer) { timers.delete(timer); clearTimeout(timer); },
    caches: { default: { async match() { return new Response('locked'); }, async put() {} } },
    fetch() { networkCalls++; throw new Error('Unexpected network access in offline test'); }, connect,
  });
  vm.runInContext(executable, context);
  const state = context.__test;
  state.lastWrite.set(username, Date.now());
  const ctx = { waitUntil(promise) { pending.push(Promise.resolve(promise)); } };
  const streams = [];
  t.after(async () => {
    for (const socket of sockets) socket.close();
    for (const stream of streams) { try { stream.error(new Error('Test disposal')); } catch {} }
    for (const timer of timers) clearTimeout(timer);
    await Promise.allSettled(pending);
    assert.equal(networkCalls, 0, 'No external network was accessed');
  });
  return { env, uuid, user, context, state, sockets, queries, writes, logs,
    async settle() { await tick(); await Promise.allSettled(pending); await tick(); },
    async subscription(format, flag) {
      const bindings = { ...env };
      delete bindings.HTTP_TRANSPORTS;
      if (flag !== undefined) bindings.HTTP_TRANSPORTS = flag;
      return context.worker.fetch(new Request(`https://test.invalid/${format}/${username}`), bindings, ctx);
    },
    async open(kind = 'xhttp', { contentType, suffix, route, method = 'POST' } = {}) {
      let controller, cancelled = false;
      const aborter = new AbortController();
      const body = new ReadableStream({ start(c) { controller = c; streams.push(c); }, cancel() { cancelled = true; } });
      const path = route || `/stream/PANEL_ZEUS/${suffix || uuid.split('-')[4]}/${kind}${kind === 'grpc' ? '/Tun' : ''}`;
      const init = { method, signal: aborter.signal, headers: { 'Content-Type': contentType || (kind === 'grpc' ? 'application/grpc' : 'application/octet-stream') } };
      if (method === 'POST') Object.assign(init, { body, duplex: 'half' });
      const response = context.worker.fetch(new Request('https://test.invalid' + path, init), env, ctx);
      return { response, send(bytes) { controller.enqueue(new Uint8Array(bytes)); }, end() { controller.close(); },
        fail() { controller.error(new Error('Synthetic upload cancellation')); }, abort() { aborter.abort(); }, get cancelled() { return cancelled; } };
    },
  };
}
async function connected(f, expected = application) {
  await until(() => f.sockets.length > 0 && Buffer.concat(f.sockets[0].uploads).length >= expected.length,
    'Authenticated application bytes reach the mocked TCP destination');
  assert.equal(f.sockets.length, 1);
  assert.equal(f.sockets[0].address.hostname, 'example.com');
  assert.equal(f.sockets[0].address.port, 443);
  assert.deepEqual(Buffer.concat(f.sockets[0].uploads), expected);
  return f.sockets[0];
}


export { fixture, username, application, downstream, tick, until, vless, grpcHunk, decodeGrpc, connected };
