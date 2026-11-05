// Generic WSS relay adapter: binary fidelity, bounded queues and cleanup.
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { section } from './helpers/source.mjs';

const adapter = section('async function connectWssUpstream(', 'async function connectProxy(');
const tick = () => new Promise(resolve => setImmediate(resolve));
const fixtureToken = 'SYNTHETIC_TEST_TOKEN_NOT_A_SECRET';
const fixtureUrl = 'wss://' + fixtureToken + '@relay.example/relay';
let count = 0;
class FakeWebSocket {
  constructor(autoAck = false) {
    this.readyState = 0; this.listeners = new Map(); this.sent = [];
    this.autoAck = autoAck; this.total = 0; this.closeCode = null;
  }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  emit(type, event = {}) { for (const callback of this.listeners.get(type) || []) callback(event); }
  accept() { this.readyState = 1; this.onAccept?.(); }
  send(data) {
    if (this.throwOnSend) throw new Error('synthetic send failure');
    assert(ArrayBuffer.isView(data));
    const copy = Uint8Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
    this.sent.push(copy); this.total += copy.byteLength;
    const total = this.total;
    if (this.autoAck) queueMicrotask(() => this.emit('message', { data: 'ack:' + total }));
  }
  close(code) { this.closeCode = code; this.readyState = 3; }
  receive(bytes) { this.emit('message', { data: Uint8Array.from(bytes).buffer }); }
  ack(value = this.total) { this.emit('message', { data: 'ack:' + value }); }
  remoteClose(code = 1000) { this.readyState = 3; this.emit('close', { code, wasClean: code === 1000 }); }
}
function fixture(options = {}) {
  const ws = new FakeWebSocket(options.autoAck);
  const calls = [];
  const timers = new Map();
  let id = 0;
  const context = vm.createContext({
    URL, AbortController, ArrayBuffer, Uint8Array, ReadableStream, WritableStream,
    setTimeout(callback, ms) { const key = ++id; timers.set(key, { callback, ms }); return key; },
    clearTimeout(key) { timers.delete(key); },
    async fetch(url, settings) { calls.push({ url, settings }); return options.response || { status: 101, webSocket: ws }; },
  });
  vm.runInContext(adapter + '\nglobalThis.api = { connectWssUpstream, webSocketUpstreamSocket };', context, { timeout: 1000 });
  return { ws, calls, timers, context, api: context.api };
}
async function rejects(promise, reason) { await assert.rejects(promise, error => error.message === reason); }

// Upgrade strips token from URL, sets correct headers, and preserves initial bytes.
{
  const f = fixture({ autoAck: true });
  const initial = new Uint8Array([99, 22, 33, 88]).subarray(1, 3);
  const socket = await f.api.connectWssUpstream(fixtureUrl, 'example.com', 443, initial);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, 'https://relay.example/relay');
  assert.equal(f.calls[0].settings.redirect, 'manual');
  assert.equal(f.calls[0].settings.headers.Authorization, 'Bearer ' + fixtureToken);
  assert.equal(f.calls[0].settings.headers['X-Exit-Host'], 'example.com');
  assert.equal(f.calls[0].settings.headers['X-Exit-Port'], '443');
  assert.equal(f.calls[0].settings.headers.Upgrade, 'websocket');
  assert.deepEqual(Array.from(f.ws.sent[0]), [22, 33]);
  assert.equal(f.ws.binaryType, 'arraybuffer');
  await socket.close(); await socket.closed;
  assert.equal(f.timers.size, 0); count++;
}
// Reject invalid URL/auth material before fetch; no insecure scheme/downgrade.
for (const url of [
  'ws://token@relay.example/relay', 'wss://relay.example/relay',
  'wss://token:password@relay.example/relay',
  'wss://a%20b@relay.example/relay', fixtureUrl + '?token=bad',
  fixtureUrl + '#fragment', ' ' + fixtureUrl, fixtureUrl + '\n',
  'wss://token@relay.example\\vpn-iran', fixtureUrl + '%ZZ',
]) {
  const f = fixture();
  await rejects(f.api.connectWssUpstream(url, 'example.com', 443), 'invalid_wss_proxy');
  assert.equal(f.calls.length, 0); count++;
}
for (const [host, port] of [['example.com\r\nX-Evil: x', 443], ['example.com', 0], ['example.com', 65536], ['example.com', 443.5]]) {
  const f = fixture();
  await rejects(f.api.connectWssUpstream(fixtureUrl, host, port), 'invalid_wss_destination');
  assert.equal(f.calls.length, 0); count++;
}
{
  let cancelled = false;
  const f = fixture({ response: { status: 401, body: { async cancel() { cancelled = true; } } } });
  await rejects(f.api.connectWssUpstream(fixtureUrl, 'example.com', 443), 'wss_upgrade_rejected');
  assert(cancelled); assert.equal(f.timers.size, 0); count++;
}
// Only 64KiB outstanding; exact ordered bytes survive chunk splitting and ACK.
{
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  const writer = socket.writable.getWriter();
  const payload = Uint8Array.from({ length: 131077 }, (_, i) => i % 251);
  let settled = false;
  const writing = writer.write(payload).then(() => { settled = true; });
  await tick(); assert.equal(f.ws.sent.length, 1); assert.equal(f.ws.sent[0].length, 65536); assert(!settled);
  f.ws.ack(); await tick(); assert.equal(f.ws.sent.length, 2); assert(!settled);
  f.ws.ack(); await tick(); assert.equal(f.ws.sent.length, 3); assert.equal(f.ws.sent[2].length, 5); assert(!settled);
  f.ws.ack(); await writing;
  assert.deepEqual(Buffer.concat(f.ws.sent.map(v => Buffer.from(v))), Buffer.from(payload));
  await writer.close(); await socket.closed; assert.equal(f.timers.size, 0); count++;
}
// Server data may arrive before connectWssUpstream returns; preserve it and EOF order.
{
  const f = fixture(); f.ws.onAccept = () => { f.ws.receive([1, 2]); f.ws.receive([3]); };
  const socket = await f.api.connectWssUpstream(fixtureUrl, 'example.com', 80);
  f.ws.remoteClose();
  const reader = socket.readable.getReader();
  assert.deepEqual(Array.from((await reader.read()).value), [1, 2]);
  assert.deepEqual(Array.from((await reader.read()).value), [3]);
  assert((await reader.read()).done); await socket.closed; count++;
}
for (const message of ['ack:999', 'ack:-1', 'ready', 'ack:01', 'ack:9007199254740992']) {
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  const reader = socket.readable.getReader(); const reading = reader.read();
  f.ws.emit('message', { data: message });
  await rejects(reading, 'wss_invalid_ack'); await rejects(socket.closed, 'wss_invalid_ack');
  assert.equal(f.ws.closeCode, 1002); count++;
}
// Reject decreasing cumulative ACK and clean up an outstanding write on EOF.
{
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  const writer = socket.writable.getWriter(); const p = writer.write(new Uint8Array([1, 2]));
  await tick(); f.ws.ack(2); await p; f.ws.ack(1);
  await rejects(socket.closed, 'wss_invalid_ack'); count++;
}
{
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  const writing = socket.writable.getWriter().write(new Uint8Array([1]));
  await tick(); f.ws.remoteClose(); await rejects(writing, 'wss_closed');
  await socket.closed; assert.equal(f.timers.size, 0); count++;
}
// Timeout, transport error, and send error never leave pending ACK promises.
{
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  const writing = socket.writable.getWriter().write(new Uint8Array([1]));
  await tick(); const timer = [...f.timers.values()].find(t => t.ms === 15000); assert(timer);
  timer.callback(); await rejects(writing, 'wss_ack_timeout'); await rejects(socket.closed, 'wss_ack_timeout'); count++;
}
for (const cause of ['error', 'send']) {
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  if (cause === 'send') f.ws.throwOnSend = true;
  const writing = socket.writable.getWriter().write(new Uint8Array([1]));
  if (cause === 'error') { await tick(); f.ws.emit('error'); }
  const reason = cause === 'error' ? 'wss_upstream_error' : 'wss_send_failed';
  await rejects(writing, reason); await rejects(socket.closed, reason); count++;
}
// Bound both byte and tiny-frame queues; reject unsupported data types.
for (const mode of ['read-bytes', 'read-items', 'write-bytes', 'text-write']) {
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  let reason;
  if (mode === 'read-bytes') { f.ws.receive(new Uint8Array(8 * 1024 * 1024 + 1)); reason = 'wss_read_queue_limit'; }
  if (mode === 'read-items') { for (let i = 0; i < 1025; i++) f.ws.receive([1]); reason = 'wss_read_queue_limit'; }
  if (mode === 'write-bytes' || mode === 'text-write') {
    reason = mode === 'write-bytes' ? 'wss_write_queue_limit' : 'wss_nonbinary_data';
    await rejects(socket.writable.getWriter().write(mode === 'write-bytes' ? new Uint8Array(2 * 1024 * 1024 + 1) : 'bad'), reason);
  }
  await rejects(socket.closed, reason); count++;
}
{
  const f = fixture(); const socket = f.api.webSocketUpstreamSocket(f.ws);
  const writing = socket.writable.getWriter().write(new Uint8Array([1]));
  await tick(); await socket.readable.cancel(); await rejects(writing, 'wss_closed');
  await socket.closed; assert.equal(f.timers.size, 0); count++;
}

assert(count > 25, 'All relay adapter cases ran');
