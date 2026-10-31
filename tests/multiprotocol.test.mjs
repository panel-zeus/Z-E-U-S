// Decode real AEAD packets with production parser code and synthetic identities.
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { createHash, createCipheriv, hkdfSync, webcrypto } from 'node:crypto';
import { section } from './helpers/source.mjs';

const uuid = '11111111-1111-4111-8111-111111111111';
const hash = createHash('sha224').update(uuid).digest('hex');
const fixture = { uuid, trojan_hash: hash, username: 'synthetic', connection_type: 'vless,trojan,shadowsocks', is_active: 1 };
const target = Buffer.from('example.com');
const payload = Buffer.from('TEST-APPLICATION-DATA');
const request = new Request('https://worker.example/stream/PANEL_ZEUS/111111111111?loc=1');
const env = { DB: { prepare(sql) { return { bind(...args) { return {
  async first() {
    if (sql.includes('substr(uuid, -12)')) return args[0] === '111111111111' ? fixture : null;
    if (sql.includes('trojan_hash')) return args[0] === hash ? fixture : null;
    return args[0] === uuid ? fixture : null;
  }, async run() {},
}; }, async all() { return { results: [] }; } }; } } };
const cryptoFacade = { subtle: {
  digest: async (algorithm, bytes) => algorithm === 'MD5'
    ? Uint8Array.from(createHash('md5').update(bytes).digest()).buffer
    : webcrypto.subtle.digest(algorithm, bytes),
  importKey: (...args) => webcrypto.subtle.importKey(...args),
  deriveKey: (...args) => webcrypto.subtle.deriveKey(...args),
  decrypt: (...args) => webcrypto.subtle.decrypt(...args),
  encrypt: (...args) => webcrypto.subtle.encrypt(...args),
} };
const parsedSection = section('\t\t\t// SS salt is random:', '\t\t\tconst userConn = ');
const context = vm.createContext({ crypto: cryptoFacade, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, Uint32Array, URL,
  TEXT_DECODER: new TextDecoder(), env, request, ctx: null,
});
vm.runInContext(section('const SSCrypto = {', 'export default {') + '\n' +
  section('function convertToUint8Array(', '/*') + '\n' +
  section('function concatBytes(', 'function closeSocketQuietly(') + '\n' +
  section('function sha224Pure(', 'async function forwardTrojanUDP(') + '\n' +
  section('function extractUUIDFromvIees(data) {', 'function trackRequest(') + '\n' +
  `globalThis.parse = async function(chunkBuffer, state) {
    let isHeaderParsing = false, isTrojanProto = false, isShadowsocksProto = false;
    let ssUpAeadCtx = null, ssUpExpectedPayloadLen = null, ssUpBuffer = new Uint8Array(0), reqUUID = null;
    const serverSock = { close() { state.closed = true; } };
    ${parsedSection}
    return { protocol: isTrojan ? 'trojan' : isShadowsocks ? 'shadowsocks' : 'vless', cmd, port, addr, rawData };
  };`, context);
async function parse(bytes) {
  const state = { closed: false };
  const result = await context.parse(new Uint8Array(bytes), state);
  return { result, closed: state.closed };
}
function ssPacket(salt) {
  const first = createHash('md5').update(uuid).digest();
  const second = createHash('md5').update(Buffer.concat([first, Buffer.from(uuid)])).digest();
  const master = Buffer.concat([first, second]);
  const key = hkdfSync('sha1', master, salt, Buffer.from('ss-subkey'), 32);
  const plain = Buffer.concat([Buffer.from([3, target.length]), target, Buffer.from([1, 187]), payload]);
  function encrypt(bytes, counter) {
    const nonce = Buffer.alloc(12); nonce[0] = counter;
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    return Buffer.concat([cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
  }
  const length = Buffer.alloc(2); length.writeUInt16BE(plain.length);
  return Buffer.concat([salt, encrypt(length, 0), encrypt(plain, 1)]);
}
let saltCases = 0, partialCases = 0;
for (let first = 0; first < 256; first++) {
  const salt = Buffer.from(Array.from({ length: 32 }, (_, i) => i === 0 ? first : (i * 19 + first) & 255));
  const packet = ssPacket(salt);
  const actual = await parse(packet);
  assert.equal(actual.closed, false);
  assert.equal(actual.result?.protocol, 'shadowsocks', 'Every salt first byte is valid, including 0..3');
  assert.equal(actual.result.addr, 'example.com');
  assert.equal(actual.result.port, 443);
  assert.deepEqual(Buffer.from(actual.result.rawData), payload);
  for (const cut of [1, 16, 17, 32, 49, 50, 57, 58, 59, packet.length - 1]) {
    const part = await parse(packet.subarray(0, cut));
    assert.equal(part.closed, false, `Partial SS packet closed at byte${cut}`);
    assert.equal(part.result, undefined);
    partialCases++;
  }
  saltCases++;
}
// SS can also begin with a long apparent Trojan hash prefix.
const hexSaltPacket = ssPacket(Buffer.alloc(32, 0x61));
for (let cut = 1; cut < hexSaltPacket.length; cut++) {
  const partial = await parse(hexSaltPacket.subarray(0, cut));
  assert.equal(partial.closed, false);
  assert.equal(partial.result, undefined);
  partialCases++;
}
assert.equal((await parse(hexSaltPacket)).result.protocol, 'shadowsocks');

const vlessHeader = Buffer.concat([Buffer.from([0]), Buffer.from(uuid.replaceAll('-', ''), 'hex'),
  Buffer.from([0, 1, 1, 187, 2, target.length]), target]);
const trojanHeader = Buffer.concat([Buffer.from(hash + '\r\n'), Buffer.from([1, 3, target.length]),
  target, Buffer.from([1, 187, 13, 10])]);
for (const [protocol, header] of [['vless', vlessHeader], ['trojan', trojanHeader]]) {
  for (let cut = 1; cut < header.length; cut++) {
    const part = await parse(header.subarray(0, cut));
    assert.equal(part.closed, false, `Partial ${protocol} closed at byte${cut}`);
    assert.equal(part.result, undefined);
    partialCases++;
  }
  const actual = await parse(Buffer.concat([header, payload]));
  assert.equal(actual.closed, false);
  assert.equal(actual.result.protocol, protocol);
  assert.equal(actual.result.addr, 'example.com');
  assert.equal(actual.result.port, 443);
  assert.deepEqual(Buffer.from(actual.result.rawData), payload);
}
context.request = new Request('https://worker.example/stream/PANEL_ZEUS/222222222222');
const wrongPath = await parse(Buffer.concat([vlessHeader, payload]));
assert.equal(wrongPath.result, undefined);
assert.equal(wrongPath.closed, true);
context.request = request;


assert.equal(saltCases, 256);
assert(partialCases > 2500, 'Fragmented protocol headers cover each possible salt prefix');
