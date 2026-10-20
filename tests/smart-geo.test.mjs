import assert from 'node:assert/strict';
import vm from 'node:vm';
import test from 'node:test';
import { section } from './helpers/source.mjs';
import { performance } from 'node:perf_hooks';

const context = vm.createContext({ URL, TextEncoder, TextDecoder, Response, Headers, AbortController, AbortSignal, Uint8Array, setTimeout, clearTimeout, fetch() { throw new Error('Unexpected network access'); } });
vm.runInContext(section('function createZeusDestinationCountryResolver(', 'const ZEUS_SMART_ISO_COUNTRIES'), context);
const { createZeusDestinationCountryResolver } = context;
const json = (value, init = {}) => new Response(JSON.stringify(value), { status: 200, ...init });
const dns = (ip = '8.8.8.8', type = 1) => json({ Status: 0, Answer: [{ type, data: ip, TTL: 60 }] });
const geo = (ip = '8.8.8.8', country = 'US') => json({ ip, country });
const host = { host: 'example.com', type: 'hostname' };
const ip = { host: '8.8.8.8', type: 'ipv4' };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function scripted(...responses) {
    const calls = [];
    const fetchImpl = async (url, options) => {
        calls.push({ url, options });
        assert.equal(options.redirect, 'error');
        assert.equal(options.method, 'GET');
        assert(options.signal instanceof AbortSignal);
        assert.match(url, /^https:\/\/(?:cloudflare-dns\.com\/dns-query\?|api\.country\.is\/)/);
        assert(responses.length, 'Unexpected additional network request: ' + url);
        const response = responses.shift();
        return typeof response === 'function' ? response(url, options) : response;
    };
    return { calls, fetchImpl };
}

async function check(name, run) {
    await test(name, run);
}

await check('IPv4 DNS and geo lookup use bounded trusted GET endpoints', async () => {
    const mock = scripted(dns(), geo());
    assert.equal(await createZeusDestinationCountryResolver(mock)(host), 'US');
    assert.equal(mock.calls.length, 2);
    assert.equal(mock.calls[0].url, 'https://cloudflare-dns.com/dns-query?name=example.com&type=A');
    assert.equal(mock.calls[0].options.headers.Accept, 'application/dns-json');
    assert.equal(mock.calls[1].url, 'https://api.country.is/8.8.8.8');
});

await check('CNAME and unrelated DNS record types never become geo lookup targets', async () => {
    const mock = scripted(json({ Status: 0, Answer: [
        { type: 5, data: 'alias.example.com' }, { type: 16, data: '1.1.1.1' },
        { type: 28, data: '2606:4700:4700::1111' }, { type: 1, data: '10.1.2.3' },
        { type: 1, data: '8.8.8.8' }, { type: 1, data: '1.1.1.1' },
    ] }), geo());
    assert.equal(await createZeusDestinationCountryResolver(mock)(host), 'US');
    assert.equal(mock.calls.length, 2);
    assert.equal(mock.calls[1].url, 'https://api.country.is/8.8.8.8');
});

await check('AAAA is attempted only after a successful DNS response with no public A', async () => {
    const mock = scripted(json({ Status: 0, Answer: [{ type: 5, data: 'alias.example.com' }] }), dns('2606:4700:4700::1111', 28), geo('2606:4700:4700:0:0:0:0:1111', 'AU'));
    assert.equal(await createZeusDestinationCountryResolver(mock)(host), 'AU');
    assert.equal(mock.calls.length, 3);
    assert.match(mock.calls[1].url, /&type=AAAA$/);
});

await check('DNS error statuses stop without retries', async () => {
    for (const body of [{ Status: 3 }, { Status: 2 }, { Status: '0', Answer: [] }, { Status: 0, Answer: {} }, null]) {
        const mock = scripted(json(body));
        assert.equal(await createZeusDestinationCountryResolver(mock)(host), null);
        assert.equal(mock.calls.length, 1);
    }
});

await check('DNS absence stops after at most A and AAAA', async () => {
    const mock = scripted(json({ Status: 0 }), json({ Status: 0, Answer: [] }));
    assert.equal(await createZeusDestinationCountryResolver(mock)(host), null);
    assert.equal(mock.calls.length, 2);
});

await check('private, reserved, loopback, CGNAT, multicast and documentation IPv4 never leave the worker', async () => {
    const mock = scripted();
    const resolve = createZeusDestinationCountryResolver(mock);
    for (const address of ['0.0.0.0', '0.8.8.8', '10.0.0.1', '100.64.0.1', '100.127.255.254', '127.0.0.1', '169.254.0.1', '172.16.0.1', '172.31.255.1', '192.0.0.9', '192.0.2.1', '192.88.99.1', '192.168.0.1', '198.18.0.1', '198.19.255.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255']) {
        assert.equal(await resolve({ host: address, type: 'ipv4' }), null, address);
    }
    assert.equal(mock.calls.length, 0);
});

await check('special and documentation IPv6 never leave the worker', async () => {
    const mock = scripted();
    const resolve = createZeusDestinationCountryResolver(mock);
    for (const address of ['::', '::1', '::ffff:8.8.8.8', '::ffff:10.0.0.1', '64:ff9b::808:808', '100::1', '2001::1', '2001:2::1', '2001:10::1', '2001:20::1', '2001:db8::1', '2002:808:808::1', '3ffe::1', '3fff::1', '3fff:fff::1', 'fc00::1', 'fdff::1', 'fe80::1', 'fec0::1', 'ff02::1', '5000::1']) {
        assert.equal(await resolve({ host: address, type: 'ipv6' }), null, address);
    }
    assert.equal(mock.calls.length, 0);
});

await check('public address range boundaries and IPv6 normalization remain usable', async () => {
    const addresses = ['100.63.255.255', '100.128.0.1', '172.15.0.1', '172.32.0.1', '198.17.1.1', '198.20.1.1', '223.255.255.254'];
    for (const address of addresses) {
        const mock = scripted(geo(address, 'IR'));
        assert.equal(await createZeusDestinationCountryResolver(mock)(address), 'IR', address);
    }
    const mock = scripted(geo('2606:4700:4700::1111', 'US'));
    assert.equal(await createZeusDestinationCountryResolver(mock)('[2606:4700:4700::1111]'), 'US');
    assert.equal(mock.calls[0].url, 'https://api.country.is/2606:4700:4700:0:0:0:0:1111');
});

await check('malformed destinations and IP shorthand never trigger requests', async () => {
    const mock = scripted();
    const resolve = createZeusDestinationCountryResolver(mock);
    for (const address of [null, {}, { host: 42 }, '', 'https://example.com', 'example.com:443', 'example.com/path', ' example.com', 'example..com', '-example.com', 'example-.com', 'localhost', 'foo.localhost', 'foo.local', 'foo.internal', 'foo.invalid', 'foo.test', '2130706433', '127.1', '0177.0.0.1', '256.2.3.4', '1.2.3.4.', '1::2::3', '[::1]', 'fe80::1%eth0', '1:2:3:4:5:6:7:8:9', { host: 'example.com', type: 'ipv4' }]) {
        assert.equal(await resolve(address), null, JSON.stringify(address));
    }
    assert.equal(mock.calls.length, 0);
});

await check('hostname case and final dot are normalized safely', async () => {
    const mock = scripted(dns(), geo());
    assert.equal(await createZeusDestinationCountryResolver(mock)('EXAMPLE.COM.'), 'US');
    assert.match(mock.calls[0].url, /name=example\.com&type=A$/);
});

await check('DNS private addresses are filtered before any geo request', async () => {
    const mock = scripted(dns('10.0.0.1'), dns('fd00::1', 28));
    assert.equal(await createZeusDestinationCountryResolver(mock)(host), null);
    assert.equal(mock.calls.length, 2);
    assert(mock.calls.every(call => call.url.includes('cloudflare-dns.com')));
});

await check('malformed DNS JSON fails quickly without AAAA retry', async () => {
    const mock = scripted(new Response('{broken'));
    assert.equal(await createZeusDestinationCountryResolver(mock)(host), null);
    assert.equal(mock.calls.length, 1);
});

await check('non-200 DNS and geo API responses fail closed without retries', async () => {
    for (const status of [301, 403, 429, 500]) {
        const mock = scripted(new Response('failure', { status }));
        assert.equal(await createZeusDestinationCountryResolver(mock)(host), null);
        assert.equal(mock.calls.length, 1);
        const ipMock = scripted(new Response('failure', { status }));
        assert.equal(await createZeusDestinationCountryResolver(ipMock)(ip), null);
        assert.equal(ipMock.calls.length, 1);
    }
});

await check('geo country must be an assigned uppercase ISO code and IP must match', async () => {
    for (const body of [{ ip: '8.8.8.8', country: 'ZZ' }, { ip: '8.8.8.8', country: 'USA' }, { ip: '8.8.8.8', country: 'us' }, { ip: '8.8.8.8', country: null }, { ip: '8.8.8.8', country: {} }, { country: 'US' }, { ip: '1.1.1.1', country: 'IR' }, null, []]) {
        const mock = scripted(json(body));
        assert.equal(await createZeusDestinationCountryResolver(mock)(ip), null, JSON.stringify(body));
    }
    const mock = scripted(new Response('{broken'));
    assert.equal(await createZeusDestinationCountryResolver(mock)(ip), null);
});

await check('positive geo cache is shared by resolved IP and respects expiry', async () => {
    let time = 1000;
    const mock = scripted(dns(), geo(), dns(), geo('8.8.8.8', 'IR'));
    const resolve = createZeusDestinationCountryResolver({ ...mock, now: () => time, ttlMs: 100 });
    assert.equal(await resolve(host), 'US');
    assert.equal(await resolve(ip), 'US');
    time = 1099;
    assert.equal(await resolve({ host: 'other.example.com', type: 'hostname' }), 'US');
    assert.equal(mock.calls.length, 3, 'different hostname shares settled IP geo cache');
    time = 1100;
    assert.equal(await resolve(ip), 'IR');
    assert.equal(mock.calls.length, 4);
});

await check('negative geo cache lasts 30 seconds and then retries', async () => {
    let time = 0;
    const mock = scripted(json({ ip: '8.8.8.8', country: null }), geo());
    const resolve = createZeusDestinationCountryResolver({ ...mock, now: () => time });
    assert.equal(await resolve(ip), null);
    time = 29999;
    assert.equal(await resolve(ip), null);
    assert.equal(mock.calls.length, 1);
    time = 30000;
    assert.equal(await resolve(ip), 'US');
    assert.equal(mock.calls.length, 2);
});

await check('negative DNS cache avoids repeated failures for 30 seconds', async () => {
    let time = 0;
    const mock = scripted(json({ Status: 3 }), dns(), geo());
    const resolve = createZeusDestinationCountryResolver({ ...mock, now: () => time });
    assert.equal(await resolve(host), null);
    time = 29999;
    assert.equal(await resolve(host), null);
    assert.equal(mock.calls.length, 1);
    time = 30000;
    assert.equal(await resolve(host), 'US');
    assert.equal(mock.calls.length, 3);
});

await check('bounded LRU evicts least recently read settled entry', async () => {
    const mock = scripted(geo('8.8.8.8'), geo('1.1.1.1', 'AU'), geo('9.9.9.9', 'CH'), geo('1.1.1.1', 'IR'));
    const resolve = createZeusDestinationCountryResolver({ ...mock, maxEntries: 2 });
    assert.equal(await resolve('8.8.8.8'), 'US');
    assert.equal(await resolve('1.1.1.1'), 'AU');
    assert.equal(await resolve('8.8.8.8'), 'US');
    assert.equal(await resolve('9.9.9.9'), 'CH');
    assert.equal(await resolve('8.8.8.8'), 'US');
    assert.equal(await resolve('1.1.1.1'), 'IR');
    assert.equal(mock.calls.length, 4);
});

await check('zero capacity disables all caching', async () => {
    const mock = scripted(geo(), geo('8.8.8.8', 'IR'));
    const resolve = createZeusDestinationCountryResolver({ ...mock, maxEntries: 0 });
    assert.equal(await resolve(ip), 'US');
    assert.equal(await resolve(ip), 'IR');
    assert.equal(mock.calls.length, 2);
});

await check('pre-aborted callers never use the cache or network', async () => {
    const mock = scripted(geo());
    const resolve = createZeusDestinationCountryResolver(mock);
    assert.equal(await resolve(ip), 'US');
    const controller = new AbortController();
    controller.abort();
    assert.equal(await resolve(ip, { signal: controller.signal }), null);
    assert.equal(mock.calls.length, 1);
});

await check('inherited abort interrupts ignored fetch and does not poison cache', async () => {
    const mock = scripted(() => new Promise(() => {}), geo());
    const resolve = createZeusDestinationCountryResolver(mock);
    const controller = new AbortController();
    const pending = resolve(ip, { signal: controller.signal });
    controller.abort();
    assert.equal(await pending, null);
    assert.equal(mock.calls[0].options.signal.aborted, true);
    assert.equal(await resolve(ip), 'US');
});

await check('timeout bounds fetch that ignores abort and does not start AAAA', async () => {
    const mock = scripted(() => new Promise(() => {}));
    const before = performance.now();
    assert.equal(await createZeusDestinationCountryResolver({ ...mock, timeoutMs: 25 })(host), null);
    assert(performance.now() - before < 300, 'ignored fetch exceeded the shared timeout');
    assert.equal(mock.calls.length, 1);
    assert.equal(mock.calls[0].options.signal.aborted, true);
});

await check('DNS and geo consume one shared deadline, not independent timeouts', async () => {
    const mock = scripted(async () => { await delay(40); return dns(); }, () => new Promise(() => {}));
    const before = performance.now();
    assert.equal(await createZeusDestinationCountryResolver({ ...mock, timeoutMs: 65 })(host), null);
    const elapsed = performance.now() - before;
    assert(elapsed < 100, 'geo received a fresh deadline instead of the remaining budget: ' + elapsed);
    assert.equal(mock.calls.length, 2);
});

await check('stalled response body is cancelled within the deadline', async () => {
    let cancelled = false;
    const mock = scripted(new Response(new ReadableStream({ pull() { return new Promise(() => {}); }, cancel() { cancelled = true; } })));
    const before = performance.now();
    assert.equal(await createZeusDestinationCountryResolver({ ...mock, timeoutMs: 25 })(ip), null);
    assert(performance.now() - before < 300);
    assert.equal(cancelled, true);
});

await check('late fetch body is released after timeout', async () => {
    let finish;
    let cancelled = false;
    const mock = scripted(() => new Promise(resolve => { finish = resolve; }));
    assert.equal(await createZeusDestinationCountryResolver({ ...mock, timeoutMs: 10 })(ip), null);
    finish(new Response(new ReadableStream({ cancel() { cancelled = true; } })));
    await delay(0);
    assert.equal(cancelled, true);
});

await check('DNS and geo enforce body byte limits before JSON parsing', async () => {
    for (const [destination, limit] of [[host, 16384], [ip, 4096]]) {
        let cancelled = false;
        let delivered = 0;
        const mock = scripted(new Response(new ReadableStream({
            pull(controller) { delivered += 1024; controller.enqueue(new Uint8Array(1024).fill(32)); },
            cancel() { cancelled = true; },
        })));
        assert.equal(await createZeusDestinationCountryResolver(mock)(destination), null);
        assert.equal(cancelled, true);
        assert(delivered <= limit + 2048, 'reader consumed too much data');
        assert.equal(mock.calls.length, 1);
    }
});

await check('Content-Length over the limit is rejected without reading body', async () => {
    let reads = 0;
    let cancelled = false;
    const body = { getReader() { reads++; throw new Error('must not read'); }, cancel() { cancelled = true; } };
    const mock = scripted({ status: 200, headers: new Headers({ 'Content-Length': '4097' }), body });
    assert.equal(await createZeusDestinationCountryResolver(mock)(ip), null);
    assert.equal(reads, 0);
    assert.equal(cancelled, true);
});

await check('concurrent requests do not share in-flight I/O or cancellation', async () => {
    let finishFirst;
    const mock = scripted(() => new Promise(resolve => { finishFirst = resolve; }), geo('8.8.8.8', 'IR'));
    const resolve = createZeusDestinationCountryResolver(mock);
    const controller = new AbortController();
    const first = resolve(ip, { signal: controller.signal });
    assert.equal(await resolve(ip), 'IR');
    assert.equal(mock.calls.length, 2);
    controller.abort();
    assert.equal(await first, null);
    finishFirst(geo('8.8.8.8', 'US'));
    await delay(0);
    assert.equal(await resolve(ip), 'IR');
});

await check('abort during response delivery consumes the late body rejection safely', async () => {
    const controller = new AbortController();
    let rejectedRead = false;
    const mock = scripted({
        status: 200,
        headers: new Headers(),
        body: {
            getReader() {
                return {
                    read() {
                        controller.abort();
                        rejectedRead = true;
                        return Promise.reject(new Error('late stream error'));
                    },
                    cancel() {}, releaseLock() {},
                };
            },
            cancel() {},
        },
    });
    assert.equal(await createZeusDestinationCountryResolver(mock)(ip, { signal: controller.signal }), null);
    await delay(0);
    assert.equal(rejectedRead, true);
});

await check('invalid UTF-8 and empty bodies fail without retries', async () => {
    for (const response of [new Response(new Uint8Array([0xff, 0xfe])), new Response('')]) {
        const mock = scripted(response);
        assert.equal(await createZeusDestinationCountryResolver(mock)(ip), null);
        assert.equal(mock.calls.length, 1);
    }
});
