// Offline tests of the production routing helper. No live credentials or network access.
import { section } from './helpers/source.mjs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = section('const ZEUS_SMART_ISO_COUNTRIES', 'const ZEUS_SMART_GEO');
const context = vm.createContext({ URL, TextEncoder, TextDecoder, AbortController, AbortSignal,
  setTimeout, clearTimeout, console,
  fetch() { throw new Error('Network access is forbidden in this offline test'); },
});
vm.runInContext(source, context);
const createRouter = options => context.createZeusSmartRouter(options);
const normalize = input => context.normalizeZeusSmartDestination(input);
const codes = result => Array.from(result.routes, exit => exit.country);
const exit = (country, suffix = '') => ({ country, proxy: `socks5://synthetic-${country.toLowerCase()}${suffix}.invalid:1080` });
const exits = ['IR', 'AE', 'CA', 'US', 'DE', 'TR', 'GB'].map(country => exit(country));
const defaultOrder = ['DE', 'US', 'GB', 'CA', 'TR', 'AE', 'IR'];
const aiOrder = ['US', 'DE', 'GB', 'CA', 'TR', 'AE'];
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
function originalReferences(result, input) {
  assert(result.routes.every(route => input.includes(route)), 'Routing returns original exit references only');
  assert.equal(new Set(result.routes).size, result.routes.length, 'Routing does not duplicate exits');
}

test('normalization classifies hostnames and addresses without accepting endpoint URLs', () => {
  const host = normalize('API.Example.COM.');
  assert.equal(host.host, 'api.example.com'); assert.equal(host.type, 'hostname');
  const ipv4 = normalize('8.8.8.8');
  assert.equal(ipv4.host, '8.8.8.8'); assert.equal(ipv4.type, 'ipv4');
  const ipv6 = normalize('2001:db8::1');
  assert.equal(ipv6.host, '2001:db8::1'); assert.equal(ipv6.type, 'ipv6');
});

test('invalid destinations fail with TypeError', () => {
  for (const value of ['', null, undefined, 7, {}, 'https://example.com/', 'user@example.com',
    'example.com:443', 'example.com/path', 'example..com', '-invalid.example',
    'example.com\0evil', 'a'.repeat(64) + '.com', '256.1.2.3']) {
    assert.throws(() => normalize(value), error => error?.name === 'TypeError', String(value));
  }
});

test('AI hostname and subdomain matches prefer US and exclude Iran without resolver calls', async () => {
  let calls = 0;
  const router = createRouter({ resolveCountry: async () => { calls++; return 'IR'; } });
  for (const destination of ['chatgpt.com', 'api.openai.com', 'OPENAI.COM.', 'api.chatgpt.com']) {
    const result = await router.orderRoutes({ destination, exits });
    assert.deepEqual(codes(result), aiOrder);
    assert.equal(result.source, 'ai-rule'); assert.equal(result.country, null);
    assert.deepEqual(Array.from(result.preferredCountries), aiOrder);
    originalReferences(result, exits);
  }
  assert.equal(calls, 0);
});

test('lookalike hostnames do not cross AI suffix boundaries', async () => {
  let calls = 0;
  const router = createRouter({ resolveCountry: async () => { calls++; return null; } });
  for (const destination of ['evilopenai.com', 'openai.com.evil', 'evilchatgpt.com', 'chatgpt.com.evil']) {
    const result = await router.orderRoutes({ destination, exits });
    assert.equal(result.source, 'unknown'); assert.deepEqual(codes(result), defaultOrder);
  }
  assert.equal(calls, 4);
});

test('AI routing with only Iran exits returns no route', async () => {
  const result = await createRouter().orderRoutes({ destination: 'chatgpt.com', exits: [exits[0]] });
  assert.equal(result.routes.length, 0);
  assert.equal(result.source, 'ai-rule');
});

test('Iran ccTLD routes prefer Iran without resolver calls', async () => {
  const router = createRouter({ resolveCountry() { throw new Error('ccTLD must not require resolution'); } });
  const result = await router.orderRoutes({ destination: 'portal.example.ir', exits });
  assert.equal(result.country, 'IR'); assert.equal(result.source, 'cctld-rule');
  assert.deepEqual(codes(result).slice(0, 4), ['IR', 'TR', 'AE', 'DE']);
  originalReferences(result, exits);
});

test('Iran destination without an Iran exit falls back through Turkey, UAE, Germany', async () => {
  const available = exits.filter(item => item.country !== 'IR');
  const result = await createRouter().orderRoutes({ destination: 'example.ir', exits: available });
  assert.deepEqual(codes(result).slice(0, 3), ['TR', 'AE', 'DE']);
  originalReferences(result, available);
});

test('actual country ccTLDs select their country including UK mapped to GB', async () => {
  const router = createRouter();
  for (const [destination, country] of [['example.co.uk', 'GB'], ['example.de', 'DE'], ['example.ca', 'CA'], ['example.tr', 'TR']]) {
    const result = await router.orderRoutes({ destination, exits });
    assert.equal(result.source, 'cctld-rule'); assert.equal(result.country, country);
    assert.equal(result.routes[0].country, country);
  }
});

test('commercial ai/io/tv suffixes do not infer their registry countries', async () => {
  const resolved = [];
  const router = createRouter({ resolveCountry: async destination => { resolved.push(destination.host); return 'CA'; } });
  for (const destination of ['business.ai', 'business.io', 'business.tv']) {
    const result = await router.orderRoutes({ destination, exits });
    assert.equal(result.source, 'resolver'); assert.equal(result.country, 'CA');
    assert.equal(result.routes[0].country, 'CA');
  }
  assert.deepEqual(resolved, ['business.ai', 'business.io', 'business.tv']);
});

test('resolver receives the normalized destination and an AbortSignal', async () => {
  let received, signal;
  const result = await createRouter({ resolveCountry: async (destination, options) => {
    received = destination; signal = options.signal; return 'US';
  } }).orderRoutes({ destination: '8.8.8.8', exits });
  assert.equal(received.host, '8.8.8.8'); assert.equal(received.type, 'ipv4');
  assert(signal instanceof AbortSignal);
  assert.equal(result.country, 'US'); assert.equal(result.source, 'resolver');
  assert.equal(result.routes[0].country, 'US');
});

test('resolved country is preferred even outside the default ranked list', async () => {
  const france = exit('FR'), available = [...exits, france];
  const result = await createRouter({ resolveCountry: async () => 'FR' }).orderRoutes({ destination: 'business.com', exits: available });
  assert.equal(result.routes[0], france);
  assert.deepEqual(codes(result).slice(1), defaultOrder);
});

test('resolved country absent from exits uses the original available default ordering', async () => {
  const result = await createRouter({ resolveCountry: async () => 'NZ' }).orderRoutes({ destination: 'business.com', exits });
  assert.equal(result.country, 'NZ'); assert.deepEqual(codes(result), defaultOrder);
  originalReferences(result, exits);
});

test('missing or unknown country resolver returns the default order without injecting direct routes', async () => {
  for (const options of [{}, { resolveCountry: async () => null }]) {
    const result = await createRouter(options).orderRoutes({ destination: 'business.com', exits });
    assert.equal(result.source, 'unknown'); assert.equal(result.country, null);
    assert.deepEqual(codes(result), defaultOrder); originalReferences(result, exits);
  }
  const empty = await createRouter().orderRoutes({ destination: 'business.com', exits: [] });
  assert.equal(empty.routes.length, 0);
});

test('resolver failures fall back safely and are negatively cached', async () => {
  let calls = 0, time = 1000;
  const router = createRouter({ now: () => time, negativeCacheTtlMs: 30,
    resolveCountry: async () => { calls++; throw new Error('Synthetic resolver failure'); } });
  for (let count = 0; count < 2; count++) {
    const result = await router.orderRoutes({ destination: 'business.com', exits });
    assert.deepEqual(codes(result), defaultOrder); assert.equal(result.source, 'unknown');
  }
  assert.equal(calls, 1);
  time += 31; await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(calls, 2);
});

test('resolver timeout aborts its signal and late resolution cannot poison the cache', { timeout: 2000 }, async () => {
  const late = deferred(); let signal, calls = 0;
  const router = createRouter({ resolverTimeoutMs: 10, resolveCountry: (_, options) => { calls++; signal = options.signal; return late.promise; } });
  const result = await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(result.source, 'unknown'); assert.deepEqual(codes(result), defaultOrder);
  assert.equal(signal.aborted, true);
  late.resolve('IR'); await tick();
  const cached = await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(cached.country, null); assert.deepEqual(codes(cached), defaultOrder);
  assert.equal(calls, 1);
});

test('positive cache normalizes destination keys and expires on its own TTL', async () => {
  let calls = 0, time = 1000;
  const router = createRouter({ now: () => time, cacheTtlMs: 100, resolveCountry: async () => { calls++; return 'CA'; } });
  await router.orderRoutes({ destination: 'Business.COM.', exits });
  await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(calls, 1);
  time += 101; await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(calls, 2);
});

test('null resolution uses negative TTL independently of positive cache TTL', async () => {
  let calls = 0, time = 1000;
  const router = createRouter({ now: () => time, cacheTtlMs: 1000, negativeCacheTtlMs: 10,
    resolveCountry: async () => { calls++; return null; } });
  await router.orderRoutes({ destination: 'business.com', exits });
  time += 9; await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(calls, 1);
  time += 2; await router.orderRoutes({ destination: 'business.com', exits });
  assert.equal(calls, 2);
});

test('country cache never exceeds its configured cap and evicts an older entry', async () => {
  let calls = 0;
  const router = createRouter({ cacheMaxEntries: 2, resolveCountry: async () => { calls++; return 'CA'; } });
  for (const destination of ['one.com', 'two.com', 'three.com']) {
    await router.orderRoutes({ destination, exits });
    assert(router.stats().cacheEntries <= 2);
  }
  assert.equal(router.stats().cacheEntries, 2);
  await router.orderRoutes({ destination: 'one.com', exits });
  assert.equal(calls, 4);
});

test('same request scope deduplicates only the same normalized in-flight destination', async () => {
  const answer = deferred(); let calls = 0;
  const router = createRouter({ resolveCountry: () => { calls++; return answer.promise; } });
  const resolutionScope = router.createResolutionScope();
  const first = router.orderRoutes({ destination: 'Business.COM.', exits, resolutionScope });
  const second = router.orderRoutes({ destination: 'business.com', exits, resolutionScope });
  const distinct = router.orderRoutes({ destination: 'other.com', exits, resolutionScope });
  await tick(); assert.equal(calls, 2, 'Only matching destinations share work within a scope');
  answer.resolve('US');
  for (const result of await Promise.all([first, second, distinct])) assert.equal(result.routes[0].country, 'US');
});

test('different request scopes never share pending resolver promises', async () => {
  const answer = deferred(); let calls = 0;
  const router = createRouter({ resolveCountry: () => { calls++; return answer.promise; } });
  const first = router.orderRoutes({ destination: 'business.com', exits, resolutionScope: router.createResolutionScope() });
  const second = router.orderRoutes({ destination: 'business.com', exits, resolutionScope: router.createResolutionScope() });
  await tick(); assert.equal(calls, 2);
  answer.resolve('US'); await Promise.all([first, second]);
});

test('absence of request scope never globally deduplicates pending I/O', async () => {
  const answer = deferred(); let calls = 0;
  const router = createRouter({ resolveCountry: () => { calls++; return answer.promise; } });
  const first = router.orderRoutes({ destination: 'business.com', exits });
  const second = router.orderRoutes({ destination: 'business.com', exits });
  await tick(); assert.equal(calls, 2);
  answer.resolve('US'); await Promise.all([first, second]);
});

test('resolver concurrency remains bounded by maxInflight', { timeout: 2000 }, async () => {
  const answer = deferred(); let active = 0, maximum = 0;
  const router = createRouter({ maxInflight: 2, resolveCountry: async () => {
    active++; maximum = Math.max(maximum, active); await answer.promise; active--; return 'CA';
  } });
  const requests = ['one.com', 'two.com', 'three.com', 'four.com'].map(destination => router.orderRoutes({ destination, exits }));
  await tick();
  answer.resolve(); await Promise.all(requests); assert(maximum <= 2);
});

test('timed-out resolver that ignores abort retains its concurrency slot until it settles', { timeout: 2000 }, async () => {
  const answer = deferred(); let calls = 0;
  const router = createRouter({ maxInflight: 1, resolverTimeoutMs: 10,
    resolveCountry: () => { calls++; return answer.promise; } });
  const timedOut = await router.orderRoutes({ destination: 'one.com', exits });
  assert.equal(timedOut.source, 'unknown'); assert.equal(calls, 1);
  const blocked = await router.orderRoutes({ destination: 'two.com', exits });
  assert.equal(blocked.source, 'unknown'); assert.equal(calls, 1, 'Still-running work consumes its slot after timeout');
  answer.resolve('CA'); await tick();
  const next = await router.orderRoutes({ destination: 'three.com', exits });
  assert.equal(calls, 2); assert.equal(next.country, 'CA');
});

test('failed exit is omitted for its normalized destination but remains usable for other targets', async () => {
  const router = createRouter(), germany = exits.find(item => item.country === 'DE');
  router.reportFailure({ destination: 'Business.COM.', exit: germany });
  const failed = await router.orderRoutes({ destination: 'business.com', exits });
  assert(!failed.routes.includes(germany)); assert.equal(failed.routes.length, exits.length - 1);
  const other = await router.orderRoutes({ destination: 'other.com', exits });
  assert.equal(other.routes[0], germany);
});

test('exit health expires by TTL and explicit success restores an exit immediately', async () => {
  let time = 1000;
  const router = createRouter({ now: () => time, failureTtlMs: 30 }), germany = exits.find(item => item.country === 'DE');
  router.reportFailure({ destination: 'business.com', exit: germany });
  time += 31;
  assert.equal((await router.orderRoutes({ destination: 'business.com', exits })).routes[0], germany);
  router.reportFailure({ destination: 'business.com', exit: germany });
  assert(!(await router.orderRoutes({ destination: 'business.com', exits })).routes.includes(germany));
  router.reportSuccess({ destination: 'business.com', exit: germany });
  assert.equal((await router.orderRoutes({ destination: 'business.com', exits })).routes[0], germany);
});

test('health state is bounded and failure of every available exit never injects a direct route', async () => {
  const bounded = createRouter({ healthMaxEntries: 2 });
  for (const item of exits) {
    bounded.reportFailure({ destination: 'business.com', exit: item });
    assert(bounded.stats().healthEntries <= 2);
  }
  const router = createRouter();
  for (const item of exits) router.reportFailure({ destination: 'business.com', exit: item });
  assert.equal((await router.orderRoutes({ destination: 'business.com', exits })).routes.length, 0);
});

test('manual mode preserves reference order and ignores country resolution and health', async () => {
  let calls = 0;
  const router = createRouter({ resolveCountry: async () => { calls++; return 'US'; } });
  for (const item of exits) router.reportFailure({ destination: 'business.com', exit: item });
  const result = await router.orderRoutes({ destination: 'business.com', exits, manual: true });
  assert.equal(result.source, 'manual'); assert.equal(result.routes.length, exits.length);
  result.routes.forEach((route, index) => assert.equal(route, exits[index]));
  assert.equal(calls, 0);
  const iranManual = await router.orderRoutes({ destination: 'chatgpt.com', exits: [exits[0]], manual: true });
  assert.equal(iranManual.routes[0], exits[0], 'Manual selection is not overridden by AI policy');
});

test('custom exit-country and identity adapters preserve original application objects', async () => {
  const custom = [{ location: 'US', id: 'first' }, { location: 'DE', id: 'second' }];
  const router = createRouter({ countryOfExit: item => item.location, exitKey: item => item.id });
  assert.equal((await router.orderRoutes({ destination: 'business.com', exits: custom })).routes[0], custom[1]);
  router.reportFailure({ destination: 'business.com', exit: custom[1] });
  const failed = await router.orderRoutes({ destination: 'business.com', exits: custom });
  assert.equal(failed.routes.length, 1); assert.equal(failed.routes[0], custom[0]);
});
