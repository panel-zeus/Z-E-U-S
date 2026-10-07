#!/usr/bin/env node
/*
 * Zeus Install Wizard — نصب خودکار پنل Zeus (نسخه مقاوم‌شده) روی Cloudflare
 * مشابه جریان BPB-Wizard: توکن → اکانت → D1 → آپلود ورکر → subdomain → دامنه سفارشی
 *
 * Usage:
 *   node zeus-wizard.mjs                (حالت تعاملی کامل)
 *   node zeus-wizard.mjs --prepare-only (فقط آماده‌سازی سورس، بدون هیچ درخواست شبکه‌ای به کلادفلر)
 *
 * Requirement: Node.js 18+
 */
import { readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import readline from 'node:readline/promises';
import { Writable } from 'node:stream';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const API = 'https://api.cloudflare.com/client/v4';
const UPSTREAM = 'https://raw.githubusercontent.com/panel-zeus/Z-E-U-S/refs/heads/main/Source.js';
const TOKEN_URL = 'https://dash.cloudflare.com/profile/api-tokens';
// لینک آماده‌ی ساخت توکن با دقیقاً دسترسی‌های موردنیاز Zeus (Workers Script, D1, Subdomain, ...)
const TOKEN_CREATE_URL = 'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22workers_scripts%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22workers_kv_storage%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22d1%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22workers_subdomain%22%2C%22type%22%3A%22edit%22%7D%2C%7B%22key%22%3A%22account_analytics%22%2C%22type%22%3A%22read%22%7D%5D&accountId=*&zoneId=all';
const COMPAT_DATE = '2024-09-23';

const KEYWORDS = ['vless','vmess','trojan','shadowsocks','v2ray','xray','hiddify','clash','sing-box','singbox','flclash','panel-zeus','z-e-u-s','hxxyrukih4kvmeawzmdmug2eh5uwtcmt','ss://'];
const KW_RE = new RegExp(KEYWORDS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'i');

let TOKEN = '';
let step = 0;
const totalSteps = 9;

// ---------------------------------------------------------------- UI helpers
const line = '─'.repeat(58);
function banner() {
  console.log(`
${line}
   ⚡ Zeus Install Wizard — نصب خودکار پنل Zeus مقاوم‌شده
${line}
   این ویزارد این کارها را انجام می‌دهد:
   ۱. اعتبارسنجی API Token کلادفلر
   ۲. انتخاب اکانت و نام ورکر
   ۳. ساخت دیتابیس D1 و اتصال آن
   ۴. آماده‌سازی سورس مقاوم‌شده (بدون کلمات قابل‌شناسایی)
   ۵. آپلود ورکر و فعال‌سازی آدرس workers.dev
   ۶. (اختیاری) اتصال دامنه سفارشی
${line}`);
}

// ---- ورودی پایپ‌شده (برای تست خودکار): اگر stdin پایپ باشد، readline غیر TTY
// همه‌ی خط‌ها را یک‌جا می‌خواند و خط‌های بدون سوالِ در انتظار را از دست می‌دهد؛
// پس در این حالت کل stdin را از پیش می‌خوانیم و هر سوال جوابش را از صف برمی‌دارد.
let pipedLines = null;
let pipedIdx = 0;
async function loadPipedInput() {
  if (process.stdin.isTTY) return;
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  pipedLines = Buffer.concat(chunks).toString('utf8').split(/\r?\n/);
  if (pipedLines.length && pipedLines[pipedLines.length - 1] === '') pipedLines.pop();
}
function nextPiped() {
  if (!pipedLines || pipedIdx >= pipedLines.length) return null;
  return pipedLines[pipedIdx++];
}

async function ask(rl, q, def = '') {
  const prompt = `  ${q}${def ? ` [${def}]` : ''}: `;
  if (pipedLines) {
    const a = nextPiped();
    if (a === null) {
      if (def) { console.log(prompt + def + '   (پیش‌فرض — ورودی پایپ تمام شده بود)'); return def; }
      fail('ورودی پایپ‌شده تمام شد و پاسخی برای این سوال نماند: ' + q);
    }
    console.log(prompt + (a === '' && def ? `${def}   (پیش‌فرض)` : a));
    return a || def;
  }
  const a = (await rl.question(prompt)).trim();
  return a || def;
}

async function askSecret(rl, q) {
  const prompt = `  ${q}: `;
  if (pipedLines) {
    let a = nextPiped();
    while (a === '') a = nextPiped(); // توکن تهی بی‌معنی است؛ خط‌های تهی را رد کن
    if (a === null) fail('ورودی پایپ‌شده تمام شد و مقداری برای «' + q + '» نماند.');
    console.log(prompt + '••••••••   (از ورودی استاندارد خوانده شد)');
    return a.trim();
  }
  // ورودی پنهان روی همان اینترفیس: خروجی موقتاً بی‌صدا می‌شود تا کاراکترها echo نشوند
  const orig = rl.output;
  const muted = new Writable({
    write(chunk, _enc, cb) {
      if (String(chunk).includes('\n')) orig.write('\n');
      cb();
    },
  });
  let a = '';
  try {
    orig.write(prompt);
    rl.output = muted;
    do { a = (await rl.question('')).trim(); } while (!a);
  } finally { rl.output = orig; }
  return a;
}

function ok(msg) { console.log(`  ✅ ${msg}`); }
function warn(msg) { console.log(`  ⚠️  ${msg}`); }
let activeRl = null; // برای خروج تمیز از readline (جلوگیری از assertion ویندوز)
function fail(msg, hint) {
  console.error(`\n  ❌ ${msg}`);
  if (hint) console.error(`     💡 ${hint}`);
  process.exitCode = 1;
  try { process.stdin.pause(); } catch {}
  try { activeRl && activeRl.close(); } catch {}
  throw { __zeusExit: true };
}
function nextStep(title) {
  step++;
  console.log(`\n${line}\n  [${step}/${totalSteps}] ${title}\n${line}`);
}

// ---------------------------------------------------------------- CF helpers
async function cf(path, { method = 'GET', body, headers = {}, raw = false } = {}) {
  let res;
  try {
    res = await fetch(API + path, {
      method,
      headers: { Authorization: `Bearer ${TOKEN}`, ...(body && !(body instanceof FormData) ? { 'Content-Type': 'application/json' } : {}), ...headers },
      body: typeof body === 'string' || body instanceof FormData ? body : body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    fail(`اتصال به api.cloudflare.com برقرار نشد (${e.message})`, 'اتصال اینترنت یا فیلترشکن خود را بررسی کنید.');
  }
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { success: false, errors: [{ code: res.status, message: text.slice(0, 200) }] }; }
  if (!res.ok || data.success === false) {
    const errs = (data.errors || []).map((e) => `کد ${e.code}: ${e.message}`).join(' | ') || `HTTP ${res.status}`;
    return { ok: false, status: res.status, errors: errs, data };
  }
  return { ok: true, status: res.status, data };
}

// ------------------------------------------------------- source preparation
async function prepareSource(rl) {
  const hardenedPath = join(ROOT, 'Source-hardened.js');
  const originalPath = join(ROOT, 'Source.js');
  const hardenTool = join(ROOT, 'tools', 'harden.mjs');

  if (existsSync(hardenedPath) && !process.env.ZEUS_FORCE_REHARDEN) {
    // اگر نسخه آماده موجوده، مستقیم استفاده می‌کنیم
    return { path: hardenedPath, fresh: false };
  }

  console.log('  فایل Source-hardened.js پیدا نشد. روش آماده‌سازی را انتخاب کنید:');
  console.log('    1) دانلود آخرین سورس Zeus از گیت‌هاب و مقاوم‌سازی (پیشنهادی)');
  console.log('    2) مقاوم‌سازی سورس محلی موجود (Source.js)');
  const choice = await ask(rl, 'روش آماده‌سازی (1/2)', '1');

  let srcPath;
  if (choice === '2') {
    if (!existsSync(originalPath)) fail('سورس محلی پیدا نشد: ' + originalPath);
    srcPath = originalPath;
  } else {
    srcPath = join(ROOT, 'Source.js');
    console.log('  ⏳ در حال دانلود سورس از گیت‌هاب ...');
    try {
      const res = execFileSync('curl', ['-fsSL', '--max-time', '120', UPSTREAM], { encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
      writeFileSync(srcPath, res);
      ok(`سورس دانلود شد (${(res.length / 1024).toFixed(0)}KB)`);
    } catch (e) {
      fail('دانلود سورس ناموفق بود: ' + (e.message || e), 'با VPN امتحان کنید یا گزینه ۲ را انتخاب کنید.');
    }
  }

  console.log('  ⏳ در حال مقاوم‌سازی سورس (حذف کلمات قابل‌شناسایی) ...');
  const r = spawnSync(process.execPath, [hardenTool, srcPath, hardenedPath], {
    cwd: join(ROOT, 'tools'), encoding: 'utf8',
  });
  if (r.status !== 0 || !existsSync(hardenedPath)) {
    fail('مقاوم‌سازی ناموفق بود', (r.stderr || r.stdout || '').slice(-600));
  }
  ok(r.stdout.trim().split('\n').filter((l) => /survivors|output size|table entries/.test(l)).join('  —  '));
  return { path: hardenedPath, fresh: true };
}

function scanKeywords(p) {
  const src = readFileSync(p, 'utf8');
  const hits = src.split('\n').filter((l) => KW_RE.test(l)).length;
  return { size: src.length, hits };
}

// ---------------------------------------------------------------- main
async function main() {
  banner();
  const prepareOnly = process.argv.includes('--prepare-only');

  await loadPipedInput();
  const rl = pipedLines ? null : readline.createInterface({ input: process.stdin, output: process.stdout });
  activeRl = rl;
  const cleanup = () => { try { rl && rl.close(); } catch {} };
  process.on('SIGINT', () => { console.log('\n\nلغو شد.'); cleanup(); process.exit(130); });

  // ---------- [1/9] token
  nextStep('اعتبارسنجی API Token');
  console.log('  این لینک را باز کنید — توکن با دسترسی‌های دقیق موردنیاز Zeus از پیش تنظیم می‌شود:');
  console.log(`     ${TOKEN_CREATE_URL}`);
  console.log('  (فقط Continue to summary → Create Token و کپی توکن)');
  TOKEN = await askSecret(rl, 'API Token کلادفلر را وارد کنید');
  const verify = await cf('/user/tokens/verify');
  if (!verify.ok) fail('توکن نامعتبر است (' + verify.errors + ')', 'توکن را دوباره با دسترسی‌های گفته‌شده بسازید.');
  ok('توکن معتبر است' + (verify.data.result?.status ? ` (وضعیت: ${verify.data.result.status})` : ''));

  // ---------- [2/9] account
  nextStep('انتخاب اکانت');
  let accounts = await cf('/accounts?per_page=50');
  let accountId, accountName;
  if (!accounts.ok || !accounts.data.result?.length) {
    warn('لیست اکانت‌ها با این توکن قابل دریافت نیست (' + (accounts.errors || 'بدون دسترسی') + ')');
    accountId = await ask(rl, 'Account ID اکانت خود را دستی وارد کنید (از صفحه‌ی overview دامنه/ورکر)');
    if (!/^[a-f0-9]{32}$/i.test(accountId)) fail('فرمت Account ID معتبر نیست (۳۲ کاراکتر hex).');
    accountName = accountId;
  } else if (accounts.data.result.length === 1) {
    accountId = accounts.data.result[0].id;
    accountName = accounts.data.result[0].name;
    ok(`اکانت: ${accountName}`);
  } else {
    accounts.data.result.forEach((a, i) => console.log(`     ${i + 1}) ${a.name}  (${a.id.slice(0, 8)}...)`));
    const idx = parseInt(await ask(rl, 'شماره اکانت', '1'), 10);
    const picked = accounts.data.result[idx - 1];
    if (!picked) fail('انتخاب نامعتبر است.');
    accountId = picked.id; accountName = picked.name;
    ok(`اکانت: ${accountName}`);
  }

  // ---------- [3/9] worker name
  nextStep('نام ورکر');
  console.log('  نکته: اسمی بی‌طرف انتخاب کنید (مثل web-panel یا my-api) — اسم‌های مشکوک شانس بن را بالا می‌برد.');
  const workerName = (await ask(rl, 'نام ورکر', 'web-panel')).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  if (!/^[a-z0-9][a-z0-9-]{0,57}$/.test(workerName)) fail('نام ورکر فقط می‌تواند حروف کوچک، عدد و خط تیره باشد.');

  // ---------- [4/9] subdomain
  nextStep('آدرس workers.dev');
  let subdomain = '';
  const sub = await cf(`/accounts/${accountId}/workers/subdomain`);
  if (sub.ok && sub.data.result?.subdomain) {
    subdomain = sub.data.result.subdomain;
    ok(`آدرس نهایی خواهد بود: https://${workerName}.${subdomain}.workers.dev`);
  } else {
    warn('دریافت subdomain ناموفق بود (' + (sub.errors || '') + ') — ادامه می‌دهیم.');
  }
  warn('توجه: workers.dev در ایران فیلتر است؛ برای استفاده داخل ایران دامنه سفارشی وصل کنید (قدم پایانی).');

  // ---------- [5/9] D1
  nextStep('ساخت دیتابیس D1');
  const dbName = workerName + '-db';
  let dbId = '';
  const listDb = await cf(`/accounts/${accountId}/d1/database?name=${encodeURIComponent(dbName)}`);
  const existing = listDb.ok && (listDb.data.result || []).find((d) => d.name === dbName);
  if (existing) {
    dbId = existing.uuid;
    ok(`دیتابیس موجود استفاده می‌شود: ${dbName} (${dbId.slice(0, 8)}...)`);
  } else {
    const created = await cf(`/accounts/${accountId}/d1/database`, { method: 'POST', body: { name: dbName } });
    if (!created.ok) fail('ساخت دیتابیس D1 ناموفق بود (' + created.errors + ')', 'مطمئن شوید توکن دسترسی D1/Edit دارد و اکانت شما D1 دارد (رایگان هم دارد).');
    dbId = created.data.result.uuid;
    ok(`دیتابیس ساخته شد: ${dbName}`);
  }

  // ---------- [6/9] source
  nextStep('آماده‌سازی سورس مقاوم‌شده');
  const src = await prepareSource(rl);
  const scan = scanKeywords(src.path);
  if (scan.hits > 0) fail(`سورس هنوز ${scan.hits} خط حاوی کلمه‌ی قابل‌شناسایی دارد!`);
  ok(`سورس آماده است: ${src.path} (${(scan.size / 1024).toFixed(0)}KB، بدون هیچ کلمه‌ی قابل‌شناسایی)`);

  // ---------- [7/9] upload
  nextStep('آپلود ورکر');
  const exists = await cf(`/accounts/${accountId}/workers/scripts/${workerName}`);
  if (exists.ok) {
    const overwrite = await ask(rl, `ورکر «${workerName}» از قبل وجود دارد؛ بازنویسی شود؟ (y/n)`, 'y');
    if (overwrite.toLowerCase() !== 'y') fail('لغو شد توسط کاربر.');
  }
  const form = new FormData();
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: COMPAT_DATE,
    bindings: [{ type: 'd1', name: 'DB', id: dbId }],
  };
  form.append('metadata', new File([JSON.stringify(metadata)], 'metadata.json', { type: 'application/json' }));
  form.append('worker.js', new File([readFileSync(src.path)], 'worker.js', { type: 'application/javascript+module' }));
  const up = await cf(`/accounts/${accountId}/workers/scripts/${workerName}`, { method: 'PUT', body: form });
  if (!up.ok) fail('آپلود ورکر ناموفق بود (' + up.errors + ')', up.status === 413 ? 'حجم اسکریپت زیاد است — نسخه‌ی دیگری از سورس بسازید.' : 'دسترسی Workers Scripts/Edit را در توکن چک کنید.');
  ok(`ورکر آپلود شد (${(scan.size / 1024).toFixed(0)}KB، اتصال D1: ${dbName})`);

  // ---------- [8/9] enable workers.dev
  nextStep('فعال‌سازی آدرس عمومی');
  const en = await cf(`/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, {
    method: 'POST', body: { enabled: true, previews_enabled: false },
  });
  if (!en.ok) warn('فعال‌سازی subdomain ناموفق بود (' + en.errors + ') — می‌توانید از داشبورد فعالش کنید.');
  else ok(`فعال شد: https://${workerName}${subdomain ? '.' + subdomain : ''}.workers.dev`);

  // ---------- [9/9] health check + summary
  nextStep('بررسی نهایی و خلاصه');
  const panelUrl = `https://${workerName}${subdomain ? '.' + subdomain : ''}.workers.dev/panel`;
  let reachable = false;
  try {
    const probe = await fetch(`https://${workerName}${subdomain ? '.' + subdomain : ''}.workers.dev/`, { signal: AbortSignal.timeout(12000) });
    reachable = probe.status >= 200 && probe.status < 500;
  } catch { reachable = false; }
  if (reachable) ok('ورکر در دسترس و پاسخ می‌دهد ✔');
  else warn('از این سیستم به آدرس workers.dev دسترسی نبود — اگر داخل ایران هستید طبیعی است (فیلتر بودن workers.dev)، نصب سالم انجام شده.');

  console.log(`
${line}
  🎉 نصب کامل شد!

     آدرس پنل (برای اولین تنظیم رمز):
       ${panelUrl}

     الگوی اشتراک کاربرها:
       https://${workerName}${subdomain ? '.' + subdomain : ''}.workers.dev/sub/<username>

${line}
  ⚠️  سه نکته‌ی مهم:
     ۱. هرگز از دکمه «آپدیت پنل» داخل خود پنل استفاده نکنید — سورس قابل‌شناسایی
        را برمی‌گرداند و هاردنینگ از بین می‌رود.
     ۲. برای استفاده داخل ایران، از قدم دامنه سفارشی استفاده کنید یا همین حالا
        آن را انجام دهید.
     ۳. API Token خود را محرمانه نگه دارید؛ این ویزارد آن را ذخیره نمی‌کند.
${line}`);

  // ---------- optional custom domain
  const wantDomain = await ask(rl, 'آیا دامنه سفارشی دارید و می‌خواهید وصل کنید؟ (y/n)', 'n');
  if (wantDomain.toLowerCase() === 'y') {
    const zones = await cf('/zones?per_page=50');
    if (!zones.ok || !zones.data.result?.length) {
      warn('لیست دامنه‌ها دریافت نشد (' + (zones.errors || 'دسترسی Zone:Read لازم است') + '). می‌توانید بعداً از داشبورد انجام دهید.');
    } else {
      zones.data.result.forEach((z, i) => console.log(`     ${i + 1}) ${z.name}`));
      const zi = parseInt(await ask(rl, 'شماره دامنه', '1'), 10);
      const zone = zones.data.result[zi - 1];
      if (!zone) warn('انتخاب نامعتبر؛ رد شد.');
      else {
        const hostname = (await ask(rl, `زیر‌دامنه‌ی موردنظر روی ${zone.name} (مثلاً panel)`, 'panel')) + '.' + zone.name;
        const cd = await cf(`/accounts/${accountId}/workers/domains`, {
          method: 'POST',
          body: { environment: 'production', hostname, service: workerName, zone_id: zone.id },
        });
        if (!cd.ok) warn('اتصال دامنه ناموفق بود (' + cd.errors + ') — از داشبورد: Workers → Settings → Domains');
        else {
          ok(`دامنه وصل شد: https://${hostname}/panel`);
          console.log(`     (رکورد DNS و گواهی به‌صورت خودکار ساخته می‌شود؛ چند دقیقه صبر کنید)`);
        }
      }
    }
  }

  cleanup();
  console.log('\nپایان. موفق باشید 🌐');
}

// آماده‌سازی سورس بدون نیاز به توکن/شبکه‌ی کلادفلر (برای تست)
async function prepareOnlyMain() {
  await loadPipedInput();
  const rl = pipedLines ? null : readline.createInterface({ input: process.stdin, output: process.stdout });
  activeRl = rl;
  console.log('حالت prepare-only: فقط آماده‌سازی سورس\n');
  const src = await prepareSource(rl);
  const scan = scanKeywords(src.path);
  console.log(`  فایل: ${src.path}`);
  console.log(`  حجم: ${(scan.size / 1024).toFixed(0)}KB | کلمات قابل‌شناسایی: ${scan.hits}`);
  if (rl) rl.close();
  if (scan.hits > 0) { process.exitCode = 2; return; }
  console.log('  ✅ آماده‌سازی موفق');
}

function onUnhandled(e) {
  if (e && e.__zeusExit) return; // خروج کنترل‌شده توسط fail()
  console.error(e && e.stack || e);
  process.exitCode = 1;
}

if (process.argv.includes('--prepare-only')) {
  prepareOnlyMain().catch(onUnhandled);
} else {
  main().catch(onUnhandled);
}
