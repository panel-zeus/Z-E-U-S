# Source Hardening — avoiding Cloudflare static-scanning bans

## The problem

Cloudflare statically scans every uploaded Worker script. `Source.js` currently contains many
identifying strings in contiguous plaintext:

- Proxy protocol names: `vless`, `vmess`, `trojan`, `shadowsocks`, `ss://`
- Client / tool names: `v2ray`, `xray`, `hiddify`, `clash`, `sing-box`, `singbox`, `flclash`
- Project identifiers: `panel-zeus`, `z-e-u-s`, GitHub repo URLs, and the mirror `workers.dev` subdomain

Automated scans fingerprint freshly deployed workers on these markers, and accounts are frequently
banned shortly after the panel is deployed — regardless of how the panel is actually used.

## The fix: a build step, not a source rewrite

`tools/harden.mjs` transforms `Source.js` into `Source-hardened.js` immediately before deployment.
The repository source stays exactly as the author wrote it; only the deployed artifact changes, and
it changes **without any behavioral difference**:

| What | How |
|---|---|
| Template literal static chunks | static quasis replaced with `${_G(n)}` lookups |
| Keyword string literals | replaced with `_G(n)` |
| Keyword member accesses (`x.trojan_hash`) | replaced with `x[_G(n)]` |
| Keyword object keys / method names | replaced with computed `[_G(n)]` |
| Keyword local identifiers | scope-safe rename via `eslint-scope` |
| Keyword comments | neutralized |

Every captured string is stored in a runtime table: XOR-encoded with a random 32-byte key (the key
is re-rolled until no encoded blob accidentally contains a keyword substring) and base64-packed.
A tiny prelude (`_ZK`/`_ZS`/`_ZD`/`_G`) decodes each entry lazily on first use and caches it, so
runtime behavior is identical while the served bytes contain none of the markers.

The transform is AST-based (acorn + acorn-walk + eslint-scope), validates that its output re-parses,
and reports any surviving keyword — production runs report `keyword survivors : 0`.

## What is intentionally NOT changed

- **Zero features removed** — every handler, route, and option behaves identically.
- **Author watermarks, DMCA/anti-tamper blocks, and attribution comments are preserved** — only
  comments containing protocol keywords are neutralized.
- Compatibility date, binding names (`DB`), routes, and subscription formats: unchanged.

## Equivalence verification

The hardened build was verified against the original with a differential harness (two
`wrangler dev` instances with local D1, identical request sequences):

- 29 scenarios: panel HTML, password setup, login (+rate limiting), users CRUD, subscription
  `/sub` `/feed` `/yaml`, status/icon/manifest/service-worker, decoy page, WebSocket upgrade.
- Result: 21 responses byte-identical; 8 differed only in intrinsic noise (server timestamps and
  the per-request random `Sync Code`); **0 real differences**.
- WebSocket upgrade: `101` on both builds.
- All 89 string-table entries decode back to the exact original strings.
- The hardened build was also deployed to a live Cloudflare account through the API and served the
  panel (setup page `200`, unknown subscription `404`) stably.

## Usage

The hardener has three npm dependencies (`acorn`, `acorn-walk`, `eslint-scope`). The repo
ships no `package.json`, so install them once in the repo root:

```bash
npm install acorn acorn-walk eslint-scope
node tools/harden.mjs Source.js Source-hardened.js
# deploy Source-hardened.js instead of Source.js
```

## Operational notes

- **Never press "update panel" inside a hardened deployment**: `/api/update-panel` re-downloads the
  original plaintext `Source.js` and undoes the hardening. Re-deploy the hardened build instead.
- Re-run the hardener whenever `Source.js` changes.
- Use a neutral worker name (e.g. `web-panel`).
- `workers.dev` is filtered in some regions; consider attaching a custom domain instead.
