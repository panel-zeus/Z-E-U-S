import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { fixture } from './helpers/worker-fixture.mjs';
test('legacy backfill runs once across cold isolates and its marker is committed in the same batch', async t => {
  let marker = false, batches = 0; const indexes = new Set();
  const db = { prepare(sql) { return { sql, async run() { if (sql.startsWith('CREATE INDEX')) indexes.add(sql); },
    async all() { return { results: [] }; }, async first() { return marker ? { value: '1' } : null; } }; },
    async batch(statements) {
      assert.equal(statements.length, 3);
      assert(statements[0].sql.includes('UPDATE users SET ip_limit'));
      assert(statements[1].sql.includes('UPDATE users SET lifetime_used_gb'));
      assert(statements[2].sql.includes('INSERT OR IGNORE INTO settings'));
      marker = true; batches++;
    } };
  for (let i=0;i<3;i++) {
    const f = fixture(t); f.context.testDb=db;
    await vm.runInContext('DbService.ensureSchema(testDb)', f.context);
  }
  assert.equal(batches, 1); assert.equal(indexes.size, 5);
});
test('failed backfill transaction is retried by a later isolate', async t => {
  let attempts=0;
  const db = { prepare(sql) { return { sql, async run() {}, async all() {return {results:[]};}, async first() {return null;} }; },
    async batch() { attempts++; throw Error('Synthetic rollback'); } };
  for (let i=0;i<2;i++) { const f=fixture(t); f.context.testDb=db; await vm.runInContext('DbService.ensureSchema(testDb)',f.context); }
  assert.equal(attempts,2);
});
