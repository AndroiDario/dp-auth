import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { D1PreparedStatement } from '@cloudflare/workers-types';
import type { AuthEnv } from '../src/types.ts';
// D1 simulato con node:sqlite: stesse migrazioni della produzione, database in memoria per ogni test.
export function testEnv(extra: Partial<AuthEnv> = {}) {
  const database = new DatabaseSync(':memory:');
  const migrations = join(fileURLToPath(import.meta.url), '..', '..', 'migrations');
  for (const file of readdirSync(migrations).filter(f => f.endsWith('.sql')).sort()) database.exec(readFileSync(join(migrations, file), 'utf8'));
  function statement(sql: string, args: unknown[] = []): D1PreparedStatement {
    const params = args as (string | number | null)[];
    return {
      bind(...values: unknown[]) { return statement(sql, values); },
      async first() { return database.prepare(sql).get(...params) ?? null; },
      async all() { return { results: database.prepare(sql).all(...params), success: true, meta: {} }; },
      async run() { const result = database.prepare(sql).run(...params); return { results: [], success: true, meta: { changes: Number(result.changes) } }; },
    } as unknown as D1PreparedStatement;
  }
  const env = {
    DB: {
      prepare: statement,
      async batch(statements: D1PreparedStatement[]) {
        database.exec('BEGIN');
        try { const result = []; for (const s of statements) result.push(await s.run()); database.exec('COMMIT'); return result; }
        catch (error) { database.exec('ROLLBACK'); throw error; }
      },
    },
    ...extra,
  } as unknown as AuthEnv;
  return { env, database };
}
