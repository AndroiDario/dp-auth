import { readFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
// Funzioni comuni degli script: lettura di wrangler.jsonc dell'app, esecuzione SQL con Wrangler, copia negli appunti.

export function fail(message) { console.error(message); process.exit(1); }
export const emailPattern = /^[^\s@'"<>]+@[^\s@'"<>]+\.[a-z]{2,}$/i;
export function requireEmail(value) {
  const email = value?.trim().toLowerCase();
  if (!email || email.length > 254 || !emailPattern.test(email)) fail('Indirizzo email non valido.');
  return email;
}
/** wrangler.jsonc dell'app corrente, senza commenti. */
export function wranglerConfig() {
  try {
    const text = readFileSync('wrangler.jsonc', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1');
    return JSON.parse(text);
  } catch { fail('wrangler.jsonc non trovato: eseguire dalla cartella dell’app.'); }
}
/** Esegue SQL sul D1 dell'app, locale o remoto, e restituisce i risultati JSON. */
export function sql(statement, local) {
  const config = wranglerConfig();
  const binding = config.d1_databases?.[0]?.binding ?? 'DB';
  const result = spawnSync('npx', ['wrangler', 'd1', 'execute', binding, local ? '--local' : '--remote', '--json', '--command', statement], {
    encoding: 'utf8', env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: process.env.CLOUDFLARE_ACCOUNT_ID ?? config.account_id ?? '', WRANGLER_LOG_PATH: '.local/wrangler.log', WRANGLER_SEND_METRICS: 'false' },
  });
  if (result.status !== 0) fail(`Wrangler non riuscito: ${result.stderr.split('\n').filter(l => /ERROR|✘/.test(l)).join(' ').slice(0, 300)}`);
  return JSON.parse(result.stdout);
}
export const quote = value => `'${String(value).replace(/'/g, "''")}'`;
export async function clipboard(text) {
  const copy = spawn('pbcopy', [], { stdio: ['pipe', 'ignore', 'inherit'] });
  copy.stdin.end(text);
  await new Promise((resolve, reject) => { copy.on('exit', code => code === 0 ? resolve() : reject(new Error('Copia non riuscita.'))); copy.on('error', reject); });
}
export const originOf = (config, local) => local ? 'http://localhost:8787' : (config.vars?.AUTH_ORIGIN ?? fail('AUTH_ORIGIN assente in wrangler.jsonc.'));
export const appOf = config => config.vars?.AUTH_APP ?? config.name ?? fail('Nome dell’app assente in wrangler.jsonc.');
