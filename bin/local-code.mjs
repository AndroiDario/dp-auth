#!/usr/bin/env node
import { clipboard, fail, sql } from './lib.mjs';
// Ultimo codice di accesso dell'archivio locale (auth_outbox), copiato negli appunti senza stamparlo.
// Online i codici arrivano via email: auth_outbox si usa solo in locale senza chiave Resend. Uso: npx dp-auth-code [--print]
const print = process.argv.includes('--print');
const [message] = sql('SELECT email, text FROM auth_outbox ORDER BY created_at DESC LIMIT 1', true)[0]?.results ?? [];
const code = message && /è (\d{6})\./.exec(message.text)?.[1];
if (!code) fail('Nessun codice nell’archivio locale.');
sql('DELETE FROM auth_outbox', true);
if (print) console.log(code);
else { await clipboard(code).catch(() => fail('Copia negli appunti non riuscita: usa --print.')); console.log(`Codice per ${message.email} copiato negli appunti.`); }
