#!/usr/bin/env node
import { createHash, randomBytes } from 'node:crypto';
import { clipboard, fail, originOf, quote, requireEmail, sql, wranglerConfig } from './lib.mjs';
// Link di attivazione della passkey: owner senza passkey e recupero dopo la perdita dei dispositivi.
// Nel D1 va solo l'hash del token. Il link è copiato negli appunti senza stamparlo. Vale una volta per 15 minuti.
// Uso: npx dp-auth-link <email> [--local] [--print]
const args = process.argv.slice(2), local = args.includes('--local'), print = args.includes('--print');
const email = requireEmail(args.find(a => !a.startsWith('--')));
const token = randomBytes(32).toString('base64url'), id = createHash('sha256').update(token).digest('hex');
const expires = new Date(Date.now() + 15 * 60000);
const result = sql(`DELETE FROM auth_challenges WHERE kind='link' AND email=${quote(email)}; INSERT INTO auth_challenges (id,kind,email,secret,attempts,expires_at) SELECT ${quote(id)},'link',email,'',0,${quote(expires.toISOString())} FROM users WHERE email=${quote(email)};`, local);
if (result.at(-1)?.meta?.changes !== 1) fail('Account inesistente. Aggiungi prima l’indirizzo con npx dp-auth-member.');
const config = wranglerConfig();
const url = `${originOf(config, local)}${config.vars?.AUTH_LOGIN_PATH ?? '/login'}/attiva#${token}`;
const time = new Intl.DateTimeFormat('it-IT', { timeStyle: 'short', timeZone: 'Europe/Rome' }).format(expires);
if (print) console.log(url);
else {
  await clipboard(url).catch(() => fail('Copia negli appunti non riuscita: usa --print.'));
  console.log(`Link di attivazione per ${email} copiato negli appunti. Scade alle ${time} Europe/Rome.`);
}
