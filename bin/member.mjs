#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { appOf, fail, quote, requireEmail, sql, wranglerConfig } from './lib.mjs';
// Aggiunge o aggiorna un membro dell'app: npx dp-auth-member <email> --role owner|member|viewer [--name "Nome"] [--local] [--remove]
// L'app è AUTH_APP in wrangler.jsonc (vars), altrimenti il nome del Worker.
const args = process.argv.slice(2), local = args.includes('--local'), remove = args.includes('--remove');
const option = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const email = requireEmail(args.find(a => !a.startsWith('--') && a !== option('--role') && a !== option('--name')));
const role = option('--role') ?? 'member', name = option('--name') ?? null;
if (!['owner', 'member', 'viewer'].includes(role)) fail('Ruolo non valido: owner, member o viewer.');
const config = wranglerConfig(), app = appOf(config), at = new Date().toISOString();
if (remove) {
  sql(`DELETE FROM members WHERE app=${quote(app)} AND email=${quote(email)};
    DELETE FROM sessions WHERE email=${quote(email)} AND NOT EXISTS (SELECT 1 FROM members WHERE email=${quote(email)});
    DELETE FROM passkeys WHERE email=${quote(email)} AND NOT EXISTS (SELECT 1 FROM members WHERE email=${quote(email)});
    DELETE FROM users WHERE email=${quote(email)} AND NOT EXISTS (SELECT 1 FROM members WHERE email=${quote(email)});
    INSERT INTO auth_events (at,email,event,detail) VALUES (${quote(at)},${quote(email)},'access_revoked',${quote(`${app} · cli`)});`, local);
  console.log(`Accesso a ${app} rimosso per ${email}.`);
} else {
  sql(`INSERT OR IGNORE INTO users (email,webauthn_id,created_at) VALUES (${quote(email)},${quote(randomBytes(32).toString('hex'))},${quote(at)});
    INSERT INTO members (app,email,role,name) VALUES (${quote(app)},${quote(email)},${quote(role)},${name === null ? 'NULL' : quote(name)}) ON CONFLICT(app,email) DO UPDATE SET role=excluded.role, name=COALESCE(excluded.name, members.name);
    INSERT INTO auth_events (at,email,event,detail) VALUES (${quote(at)},${quote(email)},'access_granted',${quote(`${app} · ${role} · cli`)});`, local);
  console.log(`${email} è ${role} di ${app}${local ? ' (locale)' : ''}. ${role === 'owner' ? 'Crea il link di attivazione con npx dp-auth-link.' : 'Può accedere con il codice via email.'}`);
}
