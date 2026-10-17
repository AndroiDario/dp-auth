import { logEvent, randomHex } from './session.ts';
import type { AuthEnv, Member, Role } from './types.ts';
// Chi può accedere a un'app e con quale ruolo. La tabella `members` è per app; `users` è condivisa dalle app sullo stesso D1.
// owner: solo passkey. member e viewer: passkey o codice via email, salvo l'opzione «solo passkey».

export const roles: Role[] = ['owner', 'member', 'viewer'];
export const isRole = (value: unknown): value is Role => typeof value === 'string' && (roles as string[]).includes(value);

export async function memberOf(env: AuthEnv, app: string, email: string): Promise<Member | null> {
  return env.DB.prepare('SELECT m.email, m.role, m.name FROM members m JOIN users u ON u.email=m.email WHERE m.app=? AND m.email=?').bind(app, email).first<Member>();
}
export async function membersOf(env: AuthEnv, app: string): Promise<(Member & { lastLoginAt: string | null; passkeys: number })[]> {
  const { results } = await env.DB.prepare(`SELECT m.email, m.role, m.name, u.last_login_at AS lastLoginAt,
    (SELECT COUNT(*) FROM passkeys p WHERE p.email=m.email) AS passkeys
    FROM members m JOIN users u ON u.email=m.email WHERE m.app=? ORDER BY m.role='viewer', m.role='member', m.email`).bind(app).all<Member & { lastLoginAt: string | null; passkeys: number }>();
  return results;
}
/** Aggiunge o aggiorna un membro. Crea l'account se manca, con user handle casuale. */
export async function addMember(env: AuthEnv, app: string, email: string, role: Role, name: string | null, actor: string, now = new Date()): Promise<void> {
  const at = now.toISOString();
  await env.DB.batch([
    env.DB.prepare('INSERT OR IGNORE INTO users (email,webauthn_id,created_at) VALUES (?,?,?)').bind(email, randomHex(), at),
    env.DB.prepare('INSERT INTO members (app,email,role,name) VALUES (?,?,?,?) ON CONFLICT(app,email) DO UPDATE SET role=excluded.role, name=COALESCE(excluded.name, members.name)').bind(app, email, role, name),
    env.DB.prepare("INSERT INTO auth_events (at,email,event,detail) VALUES (?,?,'access_granted',?)").bind(at, email, `${app} · ${role} · ${actor}`),
  ]);
}
/** Toglie l'accesso all'app. Senza altre app l'account si cancella con passkey e sessioni. */
export async function removeMember(env: AuthEnv, app: string, email: string, actor: string, now = new Date()): Promise<'removed' | 'missing'> {
  const row = await env.DB.prepare('SELECT 1 FROM members WHERE app=? AND email=?').bind(app, email).first();
  if (!row) return 'missing';
  const orphan = 'NOT EXISTS (SELECT 1 FROM members WHERE email=?1)';
  await env.DB.batch([
    env.DB.prepare('DELETE FROM members WHERE app=? AND email=?').bind(app, email),
    env.DB.prepare(`DELETE FROM sessions WHERE email=?1 AND ${orphan}`).bind(email),
    env.DB.prepare(`DELETE FROM passkeys WHERE email=?1 AND ${orphan}`).bind(email),
    env.DB.prepare(`DELETE FROM users WHERE email=?1 AND ${orphan}`).bind(email),
    env.DB.prepare("INSERT INTO auth_events (at,email,event,detail) VALUES (?,?,'access_revoked',?)").bind(now.toISOString(), email, `${app} · ${actor}`),
  ]);
  return 'removed';
}

/** `passkeyOnly`: owner, oppure opzione attiva. Accede solo con passkey. */
export interface Account { email: string; role: Role; name: string | null; owner: boolean; passkeyOnly: boolean; }
export async function accountOf(env: AuthEnv, app: string, email: string): Promise<Account | null> {
  const row = await env.DB.prepare('SELECT u.email, u.passkey_only, m.role, m.name FROM users u JOIN members m ON m.email=u.email AND m.app=? WHERE u.email=?').bind(app, email).first<{ email: string; passkey_only: number; role: Role; name: string | null }>();
  if (!row) return null;
  const owner = row.role === 'owner';
  return { email: row.email, role: row.role, name: row.name, owner, passkeyOnly: owner || Boolean(row.passkey_only) };
}
/** Il codice via email vale per member e viewer senza l'opzione «solo passkey». */
export async function codeAllowed(env: AuthEnv, app: string, email: string): Promise<boolean> {
  const account = await accountOf(env, app, email);
  return Boolean(account && !account.passkeyOnly);
}
/** L'opzione richiede almeno una passkey. Per gli owner resta sempre attiva. */
export async function setPasskeyOnly(env: AuthEnv, app: string, email: string, value: boolean): Promise<'saved' | 'no-passkey' | 'owner'> {
  const account = await accountOf(env, app, email);
  if (!account) return 'no-passkey';
  if (account.owner) return 'owner';
  if (value && !await env.DB.prepare('SELECT 1 FROM passkeys WHERE email=?').bind(email).first()) return 'no-passkey';
  await env.DB.prepare('UPDATE users SET passkey_only=? WHERE email=?').bind(value ? 1 : 0, email).run();
  await logEvent(env, email, value ? 'passkey_only_on' : 'passkey_only_off');
  return 'saved';
}
