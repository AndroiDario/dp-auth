import type { AuthConfig, AuthEnv, LoginMethod } from './types.ts';
// Sessioni: token casuale nel cookie, SHA-256 del token nel D1. Derivato da VEDA Analytics (src/lib/session.ts).
// Online i cookie hanno il prefisso __Host-: Secure, Path=/ e nessun dominio. In locale su http restano senza prefisso.
const encoder = new TextEncoder();
export const defaultSessionDays: Record<LoginMethod, number> = { passkey: 30, code: 7 };
/** Durata dei challenge WebAuthn e del cookie che li lega al browser. */
export const challengeSeconds = 300;
/** Conservazione del registro degli accessi. */
export const eventDays = 180;

export function base64url(bytes: Uint8Array): string {
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromBase64url(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
export const fromHex = (value: string) => Uint8Array.from(value.match(/../g) ?? [], byte => parseInt(byte, 16));
const toHex = (buffer: ArrayBuffer) => [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
export const randomToken = (size = 32) => base64url(crypto.getRandomValues(new Uint8Array(size)));
export const randomHex = (size = 32) => toHex(crypto.getRandomValues(new Uint8Array(size)).buffer);
export const sha256 = async (value: string) => toHex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
/** Hash CSP di uno script o stile inline: base64 standard del digest SHA-256. */
export async function cspHash(source: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(source)));
  let binary = ''; for (const byte of digest) binary += String.fromCharCode(byte);
  return `sha256-${btoa(binary)}`;
}
export async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}
/** Token di sessione e di challenge: 32 byte in base64url. */
export const tokenPattern = /^[A-Za-z0-9_-]{43}$/;

export const prefixOf = (config: AuthConfig) => config.cookiePrefix ?? `${config.app}_`;
/** Cookie separati per il challenge WebAuthn e per il codice: la richiesta di un codice non annulla una passkey in attesa. */
export function cookieNames(config: AuthConfig, secure: boolean) {
  const prefix = `${secure ? '__Host-' : ''}${prefixOf(config)}`;
  return { session: `${prefix}session`, challenge: `${prefix}challenge`, code: `${prefix}code` };
}
export function readCookie(request: Request, name: string): string | null {
  const value = request.headers.get('cookie')?.match(new RegExp(`(?:^|;\\s*)${name.replace(/[-]/g, '\\-')}=([^;]+)`))?.[1];
  return value && tokenPattern.test(value) ? value : null;
}
export function cookie(name: string, value: string, maxAge: number, secure: boolean): string {
  return `${name}=${value}; HttpOnly; ${secure ? 'Secure; ' : ''}SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}
export const clearCookie = (name: string, secure: boolean) => cookie(name, '', 0, secure);

export async function createSession(env: AuthEnv, config: AuthConfig, email: string, method: LoginMethod, now = new Date()): Promise<{ token: string; maxAge: number }> {
  const days = config.sessionDays?.[method] ?? defaultSessionDays[method];
  const token = randomToken(), maxAge = days * 86400, at = now.toISOString();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO sessions (id,email,method,created_at,expires_at,last_seen_at) VALUES (?,?,?,?,?,?)').bind(await sha256(token), email, method, at, new Date(now.getTime() + maxAge * 1000).toISOString(), at),
    env.DB.prepare('DELETE FROM sessions WHERE email=? AND expires_at<=?').bind(email, at),
    env.DB.prepare('UPDATE users SET last_login_at=? WHERE email=?').bind(at, email),
    env.DB.prepare("INSERT INTO auth_events (at,email,event,detail) VALUES (?,?,'login',?)").bind(at, email, method),
    env.DB.prepare('DELETE FROM auth_events WHERE at<?').bind(new Date(now.getTime() - eventDays * 86400000).toISOString()),
  ]);
  return { token, maxAge };
}
/** Email della sessione valida. `last_seen_at` si aggiorna al massimo una volta l'ora, o a ogni richiesta se c'è un limite di inattività. */
export async function sessionEmail(env: AuthEnv, config: AuthConfig, token: string, now = new Date()): Promise<string | null> {
  const id = await sha256(token);
  const row = await env.DB.prepare('SELECT s.email,s.last_seen_at FROM sessions s JOIN users u ON u.email=s.email WHERE s.id=? AND s.expires_at>?').bind(id, now.toISOString()).first<{ email: string; last_seen_at: string }>();
  if (!row) return null;
  const idle = now.getTime() - Date.parse(row.last_seen_at);
  if (config.idleMinutes && idle > config.idleMinutes * 60000) {
    await env.DB.prepare('DELETE FROM sessions WHERE id=?').bind(id).run();
    return null;
  }
  if (idle > (config.idleMinutes ? 60000 : 3600000)) await env.DB.prepare('UPDATE sessions SET last_seen_at=? WHERE id=?').bind(now.toISOString(), id).run();
  return row.email;
}
export async function endSession(env: AuthEnv, token: string): Promise<void> {
  await env.DB.prepare('DELETE FROM sessions WHERE id=?').bind(await sha256(token)).run();
}
export async function endAllSessions(env: AuthEnv, email: string, now = new Date()): Promise<void> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(email),
    env.DB.prepare("INSERT INTO auth_events (at,email,event) VALUES (?,?,'sessions_ended')").bind(now.toISOString(), email),
  ]);
}
export interface SessionRow { method: LoginMethod; created_at: string; last_seen_at: string; expires_at: string; current: boolean; }
export async function sessionsOf(env: AuthEnv, email: string, currentId: string | null, now = new Date()): Promise<SessionRow[]> {
  const { results } = await env.DB.prepare('SELECT id,method,created_at,last_seen_at,expires_at FROM sessions WHERE email=? AND expires_at>? ORDER BY last_seen_at DESC').bind(email, now.toISOString()).all<SessionRow & { id: string }>();
  return results.map(({ id, ...row }) => ({ ...row, current: id === currentId }));
}
export async function logEvent(env: AuthEnv, email: string, event: string, detail: string | null = null, now = new Date()): Promise<void> {
  await env.DB.prepare('INSERT INTO auth_events (at,email,event,detail) VALUES (?,?,?,?)').bind(now.toISOString(), email, event, detail).run();
}
export interface AuthEvent { at: string; event: string; detail: string | null; }
export async function eventsOf(env: AuthEnv, email: string, limit = 50): Promise<AuthEvent[]> {
  const { results } = await env.DB.prepare('SELECT at,event,detail FROM auth_events WHERE email=? ORDER BY at DESC LIMIT ?').bind(email, limit).all<AuthEvent>();
  return results;
}

/** Challenge monouso: la lettura lo cancella. */
export async function consumeChallenge(env: AuthEnv, id: string, kind: 'login' | 'register', now = new Date()): Promise<{ email: string | null; secret: string } | null> {
  return env.DB.prepare('DELETE FROM auth_challenges WHERE id=? AND kind=? AND expires_at>? RETURNING email,secret').bind(id, kind, now.toISOString()).first<{ email: string | null; secret: string }>();
}
export async function saveChallenge(env: AuthEnv, kind: 'login' | 'register' | 'code', email: string | null, secret: string, seconds: number, now = new Date(), id = randomToken()): Promise<string> {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM auth_challenges WHERE expires_at<=?').bind(now.toISOString()),
    env.DB.prepare('INSERT INTO auth_challenges (id,kind,email,secret,attempts,expires_at) VALUES (?,?,?,?,0,?)').bind(id, kind, email, secret, new Date(now.getTime() + seconds * 1000).toISOString()),
  ]);
  return id;
}
