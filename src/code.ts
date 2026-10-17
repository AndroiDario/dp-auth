import { codeAllowed } from './members.ts';
import { hmac, randomToken, saveChallenge } from './session.ts';
import type { AuthConfig, AuthEnv } from './types.ts';
// Codice monouso via email, riserva delle passkey per member e viewer. Gli owner usano la passkey.
// Il codice è salvato come HMAC e legato al browser che l'ha chiesto tramite il cookie del challenge.
export const codeMinutes = 10;
export const maxCodeAttempts = 5;
/** Richieste /auth/* al minuto per IP e codici all'ora per indirizzo. */
export const limits = { ip: 20, code: 5 };
export const emailPattern = /^[^\s@'"<>]+@[^\s@'"<>]+\.[a-z]{2,}$/i;
export function normalizeEmail(value: unknown): string | null {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return email.length <= 254 && emailPattern.test(email) ? email : null;
}

/** Conta una richiesta nel minuto o nell'ora corrente. Le chiavi iniziano dal tempo: la pulizia per prefisso resta valida. */
export async function overLimit(env: AuthEnv, key: string, limit: number, window: 'minute' | 'hour', now = new Date()): Promise<boolean> {
  const bucket = `${now.toISOString().slice(0, window === 'minute' ? 16 : 13)}|${key}`;
  const row = await env.DB.prepare('INSERT INTO login_attempts(bucket,attempts) VALUES (?,1) ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1 RETURNING attempts').bind(bucket).first<{ attempts: number }>();
  await env.DB.prepare('DELETE FROM login_attempts WHERE bucket<?').bind(new Date(now.getTime() - 7200000).toISOString().slice(0, 16)).run();
  return (row?.attempts ?? 0) > limit;
}

export async function sameSecret(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [x, y] = await Promise.all([a, b].map(value => crypto.subtle.digest('SHA-256', encoder.encode(value))));
  const left = new Uint8Array(x!); const right = new Uint8Array(y!); let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

function sixDigits(): string {
  // Scarto dei valori oltre l'ultimo multiplo di 10^6: nessuna cifra più probabile delle altre.
  const value = new Uint32Array(1);
  do crypto.getRandomValues(value); while (value[0]! >= 4294000000);
  return String(value[0]! % 1000000).padStart(6, '0');
}
export function codeMessage(config: AuthConfig, origin: string, code: string) {
  return {
    subject: `Codice di accesso a ${config.name}`,
    text: [`Il tuo codice di accesso è ${code}.`, '', `Scade tra ${codeMinutes} minuti e vale una sola volta.`, 'Se non hai chiesto tu il codice, ignora questa email. Non rispondere a questo messaggio.', '', origin].join('\n'),
  };
}
/** Il challenge si crea anche per indirizzi sconosciuti: risposta e verifica non rivelano quali indirizzi sono abilitati. */
export async function requestCode(env: AuthEnv, config: AuthConfig, origin: string, email: string, secret: string, now = new Date()): Promise<{ id: string; message: ReturnType<typeof codeMessage> | null }> {
  const code = sixDigits(), id = randomToken(), allowed = await codeAllowed(env, config.app, email);
  await saveChallenge(env, 'code', email, await hmac(secret, `${id}:${code}`), codeMinutes * 60, now, id);
  return { id, message: allowed ? codeMessage(config, origin, code) : null };
}
/** Email verificata o null. Oltre il quinto tentativo il challenge si cancella. */
export async function verifyCode(env: AuthEnv, config: AuthConfig, id: string, code: unknown, secret: string, now = new Date()): Promise<string | null> {
  const row = await env.DB.prepare("UPDATE auth_challenges SET attempts=attempts+1 WHERE id=? AND kind='code' AND expires_at>? RETURNING email,secret,attempts").bind(id, now.toISOString()).first<{ email: string; secret: string; attempts: number }>();
  if (!row) return null;
  if (row.attempts > maxCodeAttempts) { await env.DB.prepare('DELETE FROM auth_challenges WHERE id=?').bind(id).run(); return null; }
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.trim()) || !await sameSecret(row.secret, await hmac(secret, `${id}:${code.trim()}`))) return null;
  await env.DB.prepare('DELETE FROM auth_challenges WHERE id=?').bind(id).run();
  return await codeAllowed(env, config.app, row.email) ? row.email : null;
}

/** Invio con la chiave Resend. In locale senza chiave il messaggio resta in auth_outbox per bin/local-code.mjs. */
export async function sendMail(env: AuthEnv, local: boolean, to: string, message: { subject: string; text: string }, transport: typeof fetch = fetch): Promise<boolean> {
  if (!env.AUTH_RESEND_KEY || !env.AUTH_FROM) {
    if (!local) { console.error('Email di accesso non configurata'); return false; }
    await env.DB.prepare('INSERT INTO auth_outbox (email,text,created_at) VALUES (?,?,?)').bind(to, message.text, new Date().toISOString()).run();
    return true;
  }
  try {
    const response = await transport('https://api.resend.com/emails', {
      method: 'POST', signal: AbortSignal.timeout(15000),
      headers: { Authorization: `Bearer ${env.AUTH_RESEND_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: env.AUTH_FROM, to: [to], subject: message.subject, text: message.text }),
    });
    if (!response.ok) {
      const error = await response.json().catch(() => null) as { name?: string; message?: string } | null;
      console.error('Email di accesso non inviata', response.status, error?.name ?? '', (error?.message ?? '').replace(/[^\s@()<>]+@[^\s@()<>]+/g, '<email>').slice(0, 200));
      return false;
    }
    return true;
  } catch { console.error('Email di accesso non inviata'); return false; }
}
