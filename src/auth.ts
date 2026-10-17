import { memberOf } from './members.ts';
import { cookieNames, readCookie, sessionEmail } from './session.ts';
import type { AuthConfig, AuthEnv, Member, RelyingParty } from './types.ts';
// Contesto della richiesta: dove valgono le sessioni e quali parametri WebAuthn usare.

export function isLocal(url: URL, env: AuthEnv): boolean {
  return env.LOCAL_AUTH_ENABLED === 'true' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && url.protocol === 'http:';
}
/** Sessione: online su https, in locale su http solo con l'accesso locale abilitato. */
export const sessionAllowed = (url: URL, env: AuthEnv) => url.protocol === 'https:' || isLocal(url, env);
/** Parametri WebAuthn dalla configurazione, mai dall'header Host. In locale solo su localhost: WebAuthn non accetta indirizzi IP. */
export function relyingParty(url: URL, env: AuthEnv): RelyingParty | null {
  if (isLocal(url, env)) return url.hostname === 'localhost' ? { id: 'localhost', origin: url.origin } : null;
  if (!env.AUTH_RP_ID || !env.AUTH_ORIGIN || url.origin !== env.AUTH_ORIGIN) return null;
  return { id: env.AUTH_RP_ID, origin: env.AUTH_ORIGIN };
}
/** Chiave degli HMAC di codici e IP. In locale vale anche il segreto locale. */
export function authSecret(url: URL, env: AuthEnv): string | null {
  return env.AUTH_SECRET ?? (isLocal(url, env) ? env.LOCAL_AUTH_SECRET ?? null : null);
}
export function sameOrigin(request: Request): boolean { return request.headers.get('origin') === new URL(request.url).origin; }

export interface AuthContext { secure: boolean; local: boolean; allowed: boolean; rp: RelyingParty | null; secret: string | null; names: ReturnType<typeof cookieNames>; }
export function authContext(url: URL, env: AuthEnv, config: AuthConfig): AuthContext {
  const secure = url.protocol === 'https:';
  return { secure, local: isLocal(url, env), allowed: sessionAllowed(url, env), rp: relyingParty(url, env), secret: authSecret(url, env), names: cookieNames(config, secure) };
}

/** Membro autenticato per questa app, o null. Il ruolo si rilegge a ogni richiesta: una revoca ha effetto subito. */
export async function authenticate(request: Request, env: AuthEnv, config: AuthConfig, now = new Date()): Promise<Member | null> {
  try {
    const url = new URL(request.url);
    if (!sessionAllowed(url, env)) return null;
    const token = readCookie(request, cookieNames(config, url.protocol === 'https:').session);
    const email = token ? await sessionEmail(env, config, token, now) : null;
    return email ? memberOf(env, config.app, email) : null;
  } catch { return null; }
}
