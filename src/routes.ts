import { Hono, type Context, type MiddlewareHandler } from 'hono';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
import { authContext, authenticate, sameOrigin, type AuthContext } from './auth.ts';
import { codeMinutes, limits, normalizeEmail, overLimit, requestCode, sendMail, verifyCode } from './code.ts';
import { accountOf, setPasskeyOnly } from './members.ts';
import { accountPage, activatePage, loginPage, pageCsp } from './pages.ts';
import { createLink, endLink, hasPasskey, linkEmail, login, loginOptions, passkeysOf, register, registrationOptions, removePasskey, renamePasskey } from './passkeys.ts';
import { challengeSeconds, clearCookie, cookie, createSession, endAllSessions, endSession, eventsOf, hmac, readCookie, sessionsOf, sha256, tokenPattern } from './session.ts';
import type { AuthConfig, AuthEnv, Member } from './types.ts';

export type AuthVariables = { member: Member };
export type AuthApp = Hono<{ Bindings: AuthEnv; Variables: AuthVariables }>;
type Ctx = Context<{ Bindings: AuthEnv; Variables: AuthVariables }>;

/** Header di sicurezza per ogni risposta dell'app. La CSP delle pagine di login è a parte (pageCsp). */
export const securityHeaders: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'X-Robots-Tag': 'noindex, nofollow',
  'Cache-Control': 'no-store',
};

const fail = (error: string, status: 400 | 401 | 403 | 404 | 409 | 429 | 503 = 400) => Response.json({ error }, { status });
const unavailable = () => fail('Accesso non disponibile su questo indirizzo.', 503);
const tooMany = () => fail('Troppe richieste. Attendi un minuto e riprova.', 429);
/** Limite per IP su tutte le rotte /auth/*. L'IP entra nel D1 solo come HMAC. */
async function ipLimited(request: Request, env: AuthEnv, secret: string): Promise<boolean> {
  const ip = request.headers.get('cf-connecting-ip') ?? 'sconosciuto';
  return overLimit(env, `ip|${(await hmac(secret, ip)).slice(0, 32)}`, limits.ip, 'minute');
}
async function jsonBody(request: Request): Promise<Record<string, unknown> | null> {
  try { const value: unknown = await request.json(); return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null; } catch { return null; }
}
function withCookies(body: unknown, cookies: string[], status = 200): Response {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  for (const value of cookies) headers.append('Set-Cookie', value);
  return new Response(JSON.stringify(body), { status, headers });
}
async function html(body: string, status = 200): Promise<Response> {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': await pageCsp(), ...securityHeaders } });
}
function waitUntil(c: Ctx, work: Promise<unknown>): void {
  try { c.executionCtx.waitUntil(work); } catch { void work; }
}

export interface Auth {
  config: Required<Pick<AuthConfig, 'home' | 'loginPath' | 'accountPath'>> & AuthConfig;
  /** Rotte pubbliche e di account: `app.route('/', auth.routes)` prima delle rotte protette. */
  routes: AuthApp;
  /** Middleware per le rotte protette: 401 JSON sotto /api/, altrimenti redirect al login. Mette il membro in `c.var.member`. */
  requireSession: () => MiddlewareHandler<{ Bindings: AuthEnv; Variables: AuthVariables }>;
  /** Membro della richiesta o null, per usi fuori da Hono (per esempio il controllo degli asset statici). */
  authenticate: (request: Request, env: AuthEnv) => Promise<Member | null>;
  /** Link di attivazione per un account esistente: da usare da uno script o da una rotta riservata agli owner. */
  activationLink: (env: AuthEnv, origin: string, email: string) => Promise<string | null>;
}

export function createAuth(input: AuthConfig): Auth {
  const config = { home: '/', loginPath: '/login', accountPath: '/account', ...input };
  const app: AuthApp = new Hono();
  const ctx = (c: Ctx): AuthContext => authContext(new URL(c.req.url), c.env, config);
  const sessionCookies = (auth: AuthContext, session: { token: string; maxAge: number }, clear: string) => [cookie(auth.names.session, session.token, session.maxAge, auth.secure), clearCookie(clear, auth.secure)];

  // Pagine pubbliche.
  app.get(config.loginPath, async c => {
    const auth = ctx(c);
    if (await authenticate(c.req.raw, c.env, config)) return c.redirect(config.home, 303);
    return html(loginPage(config, Boolean(auth.rp), codeMinutes, auth.local));
  });
  app.get(`${config.loginPath}/attiva`, async c => html(activatePage(config, Boolean(ctx(c).rp))));

  // Rotte /auth/*: solo POST dalla stessa origine, con limite per IP.
  app.use('/auth/*', async (c, next) => {
    if (c.req.method !== 'POST') return fail('Metodo non consentito.', 404);
    if (!sameOrigin(c.req.raw)) return fail('Origine non autorizzata.', 403);
    const auth = ctx(c);
    if (!auth.allowed || !auth.secret) return unavailable();
    if (await ipLimited(c.req.raw, c.env, auth.secret)) return tooMany();
    await next();
  });
  app.post('/auth/passkey/options', async c => {
    const auth = ctx(c);
    if (!auth.rp) return unavailable();
    const { challenge, options } = await loginOptions(c.env, auth.rp);
    return withCookies(options, [cookie(auth.names.challenge, challenge, challengeSeconds, auth.secure)]);
  });
  app.post('/auth/passkey/verify', async c => {
    const auth = ctx(c);
    if (!auth.rp) return unavailable();
    const challenge = readCookie(c.req.raw, auth.names.challenge), body = await jsonBody(c.req.raw);
    const email = challenge && body ? await login(c.env, auth.rp, challenge, body as unknown as AuthenticationResponseJSON) : null;
    const member = email ? await accountOf(c.env, config.app, email) : null;
    if (!member) return fail('Passkey non riconosciuta. Riprova o usa il codice via email.', 401);
    const session = await createSession(c.env, config, member.email, 'passkey');
    return withCookies({ next: config.home }, sessionCookies(auth, session, auth.names.challenge));
  });
  app.post('/auth/code/request', async c => {
    const auth = ctx(c);
    const email = normalizeEmail((await jsonBody(c.req.raw))?.email);
    if (!email) return fail('Indirizzo email non valido.');
    if (await overLimit(c.env, `code|${(await hmac(auth.secret!, email)).slice(0, 32)}`, limits.code, 'hour')) return fail('Troppi codici richiesti per questo indirizzo. Riprova tra un’ora.', 429);
    const { id, message } = await requestCode(c.env, config, new URL(c.req.url).origin, email, auth.secret!);
    if (message) waitUntil(c, sendMail(c.env, auth.local, email, message));
    return withCookies({ ok: true }, [cookie(auth.names.code, id, codeMinutes * 60, auth.secure)]);
  });
  app.post('/auth/code/verify', async c => {
    const auth = ctx(c);
    const challenge = readCookie(c.req.raw, auth.names.code), body = await jsonBody(c.req.raw);
    const email = challenge ? await verifyCode(c.env, config, challenge, body?.code, auth.secret!) : null;
    if (!email) return fail('Codice non valido o scaduto.', 401);
    const session = await createSession(c.env, config, email, 'code');
    const next = await hasPasskey(c.env, email) ? config.home : `${config.accountPath}?attiva=1`;
    return withCookies({ next }, sessionCookies(auth, session, auth.names.code));
  });
  app.post('/auth/link/options', async c => {
    const auth = ctx(c);
    if (!auth.rp) return unavailable();
    const token = (await jsonBody(c.req.raw))?.token;
    const link = typeof token === 'string' && tokenPattern.test(token) ? await linkEmail(c.env, token) : null;
    const result = link ? await registrationOptions(c.env, auth.rp, config.name, link.email) : null;
    if (!result) return fail('Link non valido o scaduto. Chiedi un nuovo link.', 401);
    return withCookies(result.options, [cookie(auth.names.challenge, result.challenge, challengeSeconds, auth.secure)]);
  });
  app.post('/auth/link/verify', async c => {
    const auth = ctx(c);
    if (!auth.rp) return unavailable();
    const body = await jsonBody(c.req.raw), challenge = readCookie(c.req.raw, auth.names.challenge);
    const link = typeof body?.token === 'string' && tokenPattern.test(body.token) ? await linkEmail(c.env, body.token, new Date(), false) : null;
    const name = link && challenge && body?.credential ? await register(c.env, auth.rp, challenge, link.email, body.credential as RegistrationResponseJSON) : null;
    if (!link || !name) return fail('Passkey non registrata. Riprova o chiedi un nuovo link.', 401);
    await endLink(c.env, link.id);
    const session = await createSession(c.env, config, link.email, 'passkey');
    return withCookies({ next: config.home }, sessionCookies(auth, session, auth.names.challenge));
  });
  app.post('/auth/logout', async c => {
    const auth = ctx(c);
    const token = readCookie(c.req.raw, auth.names.session);
    if (token) await endSession(c.env, token);
    const headers = new Headers({ Location: config.loginPath });
    headers.append('Set-Cookie', clearCookie(auth.names.session, auth.secure));
    return new Response(null, { status: 303, headers });
  });

  // Account: richiede la sessione. Le scritture richiedono la stessa origine.
  const requireSession = (): MiddlewareHandler<{ Bindings: AuthEnv; Variables: AuthVariables }> => async (c, next) => {
    const member = await authenticate(c.req.raw, c.env, config);
    const path = new URL(c.req.url).pathname;
    if (!member) {
      if (path.startsWith('/api/') || path.startsWith(`${config.accountPath}/`)) return fail('Accesso richiesto.', 401);
      return c.redirect(config.loginPath, 303);
    }
    if (!['GET', 'HEAD'].includes(c.req.method) && !sameOrigin(c.req.raw)) return fail('Origine non autorizzata.', 403);
    c.set('member', member);
    await next();
  };
  app.use(`${config.accountPath}/*`, requireSession());
  app.use(config.accountPath, requireSession());
  app.get(config.accountPath, async c => {
    const auth = ctx(c), email = c.var.member.email;
    const account = (await accountOf(c.env, config.app, email))!;
    const passkeys = await passkeysOf(c.env, email);
    const token = readCookie(c.req.raw, auth.names.session);
    const [sessions, events] = await Promise.all([sessionsOf(c.env, email, token ? await sha256(token) : null), eventsOf(c.env, email, 10)]);
    const prompt = new URL(c.req.url).searchParams.get('attiva') === '1' && passkeys.length === 0;
    return html(accountPage(config, { account, passkeys, sessions, events, available: Boolean(auth.rp), prompt }));
  });
  app.post(`${config.accountPath}/passkeys/options`, async c => {
    const auth = ctx(c);
    if (!auth.rp) return unavailable();
    const result = await registrationOptions(c.env, auth.rp, config.name, c.var.member.email);
    if (!result) return fail('Account non trovato.', 404);
    return withCookies(result.options, [cookie(auth.names.challenge, result.challenge, challengeSeconds, auth.secure)]);
  });
  app.post(`${config.accountPath}/passkeys`, async c => {
    const auth = ctx(c);
    if (!auth.rp) return unavailable();
    const challenge = readCookie(c.req.raw, auth.names.challenge), body = await jsonBody(c.req.raw);
    const name = challenge && body ? await register(c.env, auth.rp, challenge, c.var.member.email, body as unknown as RegistrationResponseJSON) : null;
    if (!name) return fail('Passkey non registrata. Riprova.', 400);
    return withCookies({ name }, [clearCookie(auth.names.challenge, auth.secure)]);
  });
  app.patch(`${config.accountPath}/passkeys/:id`, async c => {
    const raw = (await jsonBody(c.req.raw))?.name, name = typeof raw === 'string' ? raw.replace(/\s+/g, ' ').trim().slice(0, 60) : '';
    if (!name) return fail('Nome non valido.');
    if (!await renamePasskey(c.env, c.var.member.email, c.req.param('id'), name)) return fail('Passkey non trovata.', 404);
    return Response.json({ name });
  });
  app.delete(`${config.accountPath}/passkeys/:id`, async c => {
    const account = (await accountOf(c.env, config.app, c.var.member.email))!;
    const result = await removePasskey(c.env, account.email, c.req.param('id'), account.passkeyOnly);
    if (result === 'missing') return fail('Passkey non trovata.', 404);
    if (result === 'last') return fail('Serve almeno una passkey: questo account accede solo con passkey.', 409);
    return Response.json({ ok: true });
  });
  app.patch(`${config.accountPath}/settings`, async c => {
    const value = (await jsonBody(c.req.raw))?.passkeyOnly;
    if (typeof value !== 'boolean') return fail('Valore non valido.');
    const result = await setPasskeyOnly(c.env, config.app, c.var.member.email, value);
    if (result === 'owner') return fail('Gli owner accedono sempre solo con passkey.', 409);
    if (result === 'no-passkey') return fail('Crea prima una passkey.', 409);
    return Response.json({ passkeyOnly: value });
  });
  app.delete(`${config.accountPath}/sessions`, async c => {
    const auth = ctx(c);
    await endAllSessions(c.env, c.var.member.email);
    return withCookies({ next: config.loginPath }, [clearCookie(auth.names.session, auth.secure)]);
  });

  return {
    config,
    routes: app,
    requireSession,
    authenticate: (request, env) => authenticate(request, env, config),
    activationLink: async (env, origin, email) => { const token = await createLink(env, email); return token ? `${origin}${config.loginPath}/attiva#${token}` : null; },
  };
}
