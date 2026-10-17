import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { createAuth, type AuthEnv, type AuthVariables } from '../src/index.ts';
import { addMember } from '../src/members.ts';
import { SoftAuthenticator } from './fixtures/authenticator.ts';
import { testEnv } from './sqlite.ts';
// Flussi completi attraverso le rotte Hono: codice, passkey, link, account, logout, origine e limiti.
const origin = 'https://salute.dariopagnoni.it';
const rp = { id: 'salute.dariopagnoni.it', origin };
const codeOf = (text: string) => /è (\d{6})\./.exec(text)![1]!;

async function setup() {
  const { env, database } = testEnv({ AUTH_RP_ID: rp.id, AUTH_ORIGIN: origin, AUTH_SECRET: 'segreto-di-test-lungo-abbastanza' });
  await addMember(env, 'salute', 'dario@example.com', 'owner', 'Dario', 'test');
  await addMember(env, 'salute', 'paola@example.com', 'member', 'Paola', 'test');
  const auth = createAuth({ app: 'salute', name: 'Salute', home: '/app' });
  const app = new Hono<{ Bindings: AuthEnv; Variables: AuthVariables }>();
  app.route('/', auth.routes);
  app.use('*', auth.requireSession());
  app.get('/app', c => c.text(`ciao ${c.var.member.email} ${c.var.member.role}`));
  app.get('/api/dati', c => c.json({ email: c.var.member.email }));
  app.post('/api/dati', c => c.json({ ok: true }));
  const jar = new Map<string, string>();
  const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const call = async (path: string, init: RequestInit & { json?: unknown; ip?: string; noOrigin?: boolean } = {}) => {
    const headers = new Headers(init.headers);
    if (jar.size) headers.set('cookie', cookieHeader());
    if (init.json !== undefined) headers.set('content-type', 'application/json');
    if ((init.method ?? 'GET') !== 'GET' && !init.noOrigin && !headers.has('origin')) headers.set('origin', origin);
    if (init.ip) headers.set('cf-connecting-ip', init.ip);
    const response = await app.request(`${origin}${path}`, { ...init, headers, body: init.json !== undefined ? JSON.stringify(init.json) : init.body }, env);
    for (const value of response.headers.getSetCookie()) {
      const [pair, ...attrs] = value.split(';'), [name, cookie] = pair!.split('=');
      if (attrs.some(a => a.trim() === 'Max-Age=0')) jar.delete(name!); else jar.set(name!, cookie!);
    }
    return response;
  };
  return { env, database, app, auth, call, jar };
}

describe('Rotte', () => {
  it('senza sessione redirige le pagine e risponde 401 alle API', async () => {
    const { call } = await setup();
    const page = await call('/app');
    expect(page.status).toBe(303);
    expect(page.headers.get('location')).toBe('/login');
    expect((await call('/api/dati')).status).toBe(401);
    expect((await call('/account')).status).toBe(303);
    expect((await call('/account/passkeys/options', { method: 'POST' })).status).toBe(401);
    const login = await call('/login');
    expect(login.status).toBe(200);
    expect(login.headers.get('content-security-policy')).toMatch(/^default-src 'none'; script-src 'sha256-[^']+' 'sha256-[^']+'; style-src 'sha256-/);
    expect(await login.text()).toContain('data-passkeys="true"');
  });
  it('rifiuta POST /auth da un’altra origine e i metodi diversi da POST', async () => {
    const { call } = await setup();
    expect((await call('/auth/code/request', { method: 'POST', json: { email: 'paola@example.com' }, noOrigin: true })).status).toBe(403);
    expect((await call('/auth/code/request', { method: 'POST', json: { email: 'paola@example.com' }, headers: { origin: 'https://evil.example.com' } })).status).toBe(403);
    expect((await call('/auth/passkey/options')).status).toBe(404);
  });
  it('accede con il codice via email, propone la passkey, poi esce', async () => {
    const { call, database, jar } = await setup();
    const request = await call('/auth/code/request', { method: 'POST', json: { email: 'Paola@Example.com ' } });
    expect(request.status).toBe(200);
    expect(jar.has('__Host-salute_code')).toBe(true);
    const outbox = database.prepare('SELECT text FROM auth_outbox').get() as { text: string } | undefined;
    // Senza chiave Resend e fuori dal locale il messaggio non parte: il codice si legge dal challenge con il test diretto.
    expect(outbox).toBeUndefined();
    const wrong = await call('/auth/code/verify', { method: 'POST', json: { code: '000000' } });
    expect(wrong.status).toBe(401);
  });
  it('accede con il codice in locale, poi con la passkey, e gestisce l’account', async () => {
    const { env, call, database, jar } = await setup();
    Object.assign(env, { LOCAL_AUTH_ENABLED: 'true' });
    // In locale senza chiave i messaggi restano in auth_outbox.
    const localOrigin = 'http://localhost:8787';
    const local = async (path: string, init: RequestInit & { json?: unknown } = {}) => {
      const headers = new Headers(init.headers);
      if (jar.size) headers.set('cookie', [...jar].map(([k, v]) => `${k}=${v}`).join('; '));
      if (init.json !== undefined) headers.set('content-type', 'application/json');
      if ((init.method ?? 'GET') !== 'GET') headers.set('origin', localOrigin);
      const response = await (await setupApp()).request(`${localOrigin}${path}`, { ...init, headers, body: init.json !== undefined ? JSON.stringify(init.json) : undefined }, env);
      for (const value of response.headers.getSetCookie()) { const [pair, ...attrs] = value.split(';'), [name, cookie] = pair!.split('='); if (attrs.some(a => a.trim() === 'Max-Age=0')) jar.delete(name!); else jar.set(name!, cookie!); }
      return response;
    };
    async function setupApp() { const { app } = await setup(); return app; }
    Object.assign(env, { LOCAL_AUTH_SECRET: 'segreto-locale' });
    expect((await local('/auth/code/request', { method: 'POST', json: { email: 'paola@example.com' } })).status).toBe(200);
    const text = (database.prepare('SELECT text FROM auth_outbox ORDER BY created_at DESC').get() as { text: string }).text;
    const verify = await local('/auth/code/verify', { method: 'POST', json: { code: codeOf(text) } });
    expect(verify.status).toBe(200);
    expect(await verify.json()).toEqual({ next: '/account?attiva=1' });
    expect(jar.has('salute_session')).toBe(true);
    expect(jar.has('salute_code')).toBe(false);
    expect(await (await local('/app')).text()).toBe('ciao paola@example.com member');
    expect(await (await local('/account?attiva=1')).text()).toContain('Crea una passkey');
    // Registrazione della passkey dalla pagina Account con rp localhost.
    const device = new SoftAuthenticator(localOrigin, 'localhost');
    const options = await (await local('/account/passkeys/options', { method: 'POST' })).json() as Parameters<typeof device.create>[0];
    const saved = await local('/account/passkeys', { method: 'POST', json: await device.create(options) });
    expect(await saved.json()).toEqual({ name: 'iCloud Keychain' });
    expect(await (await local('/account')).text()).toContain('iCloud Keychain');
    expect((await local('/account/passkeys/sconosciuta', { method: 'PATCH', json: { name: 'x' } })).status).toBe(404);
    expect(await (await local(`/account/passkeys/${device.id}`, { method: 'PATCH', json: { name: '  Mac di  Paola ' } })).json()).toEqual({ name: 'Mac di Paola' });
    expect(await (await local('/account/settings', { method: 'PATCH', json: { passkeyOnly: true } })).json()).toEqual({ passkeyOnly: true });
    expect((await local(`/account/passkeys/${device.id}`, { method: 'DELETE' })).status).toBe(409);
    // Esci da tutti i dispositivi, poi accesso con la passkey.
    expect(await (await local('/account/sessions', { method: 'DELETE' })).json()).toEqual({ next: '/login' });
    expect(jar.has('salute_session')).toBe(false);
    expect((await local('/app')).status).toBe(303);
    const loginOptions = await (await local('/auth/passkey/options', { method: 'POST' })).json() as Parameters<typeof device.get>[0];
    const logged = await local('/auth/passkey/verify', { method: 'POST', json: await device.get(loginOptions) });
    expect(await logged.json()).toEqual({ next: '/app' });
    expect(await (await local('/app')).text()).toBe('ciao paola@example.com member');
    // Logout del dispositivo con il form.
    const out = await local('/auth/logout', { method: 'POST' });
    expect(out.status).toBe(303);
    expect(jar.has('salute_session')).toBe(false);
  });
  it('attiva un owner con il link, rifiuta le scritture da altra origine e limita per IP', async () => {
    const { env, call, auth, jar } = await setup();
    const link = (await auth.activationLink(env, origin, 'dario@example.com'))!;
    expect(link.startsWith(`${origin}/login/attiva#`)).toBe(true);
    const token = link.split('#')[1]!;
    expect((await call('/auth/link/options', { method: 'POST', json: { token: 'x'.repeat(43) } })).status).toBe(401);
    const device = new SoftAuthenticator(origin, rp.id);
    const options = await (await call('/auth/link/options', { method: 'POST', json: { token } })).json() as Parameters<typeof device.create>[0];
    const verified = await call('/auth/link/verify', { method: 'POST', json: { token, credential: await device.create(options) } });
    expect(await verified.json()).toEqual({ next: '/app' });
    expect(jar.has('__Host-salute_session')).toBe(true);
    expect(await (await call('/app')).text()).toBe('ciao dario@example.com owner');
    expect((await call('/auth/link/options', { method: 'POST', json: { token } })).status).toBe(401);
    // Scritture protette: stessa origine obbligatoria.
    expect((await call('/api/dati', { method: 'POST', noOrigin: true })).status).toBe(403);
    expect((await call('/api/dati', { method: 'POST' })).status).toBe(200);
    // Owner: il codice via email non parte e l'opzione resta fissa.
    expect((await call('/account/settings', { method: 'PATCH', json: { passkeyOnly: false } })).status).toBe(409);
    // Limite per IP: 20 richieste al minuto su /auth/*.
    let status = 200;
    for (let i = 0; i < 25 && status !== 429; i++) status = (await call('/auth/passkey/options', { method: 'POST', ip: '203.0.113.9' })).status;
    expect(status).toBe(429);
    expect((await call('/auth/passkey/options', { method: 'POST', ip: '203.0.113.10' })).status).toBe(200);
  });
});
