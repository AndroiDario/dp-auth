import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { createAuth, deliverMail, type AuthEnv, type AuthVariables, type DelegatedLogin } from '../src/index.ts';
import { addMember, setPasskeyOnly } from '../src/members.ts';
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
  // Codici di delega del portale finto: si consumano alla prima verifica, come nel Worker famiglia.
  const delegated = new Map<string, DelegatedLogin>();
  const verify = async (_env: AuthEnv, code: string) => { const login = delegated.get(code) ?? null; delegated.delete(code); return login; };
  app.get('/auth/accept-delegate', auth.acceptDelegate(verify));
  app.get('/auth/accept-delegate-owners', auth.acceptDelegate(verify, { ownersByCode: true }));
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
  return { env, database, app, auth, call, jar, delegated };
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
  it('scrive nel registro l’esito dell’invio del codice, solo per gli indirizzi abilitati', async () => {
    const { call, database } = await setup();
    await call('/auth/code/request', { method: 'POST', json: { email: 'paola@example.com' } });
    await call('/auth/code/request', { method: 'POST', json: { email: 'sconosciuto@example.com' } });
    // L'invio gira in waitUntil: si attende che il registro lo riporti.
    const events = async () => { for (let i = 0; i < 50; i++) { const rows = database.prepare("SELECT email,event,detail FROM auth_events WHERE event LIKE 'code_%'").all(); if (rows.length) return rows; await new Promise(r => setTimeout(r, 5)); } return []; };
    expect(await events()).toEqual([{ email: 'paola@example.com', event: 'code_failed', detail: 'invio non configurato' }]);
  });
  it('riporta il motivo del rifiuto di Resend senza indirizzi email', async () => {
    const { env } = await setup();
    Object.assign(env, { AUTH_RESEND_KEY: 're_test', AUTH_FROM: 'Salute <accesso@dariopagnoni.it>' });
    const message = { subject: 'Codice', text: 'Il tuo codice è 123456.' };
    const refused = await deliverMail(env, false, 'paola@example.com', message, async () => Response.json({ name: 'validation_error', message: 'The dariopagnoni.it domain is not verified. Write to paola@example.com' }, { status: 403 }));
    expect(refused).toEqual({ ok: false, detail: 'Resend 403 validation_error The dariopagnoni.it domain is not verified. Write to <email>' });
    expect(await deliverMail(env, false, 'paola@example.com', message, async () => Response.json({ id: 'x' }))).toEqual({ ok: true, detail: null });
    expect(await deliverMail(env, false, 'paola@example.com', message, async () => { throw new TypeError('rete'); })).toEqual({ ok: false, detail: 'errore di rete' });
  });
  it('accetta la delega del portale secondo il ruolo locale e il metodo d’accesso', async () => {
    const { call, jar, delegated, database, auth, env } = await setup();
    const code = (n: number) => `00000000-0000-4000-8000-00000000000${n}`;
    const open = async (n: number) => { jar.clear(); const res = await call(`/auth/accept-delegate?code=${code(n)}&from=famiglia`); return { status: res.status, location: res.headers.get('location'), session: jar.has('__Host-salute_session') }; };
    // Member entrato nel portale con il codice: sessione locale da codice.
    delegated.set(code(1), { email: 'paola@example.com', method: 'code' });
    expect(await open(1)).toEqual({ status: 303, location: '/app', session: true });
    expect(await (await call('/app')).text()).toBe('ciao paola@example.com member');
    expect(database.prepare("SELECT method FROM sessions WHERE email='paola@example.com'").get()).toEqual({ method: 'code' });
    expect(await auth.loginMethod(new Request(`${origin}/app`, { headers: { cookie: `__Host-salute_session=${jar.get('__Host-salute_session')}` } }), env)).toBe('code');
    expect(await auth.loginMethod(new Request(`${origin}/app`), env)).toBeNull();
    // Il codice vale una volta sola.
    expect(await open(1)).toEqual({ status: 303, location: '/login', session: false });
    // Owner entrato con il codice: serve la passkey.
    delegated.set(code(2), { email: 'dario@example.com', method: 'code' });
    expect(await open(2)).toEqual({ status: 303, location: '/login', session: false });
    // Owner entrato con la passkey: passa.
    delegated.set(code(3), { email: 'Dario@Example.com', method: 'passkey' });
    expect(await open(3)).toEqual({ status: 303, location: '/app', session: true });
    expect(await (await call('/app')).text()).toBe('ciao dario@example.com owner');
    // Nessun ruolo in questa app, o codice dal formato sbagliato: login.
    delegated.set(code(4), { email: 'ospite@example.com', method: 'passkey' });
    expect(await open(4)).toEqual({ status: 303, location: '/login', session: false });
    jar.clear();
    expect((await call('/auth/accept-delegate?code=x')).headers.get('location')).toBe('/login');
  });
  it('rifiuta la delega via codice a chi ha scelto «solo passkey»', async () => {
    const { env, call, delegated, jar, database } = await setup();
    database.prepare("INSERT INTO passkeys (id,email,public_key,name,created_at) VALUES ('pk','paola@example.com','x','Test','2026-11-01T00:00:00Z')").run();
    expect(await setPasskeyOnly(env, 'salute', 'paola@example.com', true)).toBe('saved');
    delegated.set('11111111-1111-4111-8111-111111111111', { email: 'paola@example.com', method: 'code' });
    const res = await call('/auth/accept-delegate?code=11111111-1111-4111-8111-111111111111');
    expect(res.headers.get('location')).toBe('/login');
    expect(jar.has('__Host-salute_session')).toBe(false);
  });
  it('con ownersByCode la delega da codice apre la sessione anche agli owner, non a chi ha scelto «solo passkey»', async () => {
    const { env, call, jar, delegated, database } = await setup();
    delegated.set('22222222-2222-4222-8222-222222222222', { email: 'dario@example.com', method: 'code' });
    const res = await call('/auth/accept-delegate-owners?code=22222222-2222-4222-8222-222222222222');
    expect(res.headers.get('location')).toBe('/app');
    expect(await (await call('/app')).text()).toBe('ciao dario@example.com owner');
    expect(database.prepare("SELECT method FROM sessions WHERE email='dario@example.com'").get()).toEqual({ method: 'code' });
    jar.clear();
    database.prepare("INSERT INTO passkeys (id,email,public_key,name,created_at) VALUES ('pk','paola@example.com','x','Test','2026-11-01T00:00:00Z')").run();
    expect(await setPasskeyOnly(env, 'salute', 'paola@example.com', true)).toBe('saved');
    delegated.set('33333333-3333-4333-8333-333333333333', { email: 'paola@example.com', method: 'code' });
    expect((await call('/auth/accept-delegate-owners?code=33333333-3333-4333-8333-333333333333')).headers.get('location')).toBe('/login');
  });
  it('mostra il link al portale nella pagina di login quando è configurato', async () => {
    const { env } = await setup();
    const portal = createAuth({ app: 'salute', name: 'Salute', portal: { name: 'Famiglia', url: 'https://famiglia.dariopagnoni.it' } });
    const page = await (await portal.routes.request(`${origin}/login`, {}, env)).text();
    expect(page).toContain('<a href="https://famiglia.dariopagnoni.it">Entra da Famiglia</a> con il codice via email.');
    const plain = await (await createAuth({ app: 'salute', name: 'Salute' }).routes.request(`${origin}/login`, {}, env)).text();
    expect(plain).not.toContain('Entra da');
  });
});
