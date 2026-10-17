import { describe, it, expect } from 'vitest';
import { authenticate, authSecret, relyingParty } from '../src/auth.ts';
import { maxCodeAttempts, overLimit, requestCode, sendMail, verifyCode } from '../src/code.ts';
import { accountOf, addMember, codeAllowed, removeMember, setPasskeyOnly } from '../src/members.ts';
import { createLink, linkEmail, login, loginOptions, register, registrationOptions, removePasskey } from '../src/passkeys.ts';
import { createSession, randomToken, sessionEmail, sha256 } from '../src/session.ts';
import type { AuthConfig } from '../src/types.ts';
import { SoftAuthenticator } from './fixtures/authenticator.ts';
import { testEnv } from './sqlite.ts';
// Sessioni, codice via email, passkey, link di attivazione e membri (docs/accesso.md).
const secret = 'segreto-di-test';
const rp = { id: 'salute.dariopagnoni.it', origin: 'https://salute.dariopagnoni.it' };
const config: AuthConfig = { app: 'salute', name: 'Salute' };
async function setup() {
  const { env, database } = testEnv();
  await addMember(env, 'salute', 'dario@example.com', 'owner', 'Dario', 'test');
  await addMember(env, 'salute', 'paola@example.com', 'member', 'Paola', 'test');
  await addMember(env, 'budget', 'ospite@example.com', 'viewer', null, 'test');
  return { env, database };
}
const codeOf = (text: string) => /è (\d{6})\./.exec(text)![1]!;

describe('Sessioni', () => {
  it('riconosce la sessione valida e rifiuta scadute, contraffatte e di utenti cancellati', async () => {
    const { env, database } = await setup(), now = new Date('2026-10-17T10:00:00Z');
    const { token, maxAge } = await createSession(env, config, 'paola@example.com', 'code', now);
    expect(maxAge).toBe(7 * 86400);
    expect(database.prepare('SELECT id FROM sessions').get()).toEqual({ id: await sha256(token) });
    expect(await sessionEmail(env, config, token, now)).toBe('paola@example.com');
    expect(await sessionEmail(env, config, token, new Date('2026-10-24T10:00:01Z'))).toBeNull();
    expect(await sessionEmail(env, config, randomToken(), now)).toBeNull();
    database.exec("DELETE FROM sessions; DELETE FROM users WHERE email='paola@example.com'");
    expect(await sessionEmail(env, config, token, now)).toBeNull();
  });
  it('dura 30 giorni con passkey e aggiorna l’ultimo uso al massimo una volta l’ora', async () => {
    const { env, database } = await setup(), now = new Date('2026-10-17T10:00:00Z');
    const { token, maxAge } = await createSession(env, config, 'dario@example.com', 'passkey', now);
    expect(maxAge).toBe(30 * 86400);
    await sessionEmail(env, config, token, new Date('2026-10-17T10:30:00Z'));
    expect(database.prepare('SELECT last_seen_at FROM sessions').get()).toEqual({ last_seen_at: '2026-10-17T10:00:00.000Z' });
    await sessionEmail(env, config, token, new Date('2026-10-17T11:00:01Z'));
    expect(database.prepare('SELECT last_seen_at FROM sessions').get()).toEqual({ last_seen_at: '2026-10-17T11:00:01.000Z' });
    expect(database.prepare("SELECT event,detail FROM auth_events WHERE email='dario@example.com' AND event='login'").get()).toEqual({ event: 'login', detail: 'passkey' });
  });
  it('scade per inattività quando l’app lo chiede', async () => {
    const { env } = await setup(), now = new Date('2026-10-17T10:00:00Z'), idle = { ...config, idleMinutes: 15 };
    const { token } = await createSession(env, idle, 'dario@example.com', 'passkey', now);
    expect(await sessionEmail(env, idle, token, new Date('2026-10-17T10:14:00Z'))).toBe('dario@example.com');
    expect(await sessionEmail(env, idle, token, new Date('2026-10-17T10:28:00Z'))).toBe('dario@example.com');
    expect(await sessionEmail(env, idle, token, new Date('2026-10-17T10:44:00Z'))).toBeNull();
    expect(await sessionEmail(env, idle, token, new Date('2026-10-17T10:45:00Z'))).toBeNull();
  });
  it('legge il cookie __Host- online e il cookie locale solo in anteprima locale, con il ruolo dell’app', async () => {
    const { env } = await setup(), { token } = await createSession(env, config, 'paola@example.com', 'passkey');
    expect(await authenticate(new Request('https://salute.dariopagnoni.it/', { headers: { cookie: `__Host-salute_session=${token}` } }), env, config)).toEqual({ email: 'paola@example.com', role: 'member', name: 'Paola' });
    expect(await authenticate(new Request('https://salute.dariopagnoni.it/', { headers: { cookie: `salute_session=${token}` } }), env, config)).toBeNull();
    expect(await authenticate(new Request('http://localhost:8787/', { headers: { cookie: `salute_session=${token}` } }), env, config)).toBeNull();
    Object.assign(env, { LOCAL_AUTH_ENABLED: 'true' });
    expect((await authenticate(new Request('http://localhost:8787/', { headers: { cookie: `salute_session=${token}` } }), env, config))?.email).toBe('paola@example.com');
    expect(await authenticate(new Request('http://example.com/', { headers: { cookie: `salute_session=${token}` } }), env, config)).toBeNull();
    // Stessa sessione, altra app: senza membership l'accesso è negato.
    expect(await authenticate(new Request('https://salute.dariopagnoni.it/', { headers: { cookie: `__Host-salute_session=${token}` } }), env, { app: 'budget', name: 'Budget', cookiePrefix: 'salute_' })).toBeNull();
  });
  it('prende rpID e origine dalla configurazione, mai dall’host della richiesta', async () => {
    const { env } = await setup();
    Object.assign(env, { AUTH_RP_ID: rp.id, AUTH_ORIGIN: rp.origin });
    expect(relyingParty(new URL('https://salute.dariopagnoni.it/login'), env)).toEqual(rp);
    expect(relyingParty(new URL('https://altro.example.com/login'), env)).toBeNull();
    expect(relyingParty(new URL('http://localhost:8787/login'), env)).toBeNull();
    Object.assign(env, { LOCAL_AUTH_ENABLED: 'true', LOCAL_AUTH_SECRET: 'locale' });
    expect(relyingParty(new URL('http://localhost:8787/login'), env)).toEqual({ id: 'localhost', origin: 'http://localhost:8787' });
    expect(relyingParty(new URL('http://127.0.0.1:8787/login'), env)).toBeNull();
    expect(authSecret(new URL('http://localhost:8787/login'), env)).toBe('locale');
    expect(authSecret(new URL('https://salute.dariopagnoni.it/login'), env)).toBeNull();
  });
});

describe('Membri', () => {
  it('crea l’account una volta sola e aggiorna ruolo e nome', async () => {
    const { env, database } = await setup();
    await addMember(env, 'budget', 'paola@example.com', 'owner', null, 'test');
    expect(database.prepare("SELECT COUNT(*) AS n FROM users WHERE email='paola@example.com'").get()).toEqual({ n: 1 });
    expect(await accountOf(env, 'budget', 'paola@example.com')).toMatchObject({ role: 'owner', owner: true, passkeyOnly: true, name: null });
    await addMember(env, 'salute', 'paola@example.com', 'viewer', 'Paola M.', 'test');
    expect(await accountOf(env, 'salute', 'paola@example.com')).toMatchObject({ role: 'viewer', owner: false, passkeyOnly: false, name: 'Paola M.' });
    expect(database.prepare('SELECT webauthn_id FROM users WHERE email=?').get('paola@example.com')).toMatchObject({ webauthn_id: expect.stringMatching(/^[0-9a-f]{64}$/) });
  });
  it('alla revoca cancella l’account solo senza altre app', async () => {
    const { env, database } = await setup();
    await addMember(env, 'budget', 'paola@example.com', 'member', null, 'test');
    await createSession(env, config, 'paola@example.com', 'code');
    expect(await removeMember(env, 'salute', 'paola@example.com', 'test')).toBe('removed');
    expect(database.prepare("SELECT COUNT(*) AS n FROM users WHERE email='paola@example.com'").get()).toEqual({ n: 1 });
    expect(database.prepare("SELECT COUNT(*) AS n FROM sessions WHERE email='paola@example.com'").get()).toEqual({ n: 1 });
    expect(await removeMember(env, 'budget', 'paola@example.com', 'test')).toBe('removed');
    expect(database.prepare("SELECT COUNT(*) AS n FROM users WHERE email='paola@example.com'").get()).toEqual({ n: 0 });
    expect(database.prepare("SELECT COUNT(*) AS n FROM sessions WHERE email='paola@example.com'").get()).toEqual({ n: 0 });
    expect(await removeMember(env, 'budget', 'paola@example.com', 'test')).toBe('missing');
  });
});

describe('Codice via email', () => {
  it('accede con il codice giusto, una sola volta', async () => {
    const { env } = await setup();
    const { id, message } = await requestCode(env, config, rp.origin, 'paola@example.com', secret);
    expect(message!.subject).not.toMatch(/\d{6}/);
    expect(message!.text).toContain(rp.origin);
    expect(await verifyCode(env, config, id, '000000' === codeOf(message!.text) ? '111111' : '000000', secret)).toBeNull();
    expect(await verifyCode(env, config, id, codeOf(message!.text), secret)).toBe('paola@example.com');
    expect(await verifyCode(env, config, id, codeOf(message!.text), secret)).toBeNull();
  });
  it('rifiuta codici scaduti, di un altro browser e oltre il quinto tentativo', async () => {
    const { env } = await setup(), now = new Date('2026-10-17T10:00:00Z');
    const first = await requestCode(env, config, rp.origin, 'paola@example.com', secret, now), second = await requestCode(env, config, rp.origin, 'paola@example.com', secret, now);
    expect(await verifyCode(env, config, first.id, codeOf(first.message!.text), secret, new Date('2026-10-17T10:10:01Z'))).toBeNull();
    expect(await verifyCode(env, config, first.id, codeOf(second.message!.text), secret, now)).toBe(codeOf(first.message!.text) === codeOf(second.message!.text) ? 'paola@example.com' : null);
    const third = await requestCode(env, config, rp.origin, 'paola@example.com', secret, now), code = codeOf(third.message!.text), wrong = code === '123456' ? '654321' : '123456';
    for (let i = 0; i < maxCodeAttempts; i++) expect(await verifyCode(env, config, third.id, wrong, secret, now)).toBeNull();
    expect(await verifyCode(env, config, third.id, code, secret, now)).toBeNull();
  });
  it('non invia codici a owner, indirizzi sconosciuti, membri di altre app e account solo passkey', async () => {
    const { env } = await setup();
    for (const email of ['dario@example.com', 'nessuno@example.com', 'ospite@example.com']) {
      const { id, message } = await requestCode(env, config, rp.origin, email, secret);
      expect(message).toBeNull();
      expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(await codeAllowed(env, 'salute', email)).toBe(false);
    }
    expect(await setPasskeyOnly(env, 'salute', 'paola@example.com', true)).toBe('no-passkey');
    expect(await setPasskeyOnly(env, 'salute', 'dario@example.com', true)).toBe('owner');
    const device = new SoftAuthenticator(rp.origin, rp.id), { challenge, options } = (await registrationOptions(env, rp, 'Salute', 'paola@example.com'))!;
    await register(env, rp, challenge, 'paola@example.com', await device.create(options));
    expect(await setPasskeyOnly(env, 'salute', 'paola@example.com', true)).toBe('saved');
    expect((await requestCode(env, config, rp.origin, 'paola@example.com', secret)).message).toBeNull();
    expect(await removePasskey(env, 'paola@example.com', device.id, true)).toBe('last');
  });
  it('limita le richieste per finestra di tempo', async () => {
    const { env } = await setup(), now = new Date('2026-10-17T10:00:30Z');
    for (let i = 0; i < 20; i++) expect(await overLimit(env, 'ip|a', 20, 'minute', now)).toBe(false);
    expect(await overLimit(env, 'ip|a', 20, 'minute', now)).toBe(true);
    expect(await overLimit(env, 'ip|b', 20, 'minute', now)).toBe(false);
    expect(await overLimit(env, 'ip|a', 20, 'minute', new Date('2026-10-17T10:01:00Z'))).toBe(false);
  });
  it('invia con la chiave Resend e in locale senza chiave usa l’archivio locale', async () => {
    const { env, database } = await setup(), calls: [string, RequestInit][] = [];
    const message = { subject: 'Oggetto', text: 'Testo' };
    const log = console.error; console.error = () => {};
    try { expect(await sendMail(env, false, 'paola@example.com', message)).toBe(false); } finally { console.error = log; }
    expect(await sendMail(env, true, 'paola@example.com', message)).toBe(true);
    expect(database.prepare('SELECT email,text FROM auth_outbox').get()).toEqual({ email: 'paola@example.com', text: 'Testo' });
    Object.assign(env, { AUTH_RESEND_KEY: 're_test', AUTH_FROM: 'Salute <accesso@dariopagnoni.it>' });
    const transport = (async (url: string, init: RequestInit) => { calls.push([url, init]); return new Response('{}'); }) as unknown as typeof fetch;
    expect(await sendMail(env, false, 'paola@example.com', message, transport)).toBe(true);
    expect(calls[0]![0]).toBe('https://api.resend.com/emails');
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({ from: 'Salute <accesso@dariopagnoni.it>', to: ['paola@example.com'], subject: 'Oggetto', text: 'Testo' });
  });
});

describe('Passkey', () => {
  async function enrolled() {
    const { env, database } = await setup(), device = new SoftAuthenticator(rp.origin, rp.id);
    const { challenge, options } = (await registrationOptions(env, rp, 'Salute', 'dario@example.com'))!;
    expect(options.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
    expect(options.rp).toEqual({ id: rp.id, name: 'Salute' });
    expect(await register(env, rp, challenge, 'dario@example.com', await device.create(options))).toBe('iCloud Keychain');
    return { env, database, device };
  }
  it('registra una passkey sincronizzata con il nome del gestore', async () => {
    const { database, device } = await enrolled();
    expect(database.prepare('SELECT id,email,backed_up,name FROM passkeys').get()).toEqual({ id: device.id, email: 'dario@example.com', backed_up: 1, name: 'iCloud Keychain' });
    expect(database.prepare("SELECT event FROM auth_events WHERE event='passkey_added'").get()).toEqual({ event: 'passkey_added' });
  });
  it('rifiuta registrazioni con origine, rpID, utente o challenge sbagliati e senza verifica dell’utente', async () => {
    const { env } = await setup();
    for (const overrides of [{ origin: 'https://evil.example.com' }, { rpId: 'evil.example.com' }, { userVerified: false }]) {
      const { challenge, options } = (await registrationOptions(env, rp, 'Salute', 'dario@example.com'))!;
      expect(await register(env, rp, challenge, 'dario@example.com', await new SoftAuthenticator(rp.origin, rp.id).create(options, overrides))).toBeNull();
    }
    const { challenge, options } = (await registrationOptions(env, rp, 'Salute', 'dario@example.com'))!;
    expect(await register(env, rp, challenge, 'paola@example.com', await new SoftAuthenticator(rp.origin, rp.id).create(options))).toBeNull();
    expect(await register(env, rp, challenge, 'dario@example.com', await new SoftAuthenticator(rp.origin, rp.id).create(options))).toBeNull();
    expect(await registrationOptions(env, rp, 'Salute', 'nessuno@example.com')).toBeNull();
  });
  it('accede con la passkey e aggiorna contatore e ultimo uso', async () => {
    const { env, database, device } = await enrolled();
    const { challenge, options } = await loginOptions(env, rp);
    expect(options).toMatchObject({ rpId: rp.id, userVerification: 'required' });
    const response = await device.get(options);
    expect(await login(env, rp, challenge, response)).toBe('dario@example.com');
    expect(database.prepare('SELECT counter, last_used_at IS NOT NULL AS used FROM passkeys').get()).toEqual({ counter: 1, used: 1 });
    expect(await login(env, rp, challenge, response)).toBeNull();
  });
  it('rifiuta accessi con origine o rpID sbagliati, user handle diverso, credenziali sconosciute e challenge scaduti', async () => {
    const { env, device } = await enrolled();
    for (const overrides of [{ origin: 'https://evil.example.com' }, { rpId: 'evil.example.com' }, { userHandle: new Uint8Array(32) }]) {
      const { challenge, options } = await loginOptions(env, rp);
      expect(await login(env, rp, challenge, await device.get(options, overrides))).toBeNull();
    }
    const stranger = new SoftAuthenticator(rp.origin, rp.id), { options: registration } = (await registrationOptions(env, rp, 'Salute', 'paola@example.com'))!;
    await stranger.create(registration);
    const { challenge, options } = await loginOptions(env, rp);
    expect(await login(env, rp, challenge, await stranger.get(options))).toBeNull();
    const expired = await loginOptions(env, rp, new Date(Date.now() - 301000));
    expect(await login(env, rp, expired.challenge, await device.get(expired.options))).toBeNull();
  });
});

describe('Link di attivazione', () => {
  it('vale per cinque richieste e fino alla scadenza, solo per account esistenti', async () => {
    const { env } = await setup(), now = new Date('2026-10-17T10:00:00Z');
    expect(await createLink(env, 'nessuno@example.com', 15, now)).toBeNull();
    const token = (await createLink(env, 'dario@example.com', 15, now))!;
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(await linkEmail(env, randomToken(), now)).toBeNull();
    expect(await linkEmail(env, token, new Date('2026-10-17T10:15:01Z'))).toBeNull();
    for (let i = 0; i < 5; i++) expect((await linkEmail(env, token, now))?.email).toBe('dario@example.com');
    expect((await linkEmail(env, token, now, false))?.email).toBe('dario@example.com');
    expect(await linkEmail(env, token, now)).toBeNull();
    expect(await linkEmail(env, token, now, false)).toBeNull();
  });
});
