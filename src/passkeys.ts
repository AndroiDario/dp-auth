import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse, type AuthenticationResponseJSON, type RegistrationResponseJSON } from '@simplewebauthn/server';
import { base64url, challengeSeconds, consumeChallenge, fromBase64url, fromHex, logEvent, saveChallenge, sha256 } from './session.ts';
import type { AuthEnv, RelyingParty } from './types.ts';
// Passkey: credenziali individuabili con verifica dell'utente (Touch ID, Face ID, Windows Hello, PIN). Nessuna attestazione.
// La chiave pubblica e il contatore restano nel D1; nessun dato biometrico lascia il dispositivo.
const algorithms = [-7, -257];
/** Nome mostrato nella pagina Account per i gestori di passkey più comuni. */
const providers: Record<string, string> = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome su Mac',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
};
export const passkeyName = (aaguid: string | null) => (aaguid && providers[aaguid]) || 'Passkey';
export interface PasskeyRow { id: string; name: string; created_at: string; last_used_at: string | null; backed_up: number; }
export async function passkeysOf(env: AuthEnv, email: string): Promise<PasskeyRow[]> {
  const { results } = await env.DB.prepare('SELECT id,name,created_at,last_used_at,backed_up FROM passkeys WHERE email=? ORDER BY created_at').bind(email).all<PasskeyRow>();
  return results;
}
export async function hasPasskey(env: AuthEnv, email: string): Promise<boolean> {
  return Boolean(await env.DB.prepare('SELECT 1 FROM passkeys WHERE email=?').bind(email).first());
}

export async function registrationOptions(env: AuthEnv, rp: RelyingParty, rpName: string, email: string, now = new Date()) {
  const user = await env.DB.prepare('SELECT webauthn_id FROM users WHERE email=?').bind(email).first<{ webauthn_id: string }>();
  if (!user) return null;
  const { results } = await env.DB.prepare('SELECT id,transports FROM passkeys WHERE email=?').bind(email).all<{ id: string; transports: string }>();
  const options = await generateRegistrationOptions({
    rpName, rpID: rp.id, userName: email, userDisplayName: email, userID: fromHex(user.webauthn_id),
    attestationType: 'none', timeout: challengeSeconds * 1000, supportedAlgorithmIDs: algorithms,
    excludeCredentials: results.map(p => ({ id: p.id, transports: JSON.parse(p.transports) as string[] })),
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
  });
  return { challenge: await saveChallenge(env, 'register', email, options.challenge, challengeSeconds, now), options };
}
/** Registra la passkey del challenge. Restituisce il nome assegnato o null. */
export async function register(env: AuthEnv, rp: RelyingParty, challengeId: string, email: string, response: RegistrationResponseJSON, now = new Date()): Promise<string | null> {
  const challenge = await consumeChallenge(env, challengeId, 'register', now);
  if (!challenge || challenge.email !== email) return null;
  try {
    const result = await verifyRegistrationResponse({ response, expectedChallenge: challenge.secret, expectedOrigin: rp.origin, expectedRPID: rp.id, requireUserVerification: true, supportedAlgorithmIDs: algorithms });
    if (!result.verified) return null;
    const { credential, aaguid, credentialBackedUp } = result.registrationInfo;
    const name = passkeyName(aaguid);
    await env.DB.prepare('INSERT INTO passkeys (id,email,public_key,counter,transports,aaguid,backed_up,name,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(credential.id, email, base64url(credential.publicKey), credential.counter, JSON.stringify(credential.transports ?? []), aaguid, credentialBackedUp ? 1 : 0, name, now.toISOString()).run();
    await logEvent(env, email, 'passkey_added', name, now);
    return name;
  } catch { return null; }
}

export async function loginOptions(env: AuthEnv, rp: RelyingParty, now = new Date()) {
  const options = await generateAuthenticationOptions({ rpID: rp.id, userVerification: 'required', timeout: challengeSeconds * 1000 });
  return { challenge: await saveChallenge(env, 'login', null, options.challenge, challengeSeconds, now), options };
}
/** Email del titolare della passkey verificata o null. */
export async function login(env: AuthEnv, rp: RelyingParty, challengeId: string, response: AuthenticationResponseJSON, now = new Date()): Promise<string | null> {
  const challenge = await consumeChallenge(env, challengeId, 'login', now);
  if (!challenge || typeof response?.id !== 'string') return null;
  const passkey = await env.DB.prepare('SELECT p.id,p.email,p.public_key,p.counter,p.transports,u.webauthn_id FROM passkeys p JOIN users u ON u.email=p.email WHERE p.id=?').bind(response.id)
    .first<{ id: string; email: string; public_key: string; counter: number; transports: string; webauthn_id: string }>();
  if (!passkey) return null;
  // Lo user handle restituito dall'autenticatore deve corrispondere al titolare della credenziale.
  const handle = response.response?.userHandle;
  if (handle && handle !== base64url(fromHex(passkey.webauthn_id))) return null;
  try {
    const result = await verifyAuthenticationResponse({
      response, expectedChallenge: challenge.secret, expectedOrigin: rp.origin, expectedRPID: rp.id, requireUserVerification: true,
      credential: { id: passkey.id, publicKey: fromBase64url(passkey.public_key), counter: passkey.counter, transports: JSON.parse(passkey.transports) as string[] },
    });
    if (!result.verified) return null;
    await env.DB.prepare('UPDATE passkeys SET counter=?,last_used_at=? WHERE id=?').bind(result.authenticationInfo.newCounter, now.toISOString(), passkey.id).run();
    return passkey.email;
  } catch { return null; }
}

export async function renamePasskey(env: AuthEnv, email: string, id: string, name: string): Promise<boolean> {
  const result = await env.DB.prepare('UPDATE passkeys SET name=? WHERE id=? AND email=?').bind(name, id, email).run();
  return Boolean(result.meta.changes);
}
/** Chi accede solo con passkey non può togliere l'ultima. */
export async function removePasskey(env: AuthEnv, email: string, id: string, passkeyOnly: boolean): Promise<'removed' | 'missing' | 'last'> {
  const count = await env.DB.prepare('SELECT COUNT(*) AS n, SUM(id=?) AS found FROM passkeys WHERE email=?').bind(id, email).first<{ n: number; found: number | null }>();
  if (!count?.found) return 'missing';
  if (passkeyOnly && count.n <= 1) return 'last';
  await env.DB.prepare('DELETE FROM passkeys WHERE id=? AND email=?').bind(id, email).run();
  await logEvent(env, email, 'passkey_removed');
  return 'removed';
}

/** Link di attivazione (bin/user-link.mjs): id = SHA-256 del token. Ogni richiesta di opzioni conta un tentativo, al massimo 5. Il link si cancella dopo la registrazione. */
export async function linkEmail(env: AuthEnv, token: string, now = new Date(), attempt = true): Promise<{ id: string; email: string } | null> {
  const id = await sha256(token);
  const row = await env.DB.prepare(attempt
    ? "UPDATE auth_challenges SET attempts=attempts+1 WHERE id=? AND kind='link' AND expires_at>? RETURNING email,attempts"
    : "SELECT email,attempts FROM auth_challenges WHERE id=? AND kind='link' AND expires_at>?").bind(id, now.toISOString()).first<{ email: string; attempts: number }>();
  return row && row.attempts <= 5 ? { id, email: row.email } : null;
}
export async function endLink(env: AuthEnv, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM auth_challenges WHERE id=? AND kind='link'").bind(id).run();
}
/** Crea un link di attivazione per un account esistente. Restituisce il token da mettere nel frammento dell'URL, mai salvato. */
export async function createLink(env: AuthEnv, email: string, minutes = 15, now = new Date()): Promise<string | null> {
  const token = randomTokenForLink(), id = await sha256(token);
  const result = await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_challenges WHERE kind='link' AND email=?").bind(email),
    env.DB.prepare("INSERT INTO auth_challenges (id,kind,email,secret,attempts,expires_at) SELECT ?,'link',email,'',0,? FROM users WHERE email=?").bind(id, new Date(now.getTime() + minutes * 60000).toISOString(), email),
  ]);
  return result[1]?.meta.changes === 1 ? token : null;
}
const randomTokenForLink = () => base64url(crypto.getRandomValues(new Uint8Array(32)));
