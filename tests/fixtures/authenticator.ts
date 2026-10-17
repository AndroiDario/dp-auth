import { createHash } from 'node:crypto';
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from '@simplewebauthn/server';
// Autenticatore software ES256 per i test: produce risposte WebAuthn reali, con attestazione «none» e firma DER.
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const sha256 = (bytes: Uint8Array | string) => new Uint8Array(createHash('sha256').update(bytes).digest());
const concat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap(p => [...p]));
const uint32 = (value: number) => Uint8Array.of(value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
// CBOR minimo: interi piccoli, stringhe e byte con lunghezza fino a 65535.
const head = (major: number, length: number) => length < 24 ? Uint8Array.of(major << 5 | length) : length < 256 ? Uint8Array.of(major << 5 | 24, length) : Uint8Array.of(major << 5 | 25, length >> 8, length & 255);
const text = (value: string) => concat(head(3, value.length), new TextEncoder().encode(value));
const bytes = (value: Uint8Array) => concat(head(2, value.length), value);
function der(raw: Uint8Array): Uint8Array {
  const integer = (part: Uint8Array) => {
    let start = 0; while (start < part.length - 1 && part[start] === 0) start++;
    const value = part[start]! & 0x80 ? concat(Uint8Array.of(0), part.slice(start)) : part.slice(start);
    return concat(Uint8Array.of(0x02, value.length), value);
  };
  const r = integer(raw.slice(0, 32)), s = integer(raw.slice(32));
  return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
}
export const icloud = 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd';

export class SoftAuthenticator {
  readonly credentialId = crypto.getRandomValues(new Uint8Array(32));
  counter = 0;
  userId: Uint8Array | null = null;
  private keys: CryptoKeyPair | null = null;
  constructor(public origin: string, public rpId: string, public aaguid = icloud) {}
  get id() { return b64(this.credentialId); }

  async create(options: PublicKeyCredentialCreationOptionsJSON, overrides: { origin?: string; rpId?: string; userVerified?: boolean } = {}): Promise<RegistrationResponseJSON> {
    this.keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    this.userId = Buffer.from(options.user.id, 'base64url');
    const jwk = await crypto.subtle.exportKey('jwk', this.keys.publicKey) as JsonWebKey;
    // Chiave COSE EC2: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
    const cose = concat(Uint8Array.of(0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21), bytes(Buffer.from(jwk.x!, 'base64url')), Uint8Array.of(0x22), bytes(Buffer.from(jwk.y!, 'base64url')));
    const aaguid = Buffer.from(this.aaguid.replace(/-/g, ''), 'hex');
    // Flag: presenza, verifica dell'utente (se richiesta), credenziale sincronizzabile e sincronizzata, dati attestati.
    const flags = 0x01 | (overrides.userVerified === false ? 0 : 0x04) | 0x08 | 0x10 | 0x40;
    const authData = concat(sha256(overrides.rpId ?? this.rpId), Uint8Array.of(flags), uint32(this.counter), aaguid, Uint8Array.of(0, this.credentialId.length), this.credentialId, cose);
    const attestation = concat(Uint8Array.of(0xa3), text('fmt'), text('none'), text('attStmt'), Uint8Array.of(0xa0), text('authData'), bytes(authData));
    const clientData = JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: overrides.origin ?? this.origin, crossOrigin: false });
    return { id: this.id, rawId: this.id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64(new TextEncoder().encode(clientData)), attestationObject: b64(attestation), transports: ['internal', 'hybrid'] } };
  }

  async get(options: PublicKeyCredentialRequestOptionsJSON, overrides: { origin?: string; rpId?: string; userHandle?: Uint8Array | null } = {}): Promise<AuthenticationResponseJSON> {
    if (!this.keys) throw new Error('Passkey non creata.');
    this.counter++;
    const authData = concat(sha256(overrides.rpId ?? this.rpId), Uint8Array.of(0x01 | 0x04 | 0x08 | 0x10), uint32(this.counter));
    const clientData = new TextEncoder().encode(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: overrides.origin ?? this.origin, crossOrigin: false }));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, concat(authData, sha256(clientData))));
    const userHandle = overrides.userHandle === undefined ? this.userId : overrides.userHandle;
    return { id: this.id, rawId: this.id, type: 'public-key', clientExtensionResults: {}, authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64(clientData), authenticatorData: b64(authData), signature: b64(der(raw)), ...userHandle ? { userHandle: b64(userHandle) } : {} } };
  }
}
