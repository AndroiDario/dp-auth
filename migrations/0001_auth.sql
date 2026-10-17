-- dp-auth: login con passkey e codice via email. Idempotente: tabelle e indici con IF NOT EXISTS.
-- webauthn_id: 32 byte casuali in esadecimale, user handle WebAuthn diverso dall'email.
CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY CHECK(email = lower(email) AND length(email) <= 254),
  webauthn_id TEXT NOT NULL UNIQUE,
  passkey_only INTEGER NOT NULL DEFAULT 0 CHECK(passkey_only IN (0, 1)),
  created_at TEXT NOT NULL,
  last_login_at TEXT
);
-- Chi accede a quale app e con quale ruolo. owner: solo passkey. name: nome mostrato nell'app.
CREATE TABLE IF NOT EXISTS members (
  app TEXT NOT NULL,
  email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('owner', 'member', 'viewer')),
  name TEXT,
  PRIMARY KEY (app, email)
);
-- Chiave pubblica COSE in base64url. name: etichetta mostrata nella pagina Account.
CREATE TABLE IF NOT EXISTS passkeys (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  aaguid TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS passkeys_email ON passkeys(email);
-- id: SHA-256 esadecimale del token nel cookie. Il token non viene salvato.
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  method TEXT NOT NULL CHECK(method IN ('passkey', 'code')),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_email ON sessions(email);
-- Challenge monouso. secret: challenge WebAuthn, HMAC del codice o vuoto per il link (id = SHA-256 del token).
CREATE TABLE IF NOT EXISTS auth_challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('login', 'register', 'code', 'link')),
  email TEXT,
  secret TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL
);
-- Limiti per finestra di tempo. bucket: minuto o ora ISO, poi la chiave (IP come HMAC, email come HMAC).
CREATE TABLE IF NOT EXISTS login_attempts (
  bucket TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL DEFAULT 0
);
-- Registro degli accessi, conservato 180 giorni. Nessun IP né user agent.
CREATE TABLE IF NOT EXISTS auth_events (
  at TEXT NOT NULL,
  email TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS auth_events_at ON auth_events(at);
CREATE INDEX IF NOT EXISTS auth_events_email ON auth_events(email, at);
-- Solo in locale senza chiave di invio: bin/local-code.mjs copia l'ultimo codice negli appunti.
CREATE TABLE IF NOT EXISTS auth_outbox (
  email TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at TEXT NOT NULL
);
