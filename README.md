# dp-auth

Login con passkey e codice via email per i servizi su `*.dariopagnoni.it`. Hono su Cloudflare Workers, dati in D1, email via Resend. Derivato dal login nativo di VEDA Analytics (ottobre 2026) e reso indipendente dal framework.

## Cosa fa

- Passkey (Touch ID, Face ID, Windows Hello, PIN) come via principale. Credenziali individuabili, verifica dell'utente obbligatoria, nessuna attestazione.
- Codice di 6 cifre via email come riserva, valido 10 minuti e una sola volta, con 5 tentativi.
- Ruoli per app nella tabella `members`: `owner` accede solo con passkey; `member` e `viewer` anche con il codice, salvo l'opzione «Accedi solo con passkey». L'app decide cosa può fare ciascun ruolo.
- Sessioni opache: token casuale nel cookie `__Host-<app>_session`, SHA-256 nel D1. 30 giorni con passkey, 7 con codice, scadenza per inattività opzionale. «Esci» e «Esci da tutti i dispositivi».
- Limiti: 20 richieste `/auth/*` al minuto per IP (IP salvato come HMAC) e 5 codici all'ora per indirizzo.
- Pagine di login, attivazione e account già pronte, con tema chiaro e scuro e CSP con hash. Nessun bundle esterno.
- Registro `auth_events` di accessi e modifiche, 180 giorni, senza IP né user agent.

## Installazione in un'app

```sh
npm install github:AndroiDario/dp-auth#v0.1.0
cp node_modules/dp-auth/migrations/0001_auth.sql migrations/0001_auth.sql
```

`wrangler.jsonc`:

```jsonc
{
  "vars": { "AUTH_APP": "salute", "AUTH_RP_ID": "salute.dariopagnoni.it", "AUTH_ORIGIN": "https://salute.dariopagnoni.it", "AUTH_FROM": "Salute <accesso@dariopagnoni.it>", "LOCAL_AUTH_ENABLED": "false" },
  "d1_databases": [{ "binding": "DB", "database_name": "salute-db", "database_id": "…", "migrations_dir": "migrations" }]
}
```

Segreti con `npx wrangler secret put`: `AUTH_SECRET` (32 byte casuali) e `AUTH_RESEND_KEY` (chiave Resend «sending access» sul dominio del mittente).

`src/worker.ts`:

```ts
import { Hono } from 'hono';
import { createAuth, securityHeaders, type AuthEnv, type AuthVariables } from 'dp-auth';

const auth = createAuth({ app: 'salute', name: 'Salute', home: '/', idleMinutes: 15 });
const app = new Hono<{ Bindings: AuthEnv & { ASSETS: Fetcher }; Variables: AuthVariables }>();
app.use('*', async (c, next) => { await next(); for (const [k, v] of Object.entries(securityHeaders)) c.res.headers.set(k, v); });
app.route('/', auth.routes);            // /login, /login/attiva, /auth/*, /account
app.use('*', auth.requireSession());    // tutto il resto richiede la sessione
app.get('/api/dati', c => c.json({ chi: c.var.member.email, ruolo: c.var.member.role }));
app.get('*', c => c.env.ASSETS.fetch(c.req.raw)); // bundle e pagine dell'app solo con sessione
export default app;
```

Con `assets.run_worker_first: true` in `wrangler.jsonc` anche i file statici passano dal Worker e restano riservati.

## Persone

```sh
npx dp-auth-member dario@example.com --role owner --name Dario      # crea l'account e il ruolo
npx dp-auth-link dario@example.com                                  # link di attivazione negli appunti, 15 minuti
npx dp-auth-member paola@example.com --role member --name Paola     # accede con il codice, poi crea la passkey
npx dp-auth-member ospite@example.com --remove
```

Gli script leggono `wrangler.jsonc` dell'app (`vars.AUTH_APP`, `vars.AUTH_ORIGIN`, binding D1) ed eseguono SQL con Wrangler. `--local` agisce sul database locale.

## In locale

`.dev.vars` con `LOCAL_AUTH_ENABLED="true"` e `LOCAL_AUTH_SECRET`. Aprire `http://localhost:8787`: WebAuthn non accetta indirizzi IP. Senza `AUTH_RESEND_KEY` i codici restano nella tabella `auth_outbox`; `npx dp-auth-code` copia l'ultimo negli appunti.

## Sviluppo del pacchetto

```sh
npm ci
npm run check
npm test
node scripts/embed-client.mjs   # dopo ogni modifica a client/auth.js
```

I test usano `node:sqlite` al posto di D1 e un autenticatore software ES256 (`tests/fixtures/authenticator.ts`) che produce risposte WebAuthn reali. Dettagli in [docs/accesso.md](docs/accesso.md).
