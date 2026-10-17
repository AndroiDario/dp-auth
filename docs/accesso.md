# Accesso: passkey e codice via email

## Metodi

| Ruolo | Passkey | Codice via email |
| --- | --- | --- |
| owner | Sì, unico metodo | No |
| member, viewer | Sì | Sì, salvo l'opzione «Accedi solo con passkey» |
| Indirizzo senza membership nell'app | No | No |

La passkey usa Touch ID, Face ID, Windows Hello o il PIN del dispositivo. Con iCloud Keychain o Google Password Manager arriva sugli altri dispositivi dello stesso account. Il server conserva chiave pubblica e contatore.
Il codice ha 6 cifre, scade in 10 minuti e vale una volta. Arriva come testo, con il codice nel corpo e non nell'oggetto, e la nota «Non rispondere».
Dopo un accesso con codice senza passkey la pagina Account propone di crearne una.

## Flussi

- **Passkey**: pulsante «Accedi con passkey» o proposta del browser nel campo email (`autocomplete="username webauthn"`). `POST /auth/passkey/options`, poi `POST /auth/passkey/verify`. La verifica controlla anche che l'email sia membro dell'app.
- **Codice**: `POST /auth/code/request`, poi `POST /auth/code/verify`. La risposta alla richiesta è identica per indirizzi abilitati, sconosciuti e owner. L'invio parte dopo la risposta.
- **Link di attivazione**: `npx dp-auth-link <email>` copia negli appunti un link `/login/attiva#<token>` valido 15 minuti. Nel D1 va solo lo SHA-256 del token. Serve agli owner senza passkey e al recupero dopo la perdita dei dispositivi.
- **Uscita**: «Esci da questo dispositivo» chiude la sessione corrente (`POST /auth/logout`). «Esci da tutti i dispositivi» chiude tutte le sessioni dell'account (`DELETE /account/sessions`).

## Protezioni

- Rotte `/auth/*` pubbliche, solo `POST` dalla stessa origine, con limite per IP.
- Parametri WebAuthn dalla configurazione (`AUTH_RP_ID`, `AUTH_ORIGIN`), mai dall'header Host. Lo user handle è un valore casuale, diverso dall'email.
- Challenge monouso legati al browser con un cookie `__Host-` di 5 minuti. Il codice ha un cookie separato.
- Codice salvato come HMAC con `AUTH_SECRET`, al massimo 5 tentativi.
- Le scritture sotto sessione richiedono la stessa origine (`requireSession`).
- Il ruolo si rilegge a ogni richiesta: togliere un membro ha effetto subito. Senza altre app l'account si cancella con passkey e sessioni.
- Pagine con CSP `default-src 'none'` e hash degli script e dello stile inline.

## Tabelle

`users` (account condiviso fra le app sullo stesso D1), `members` (app, email, ruolo, nome), `passkeys`, `sessions`, `auth_challenges`, `login_attempts`, `auth_events`, `auth_outbox` (solo locale). Schema in `migrations/0001_auth.sql`.

## Verifiche

`npm test`: sessioni (scadenza, inattività, cookie `__Host-`, ruolo per app), codice (una volta sola, scaduto, altro browser, 6° tentativo, owner e sconosciuti senza invio, limiti), passkey (origine e rpID errati, utente diverso, challenge riusato o scaduto, credenziale sconosciuta, registrazione senza verifica dell'utente), link (5 richieste, scadenza, account inesistente), rotte complete (codice in locale, account, passkey, logout, origine, 429).
Le cerimonie biometriche reali vanno provate nel browser: Touch ID su `localhost` e Face ID online.
