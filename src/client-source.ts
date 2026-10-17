// Generato da scripts/embed-client.mjs a partire da client/auth.js. Non modificare a mano.
export const authScript = `// @ts-check
// dp-auth: passkey con le API WebAuthn native e codice via email (docs/accesso.md).
// Inline nelle pagine con hash CSP: login, attivazione e account non dipendono da altri bundle.
// La pagina sceglie il comportamento con data-page sul body: login, activate, account.
(() => {
  const page = document.body.dataset.page;
  const error = document.querySelector('#auth-error');
  /** @param {string} text */
  const say = text => { if (error) error.textContent = text; };
  /** @template {Element} T @param {string} selector @returns {T} */
  const $ = selector => /** @type {T} */ (document.querySelector(selector));
  const Credential = /** @type {any} */ (window.PublicKeyCredential);
  const supported = typeof Credential === 'function' && Boolean(navigator.credentials);

  /** @param {Uint8Array} bytes */
  const encode = bytes => btoa(String.fromCharCode(...bytes)).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  /** @param {string} value */
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  /** @param {{ id: string }[] | undefined} list */
  const ids = list => (list ?? []).map(c => ({ ...c, id: decode(c.id) }));
  // Conversione manuale per i browser senza parse*FromJSON e toJSON.
  /** @param {any} json @returns {PublicKeyCredentialRequestOptions} */
  const requestOptions = json => typeof Credential.parseRequestOptionsFromJSON === 'function' ? Credential.parseRequestOptionsFromJSON(json) : { ...json, challenge: decode(json.challenge), allowCredentials: ids(json.allowCredentials) };
  /** @param {any} json @returns {PublicKeyCredentialCreationOptions} */
  const creationOptions = json => typeof Credential.parseCreationOptionsFromJSON === 'function' ? Credential.parseCreationOptionsFromJSON(json) : { ...json, challenge: decode(json.challenge), user: { ...json.user, id: decode(json.user.id) }, excludeCredentials: ids(json.excludeCredentials) };
  /** @param {any} credential */
  function serialize(credential) {
    try { if (typeof credential.toJSON === 'function') return credential.toJSON(); } catch { /* conversione manuale */ }
    /** @param {ArrayBuffer} buffer */
    const b = buffer => encode(new Uint8Array(buffer));
    const r = credential.response;
    const response = 'attestationObject' in r
      ? { clientDataJSON: b(r.clientDataJSON), attestationObject: b(r.attestationObject), transports: r.getTransports?.() ?? [] }
      : { clientDataJSON: b(r.clientDataJSON), authenticatorData: b(r.authenticatorData), signature: b(r.signature), userHandle: r.userHandle ? b(r.userHandle) : undefined };
    return { id: credential.id, rawId: b(credential.rawId), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment ?? undefined, clientExtensionResults: credential.getClientExtensionResults?.() ?? {}, response };
  }
  /** @param {string} path @param {unknown} [body] @param {string} [method] @returns {Promise<any>} */
  async function call(path, body, method = 'POST') {
    const response = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error ?? 'Operazione non riuscita. Riprova.');
    return data;
  }
  /** @param {unknown} reason */
  function failure(reason) {
    const name = reason instanceof DOMException ? reason.name : '';
    if (name === 'AbortError') return;
    if (name === 'NotAllowedError') say('Operazione annullata o scaduta. Riprova.');
    else if (name === 'InvalidStateError') say('Su questo dispositivo esiste già una passkey per questo account.');
    else say(reason instanceof Error ? reason.message : 'Operazione non riuscita. Riprova.');
  }
  /** @param {HTMLButtonElement | null} button @param {() => Promise<void>} action */
  function run(button, action) {
    say('');
    if (button) button.disabled = true;
    action().catch(failure).finally(() => { if (button) button.disabled = false; });
  }
  // body: dati per le opzioni, come il token del link di attivazione. La pagina Account non ne ha.
  async function createPasskey(/** @type {string} */ optionsPath, /** @type {unknown} */ body, /** @type {(credential: unknown) => Promise<any>} */ save) {
    const credential = await navigator.credentials.create({ publicKey: creationOptions(await call(optionsPath, body)) });
    if (credential) return save(serialize(credential));
  }

  if (page === 'login') {
    const passkeyBlock = /** @type {HTMLElement} */ ($('#passkey-block')), requestForm = /** @type {HTMLFormElement} */ ($('#code-request')), verifyForm = /** @type {HTMLFormElement} */ ($('#code-verify'));
    /** @type {AbortController | null} */
    let pending = null;
    // Con mediation 'conditional' il browser propone le passkey nel campo email (autocomplete «username webauthn»).
    /** @param {'conditional' | undefined} mediation */
    async function signIn(mediation) {
      pending?.abort();
      const controller = new AbortController(); pending = controller;
      const publicKey = requestOptions(await call('/auth/passkey/options'));
      const credential = await navigator.credentials.get({ publicKey, mediation, signal: controller.signal });
      if (!credential) return;
      location.assign((await call('/auth/passkey/verify', serialize(credential))).next);
    }
    if (supported && document.body.dataset.passkeys === 'true') {
      passkeyBlock.hidden = false;
      const button = /** @type {HTMLButtonElement} */ ($('#passkey'));
      button.addEventListener('click', () => run(button, () => signIn(undefined)));
      // La richiesta silenziosa del campo email non mostra errori del browser: l'utente non ha ancora scelto nulla.
      Promise.resolve(Credential.isConditionalMediationAvailable?.()).then(available => {
        if (available) signIn('conditional').catch(reason => { if (!(reason instanceof DOMException)) failure(reason); });
      }).catch(() => {});
    }
    requestForm.addEventListener('submit', event => {
      event.preventDefault();
      const email = String(new FormData(requestForm).get('email') ?? '');
      run(requestForm.querySelector('button'), async () => {
        await call('/auth/code/request', { email });
        pending?.abort();
        requestForm.hidden = true; passkeyBlock.hidden = true; verifyForm.hidden = false;
        $('#code-email').textContent = email;
        /** @type {HTMLInputElement} */ ($('#code')).focus();
      });
    });
    verifyForm.addEventListener('submit', event => {
      event.preventDefault();
      run(verifyForm.querySelector('button[type=submit]'), async () => { location.assign((await call('/auth/code/verify', { code: String(new FormData(verifyForm).get('code') ?? '') })).next); });
    });
    $('#code-back').addEventListener('click', () => {
      say(''); verifyForm.reset(); verifyForm.hidden = true; requestForm.hidden = false;
      passkeyBlock.hidden = !(supported && document.body.dataset.passkeys === 'true');
      /** @type {HTMLInputElement} */ ($('#email')).focus();
    });
  }

  if (page === 'activate') {
    // Il token resta nel frammento: non arriva al server nei log né nel Referer. Si toglie dall'indirizzo appena letto.
    const token = location.hash.slice(1), button = /** @type {HTMLButtonElement} */ ($('#activate'));
    history.replaceState(null, '', location.pathname);
    if (!supported || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
      button.disabled = true;
      say(supported ? 'Link non valido. Chiedi un nuovo link.' : 'Questo browser non supporta le passkey. Apri il link con Safari, Chrome, Edge o Firefox aggiornati.');
    } else button.addEventListener('click', () => run(button, () => createPasskey('/auth/link/options', { token }, async credential => {
      location.assign((await call('/auth/link/verify', { token, credential })).next);
    })));
  }

  if (page === 'account') {
    const next = document.body.dataset.next ?? location.pathname;
    for (const button of document.querySelectorAll('[data-add-passkey]')) {
      if (!supported) { /** @type {HTMLButtonElement} */ (button).disabled = true; continue; }
      button.addEventListener('click', () => run(/** @type {HTMLButtonElement} */ (button), async () => {
        await createPasskey('/account/passkeys/options', undefined, credential => call('/account/passkeys', credential));
        location.assign(next);
      }));
    }
    if (!supported) say('Questo browser non supporta le passkey.');
    for (const form of document.querySelectorAll('form[data-rename]')) form.addEventListener('submit', event => {
      event.preventDefault();
      const target = /** @type {HTMLFormElement} */ (form);
      run(target.querySelector('button'), async () => {
        await call(\`/account/passkeys/\${encodeURIComponent(target.dataset.rename ?? '')}\`, { name: String(new FormData(target).get('name') ?? '') }, 'PATCH');
        location.reload();
      });
    });
    for (const button of document.querySelectorAll('button[data-remove]')) button.addEventListener('click', () => {
      if (!confirm('Rimuovere questa passkey? Il dispositivo non potrà più accedere con questa passkey.')) return;
      const target = /** @type {HTMLButtonElement} */ (button);
      run(target, async () => { await call(\`/account/passkeys/\${encodeURIComponent(target.dataset.remove ?? '')}\`, undefined, 'DELETE'); location.reload(); });
    });
    const only = /** @type {HTMLInputElement | null} */ (document.querySelector('#passkey-only'));
    only?.addEventListener('change', () => {
      say('');
      call('/account/settings', { passkeyOnly: only.checked }, 'PATCH').catch(reason => { only.checked = !only.checked; failure(reason); });
    });
    const end = /** @type {HTMLButtonElement | null} */ (document.querySelector('#end-sessions'));
    end?.addEventListener('click', () => {
      if (!confirm('Uscire da tutti i dispositivi, compreso questo?')) return;
      run(end, async () => { location.assign((await call('/account/sessions', undefined, 'DELETE')).next); });
    });
  }
})();
`;
