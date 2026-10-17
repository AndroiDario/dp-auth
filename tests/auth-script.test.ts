import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
// Script del browser (client/auth.js) in un DOM minimo: le richieste devono portare i dati che il server si aspetta.
const source = readFileSync(join(fileURLToPath(import.meta.url), '..', '..', 'client', 'auth.js'), 'utf8');
const token = 'a'.repeat(43);

function page(name: string, hash = '') {
  const listeners = new Map<string, () => void>(), calls: { path: string; method: string; body: unknown }[] = [], assigned: string[] = [];
  const element = (id: string) => ({ id, textContent: '', hidden: false, disabled: false, dataset: {}, addEventListener: (_: string, handler: () => void) => listeners.set(id, handler), querySelector: () => null, focus() {} });
  const elements = new Map(['#auth-error', '#activate', 'add'].map(id => [id, element(id)]));
  const responses: Record<string, unknown> = {
    '/auth/link/options': { challenge: 'Y2hhbGxlbmdl', rp: { id: 'salute.dariopagnoni.it', name: 'Salute' }, user: { id: 'dXNlcg', name: 'dario@example.com', displayName: 'dario@example.com' }, pubKeyCredParams: [], excludeCredentials: [] },
    '/auth/link/verify': { next: '/app' },
    '/account/passkeys/options': { challenge: 'Y2hhbGxlbmdl', rp: { id: 'salute.dariopagnoni.it', name: 'Salute' }, user: { id: 'dXNlcg', name: 'dario@example.com', displayName: 'dario@example.com' }, pubKeyCredParams: [], excludeCredentials: [] },
    '/account/passkeys': { name: 'iCloud Keychain' },
  };
  const context = {
    document: { body: { dataset: { page: name } }, querySelector: (selector: string) => elements.get(selector) ?? null, querySelectorAll: (selector: string) => selector === '[data-add-passkey]' ? [elements.get('add')] : [] },
    window: { PublicKeyCredential: function PublicKeyCredential() {} },
    navigator: { credentials: { create: async () => ({ toJSON: () => ({ id: 'credenziale', response: {} }) }) } },
    location: { hash, pathname: name === 'account' ? '/account' : '/login/attiva', assign: (url: string) => assigned.push(url) },
    history: { replaceState() {} },
    fetch: async (path: string, init: { method: string; body?: string }) => {
      calls.push({ path, method: init.method, body: init.body === undefined ? undefined : JSON.parse(init.body) });
      return { ok: true, json: async () => responses[path] };
    },
    atob, btoa, DOMException, Uint8Array, Error, Promise, JSON, String,
  };
  runInNewContext(source, context);
  return { listeners, calls, assigned, elements };
}

describe('Script di attivazione della passkey', () => {
  it('invia il token del link sia per le opzioni sia per la verifica', async () => {
    const { listeners, calls, assigned } = page('activate', `#${token}`);
    listeners.get('#activate')!();
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(calls).toEqual([
      { path: '/auth/link/options', method: 'POST', body: { token } },
      { path: '/auth/link/verify', method: 'POST', body: { token, credential: { id: 'credenziale', response: {} } } },
    ]);
    expect(assigned).toEqual(['/app']);
  });
  it('nella pagina Account chiede le opzioni senza dati e salva la credenziale', async () => {
    const { listeners, calls, assigned } = page('account');
    listeners.get('add')!();
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(calls).toEqual([
      { path: '/account/passkeys/options', method: 'POST', body: undefined },
      { path: '/account/passkeys', method: 'POST', body: { id: 'credenziale', response: {} } },
    ]);
    expect(assigned).toEqual(['/account']);
  });
  it('blocca un link senza token valido senza chiamare il server', () => {
    const { listeners, calls, elements } = page('activate', '#corto');
    expect(listeners.has('#activate')).toBe(false);
    expect(calls).toEqual([]);
    expect(elements.get('#activate')!.disabled).toBe(true);
    expect(elements.get('#auth-error')!.textContent).toBe('Link non valido. Chiedi un nuovo link.');
  });
});
