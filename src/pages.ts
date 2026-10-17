import { authScript } from './client-source.ts';
import type { PasskeyRow } from './passkeys.ts';
import type { Account } from './members.ts';
import { cspHash, type AuthEvent, type SessionRow } from './session.ts';
import type { AuthConfig } from './types.ts';
// Pagine di login, attivazione e account: HTML con CSS e script inline, tema chiaro e scuro, hash CSP.

export const themeScript = `(()=>{const k='dp_theme',d=document,r=d.documentElement,m=matchMedia('(prefers-color-scheme: dark)');
const stored=()=>{try{const v=localStorage.getItem(k);return v==='light'||v==='dark'?v:null;}catch{return null;}};
const sync=()=>{const dark=r.dataset.theme==='dark';for(const b of d.querySelectorAll('[data-theme-toggle]')){b.setAttribute('aria-pressed',String(dark));b.setAttribute('aria-label',dark?'Attiva tema chiaro':'Attiva tema scuro');}};
const apply=t=>{r.dataset.theme=t;d.querySelector('meta[name="theme-color"]')?.setAttribute('content',t==='dark'?'#101418':'#f6f4ef');sync();};
apply(stored()??(m.matches?'dark':'light'));
d.addEventListener('DOMContentLoaded',sync);
d.addEventListener('click',e=>{const b=e.target instanceof Element?e.target.closest('[data-theme-toggle]'):null;if(!b)return;const t=r.dataset.theme==='dark'?'light':'dark';apply(t);try{localStorage.setItem(k,t);}catch{}});
m.addEventListener('change',e=>{if(!stored())apply(e.matches?'dark':'light');});
})();`;

export const pageCss = `:root{--bg:#f6f4ef;--paper:#fff;--ink:#1c1b19;--ink-2:#3a3835;--muted:#6b6862;--faint:#9a968e;--border:#e4e0d7;--border-strong:#cfcac0;--accent:#5c7f5a;--accent-ink:#3f5e3e;--red:#b4443a;--on-ink:#fff;--hover:#f1eee7;--shadow:rgba(28,27,25,.08);--track:#e4e0d7}
:root[data-theme=dark]{--bg:#101418;--paper:#171c21;--ink:#ecebe6;--ink-2:#d4d2cb;--muted:#a09d95;--faint:#77746d;--border:#2a3038;--border-strong:#3a414a;--accent:#8fb08c;--accent-ink:#b5cfb2;--red:#e07a70;--on-ink:#101418;--hover:#1f252b;--shadow:rgba(0,0,0,.4);--track:#2a3038}
*{box-sizing:border-box}html{color-scheme:light dark}body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif;color:var(--ink);background:var(--bg);display:grid;place-items:center;min-height:100vh;padding:56px 16px}
.card{width:100%;max-width:420px;background:var(--paper);border:1px solid var(--border);border-radius:16px;padding:36px 32px;box-shadow:0 18px 50px var(--shadow)}.card.wide{max-width:560px}
.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--accent-ink);font-weight:650;margin:0 0 10px}h1{font-size:24px;letter-spacing:-.5px;font-weight:650;line-height:1.25;margin:0 0 20px}h2{font-size:14px;margin:28px 0 10px}p{margin:0 0 12px;color:var(--ink-2)}
form,.stack{display:grid;gap:12px}label{font-size:13px;color:var(--muted)}input{font:inherit;padding:11px 12px;border:1px solid var(--border-strong);border-radius:8px;background:var(--paper);color:var(--ink);min-width:0;width:100%}input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
.button{font:inherit;font-size:14px;font-weight:550;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 16px;border-radius:8px;border:1px solid var(--border-strong);background:var(--paper);color:var(--ink);cursor:pointer;min-height:42px}.button:hover{background:var(--hover)}.button.primary{background:var(--ink);color:var(--on-ink);border-color:var(--ink)}.button:disabled{opacity:.5;cursor:default}
.text-button{font:inherit;font-size:13px;background:none;border:0;padding:6px 0;color:var(--muted);text-decoration:underline;text-underline-offset:3px;cursor:pointer;justify-self:start}.text-button:hover{color:var(--ink)}.text-button.danger{color:var(--red)}a{color:inherit}
.hint{font-size:13px;color:var(--muted);margin:0;line-height:1.5}.hint strong{color:var(--ink);word-break:break-all}.divider{display:flex;align-items:center;gap:12px;font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.08em;margin:8px 0 4px}.divider::before,.divider::after{content:'';flex:1;border-top:1px solid var(--border)}
.foot{font-size:12px;color:var(--muted);margin:24px 0 0;border-top:1px solid var(--border);padding-top:16px}#auth-error{font-size:13px;color:var(--red);margin:12px 0 0}#auth-error:empty{display:none}
.email{font-size:14px;font-weight:600;margin:-10px 0 0;word-break:break-all}ul.list{list-style:none;margin:0 0 12px;padding:0;display:grid;gap:8px}ul.list li{display:grid;gap:4px;padding:12px 14px;border:1px solid var(--border);border-radius:10px;font-size:14px}ul.list span{font-size:12px;color:var(--muted)}
.rename{display:flex;gap:10px;align-items:center}.rename input{flex:1;padding:8px 10px}.toggle{display:flex;align-items:center;gap:10px;font-size:14px;color:var(--ink)}.toggle input{width:16px;height:16px;padding:0}
.theme-toggle{position:fixed;top:16px;right:16px;display:inline-flex;align-items:center;justify-content:center;width:46px;height:32px;padding:0;border:1px solid var(--border-strong);border-radius:8px;background:var(--paper);cursor:pointer}.theme-track{position:relative;width:28px;height:16px;border-radius:999px;background:var(--track)}.theme-dot{position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:var(--accent);transition:transform .25s}.theme-toggle[aria-pressed=true] .theme-dot{transform:translateX(12px)}
@media(prefers-reduced-motion:reduce){.theme-dot{transition:none}}`;

const escape = (value: string) => value.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const when = new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/Rome' });
const day = new Intl.DateTimeFormat('it-IT', { dateStyle: 'medium', timeZone: 'Europe/Rome' });

let hashes: Promise<{ script: string; theme: string; style: string }> | null = null;
/** Hash CSP delle tre risorse inline, calcolati una volta per isolate. */
export const pageHashes = () => hashes ??= Promise.all([cspHash(authScript), cspHash(themeScript), cspHash(pageCss)]).then(([script, theme, style]) => ({ script, theme, style }));
export async function pageCsp(): Promise<string> {
  const h = await pageHashes();
  return `default-src 'none'; script-src '${h.script}' '${h.theme}'; style-src '${h.style}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;
}

interface Shell { config: AuthConfig; title: string; page: 'login' | 'activate' | 'account'; body: string; attributes?: string; wide?: boolean; }
function shell({ config, title, page, body, attributes = '', wide = false }: Shell): string {
  return `<!doctype html>
<html lang="it">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="#f6f4ef"><title>${escape(title)} · ${escape(config.name)}</title><style>${pageCss}</style><script>${themeScript}</script></head>
<body data-page="${page}"${attributes}>
<button class="theme-toggle" type="button" data-theme-toggle aria-pressed="false" aria-label="Attiva tema scuro" title="Cambia tema"><span class="theme-track" aria-hidden="true"><span class="theme-dot"></span></span></button>
<main class="card${wide ? ' wide' : ''}">
<p class="eyebrow">${escape(config.name)}</p>
${body}
</main>
<script>${authScript}</script>
</body>
</html>`;
}

export function loginPage(config: AuthConfig, passkeys: boolean, codeMinutes: number, local: boolean): string {
  const body = `<h1>Accedi</h1>
<div id="passkey-block" class="stack" hidden>
  <button class="button primary" type="button" id="passkey">Accedi con passkey</button>
  <p class="hint">Touch ID, Face ID o Windows Hello.</p>
  <p class="divider"><span>oppure</span></p>
</div>
<form id="code-request">
  <label for="email">Email</label>
  <input type="email" name="email" id="email" required maxlength="254" autocomplete="username webauthn" autocapitalize="none" spellcheck="false">
  <button class="button" type="submit">Ricevi un codice via email</button>
</form>
<form id="code-verify" hidden>
  <p class="hint">Se l’indirizzo <strong id="code-email"></strong> è abilitato, riceverai un codice di 6 cifre. Scade tra ${codeMinutes} minuti.</p>
  <label for="code">Codice</label>
  <input id="code" name="code" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6">
  <button class="button primary" type="submit">Accedi</button>
  <button class="text-button" type="button" id="code-back">Usa un altro indirizzo</button>
</form>
<p id="auth-error" role="alert"></p>
<p class="foot">${escape(local ? (passkeys ? 'Ambiente locale' : 'Ambiente locale · passkey disponibili su localhost') : config.footer ?? 'Accesso riservato.')}</p>`;
  return shell({ config, title: 'Accesso', page: 'login', body, attributes: ` data-passkeys="${passkeys}"` });
}

export function activatePage(config: AuthConfig, passkeys: boolean): string {
  const body = `<h1>Attiva la passkey</h1>
<p>La passkey resta sul tuo dispositivo, protetta da Touch ID, Face ID, Windows Hello o dal PIN. Con iCloud Keychain o Google Password Manager arriva anche sugli altri tuoi dispositivi.</p>
<div class="stack"><button class="button primary" type="button" id="activate"${passkeys ? '' : ' disabled'}>Crea la passkey</button></div>
<p id="auth-error" role="alert">${passkeys ? '' : 'Passkey non disponibili su questo indirizzo. In locale usa localhost.'}</p>
<p class="foot">Il link vale una sola volta e scade dopo 15 minuti.</p>`;
  return shell({ config, title: 'Attiva la passkey', page: 'activate', body });
}

const methods = { passkey: 'passkey', code: 'codice via email' } as const;
const eventLabels: Record<string, string> = { login: 'Accesso', passkey_added: 'Passkey aggiunta', passkey_removed: 'Passkey rimossa', sessions_ended: 'Uscita da tutti i dispositivi', passkey_only_on: 'Solo passkey attivato', passkey_only_off: 'Solo passkey disattivato', access_granted: 'Accesso concesso', access_revoked: 'Accesso revocato' };
export interface AccountView { account: Account; passkeys: PasskeyRow[]; sessions: SessionRow[]; events: AuthEvent[]; available: boolean; prompt: boolean; }
export function accountPage(config: AuthConfig, view: AccountView): string {
  const home = config.home ?? '/';
  const { account, passkeys, sessions, events, available, prompt } = view;
  const body = prompt ? `<h1>Accedi più in fretta la prossima volta</h1>
<p>Crea una passkey su questo dispositivo. Al prossimo accesso basteranno Touch ID, Face ID o Windows Hello, senza codice.</p>
<div class="stack"><button class="button primary" type="button" data-add-passkey${available ? '' : ' disabled'}>Crea una passkey</button><a class="text-button" href="${escape(home)}">Più tardi</a></div>
<p id="auth-error" role="alert"></p>` : `<h1>Il tuo account</h1>
<p class="email">${escape(account.email)}</p>
<h2>Passkey</h2>
${passkeys.length ? `<ul class="list">${passkeys.map(p => `<li>
  <form data-rename="${escape(p.id)}" class="rename"><input name="name" value="${escape(p.name)}" maxlength="60" required aria-label="Nome della passkey"><button class="text-button" type="submit">Rinomina</button></form>
  <span>Creata il ${day.format(new Date(p.created_at))}${p.last_used_at ? ` · ultimo uso ${when.format(new Date(p.last_used_at))}` : ''}${p.backed_up ? ' · sincronizzata' : ''}</span>
  <button class="text-button danger" type="button" data-remove="${escape(p.id)}">Rimuovi</button>
</li>`).join('')}</ul>` : '<p>Nessuna passkey. Accedi con il codice via email.</p>'}
<button class="button" type="button" data-add-passkey${available ? '' : ' disabled'}>Aggiungi una passkey</button>
<h2>Accesso</h2>
<label class="toggle"><input type="checkbox" id="passkey-only"${account.passkeyOnly ? ' checked' : ''}${account.owner ? ' disabled' : ''}> Accedi solo con passkey</label>
<p class="hint">${account.owner ? 'Gli account owner accedono solo con passkey.' : 'Con l’opzione attiva il codice via email non vale più per questo account.'}</p>
<h2>Sessioni attive</h2>
<ul class="list">${sessions.map(s => `<li><strong>${s.current ? 'Questo dispositivo' : 'Altro dispositivo'}</strong><span>Accesso con ${methods[s.method]} · ultimo uso ${when.format(new Date(s.last_seen_at))} · scade il ${day.format(new Date(s.expires_at))}</span></li>`).join('')}</ul>
<div class="stack"><button class="button" type="button" id="end-sessions">Esci da tutti i dispositivi</button><form method="post" action="/auth/logout"><button class="button" type="submit">Esci da questo dispositivo</button></form></div>
<h2>Ultimi eventi</h2>
<ul class="list">${events.map(e => `<li><strong>${escape(eventLabels[e.event] ?? e.event)}</strong><span>${when.format(new Date(e.at))}${e.detail ? ` · ${escape(e.detail)}` : ''}</span></li>`).join('') || '<li><span>Nessun evento.</span></li>'}</ul>
<p id="auth-error" role="alert">${available ? '' : 'Passkey non disponibili su questo indirizzo. In locale usa localhost.'}</p>
<p class="foot"><a href="${escape(home)}">Torna all’app</a></p>`;
  return shell({ config, title: 'Account', page: 'account', body, attributes: prompt ? ` data-next="${escape(home)}"` : '', wide: !prompt });
}
