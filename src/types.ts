import type { D1Database } from '@cloudflare/workers-types';

/** Binding e variabili che il Worker passa alla libreria. Le altre variabili dell'app restano fuori. */
export interface AuthEnv {
  DB: D1Database;
  /** Dominio delle passkey, per esempio `salute.dariopagnoni.it`. Mai letto dall'header Host. */
  AUTH_RP_ID?: string;
  /** Origine completa, per esempio `https://salute.dariopagnoni.it`. */
  AUTH_ORIGIN?: string;
  /** Mittente dei codici, per esempio `Salute <accesso@dariopagnoni.it>`. */
  AUTH_FROM?: string;
  /** Segreto: chiave degli HMAC di codici e IP. */
  AUTH_SECRET?: string;
  /** Segreto: chiave Resend «sending access» sul dominio del mittente. */
  AUTH_RESEND_KEY?: string;
  /** Solo in locale: abilita http://localhost con il segreto locale. */
  LOCAL_AUTH_ENABLED?: string;
  LOCAL_AUTH_SECRET?: string;
}

export type Role = 'owner' | 'member' | 'viewer';
export type LoginMethod = 'passkey' | 'code';

/** Configurazione dell'app che usa la libreria. */
export interface AuthConfig {
  /** Identificativo dell'app nella tabella `members`, per esempio `salute`. */
  app: string;
  /** Nome mostrato nelle pagine e nelle passkey (rpName). */
  name: string;
  /** Prefisso dei cookie. Predefinito: `<app>_`. */
  cookiePrefix?: string;
  /** Pagina dopo l'accesso. Predefinito `/`. */
  home?: string;
  /** Percorso della pagina di login. Predefinito `/login`. */
  loginPath?: string;
  /** Percorso della pagina Account. Predefinito `/account`. */
  accountPath?: string;
  /** Riga in fondo alla pagina di login. */
  footer?: string;
  /** Durata delle sessioni in giorni per metodo. Predefinito 30 con passkey e 7 con codice. */
  sessionDays?: Partial<Record<LoginMethod, number>>;
  /** Minuti di inattività dopo i quali la sessione scade. Senza valore vale solo la durata assoluta. */
  idleMinutes?: number;
}

export interface Member { email: string; role: Role; name: string | null; }
export interface RelyingParty { id: string; origin: string; }
