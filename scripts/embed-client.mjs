import { readFileSync, writeFileSync } from 'node:fs';
// Incorpora client/auth.js in src/client-source.ts: il Worker lo serve inline con l'hash CSP senza regole di bundling.
const source = readFileSync(new URL('../client/auth.js', import.meta.url), 'utf8');
const escaped = source.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
writeFileSync(new URL('../src/client-source.ts', import.meta.url), `// Generato da scripts/embed-client.mjs a partire da client/auth.js. Non modificare a mano.\nexport const authScript = \`${escaped}\`;\n`);
console.log('src/client-source.ts aggiornato.');
