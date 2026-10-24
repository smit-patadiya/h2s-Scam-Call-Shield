// Loads ../.env into process.env (Node 20.12+ built-in, no dependencies).
// Variables already set in the shell take precedence. A missing .env is fine.
import { fileURLToPath } from 'node:url';
import dns from 'node:dns';

// Fix Windows Node IPv6 resolution timeout for Google APIs
try { dns.setDefaultResultOrder('ipv4first'); } catch {}

try {
  process.loadEnvFile(fileURLToPath(new URL('../.env', import.meta.url)));
} catch (e) {
  if (e.code !== 'ENOENT') throw e;
}
