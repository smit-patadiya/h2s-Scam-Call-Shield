// Runs every test clip through the same pipeline as the browser (4 s chunks + transcript so far)
// and reports how many scams were caught and how many safe calls were wrongly flagged.
//
// Usage: node test/eval.mjs [--only=text] [--concurrency=1] [--full]
//   Requests per minute come from GEMINI_RPM in .env.
//   --only=text      only clips whose file name contains `text`
//   --concurrency=N  clips analysed in parallel (chunks inside one clip stay in order)
//   --full           keep analysing a scam clip after it is caught (default stops, like the app's single alert)
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { analyzeChunk, ANALYZE_MODEL } from '../lib/gemini.mjs';
import { TEST_DIR, decodeWav, encodeWav, readManifest } from './lib.mjs';

const CHUNK_SEC = 4;
const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')).map(([k, v]) => [k, v ?? true]));
const CONCURRENCY = Number(args.concurrency) || 1;

const DEMO = [
  { file: '../public/calls/gu-scam.wav', expected: 'scam', source: 'demo', note: 'Gujarati digital arrest' },
  { file: '../public/calls/hi-scam.wav', expected: 'scam', source: 'demo', note: 'Hindi digital arrest' },
  { file: '../public/calls/en-scam.wav', expected: 'scam', source: 'demo', note: 'English bank KYC / OTP' },
  { file: '../public/calls/en-genuine.wav', expected: 'safe', source: 'demo', note: 'Swiggy delivery' },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Rate limits (429) are handled by lib/gemini.mjs; this only retries network blips and bad JSON.
async function analyzeWithRetry(params, tries = 3) {
  for (let i = 1; ; i++) {
    try { return await analyzeChunk(params); } catch (e) {
      const transient = e.message === 'fetch failed' || e instanceof SyntaxError;
      if (!transient || i >= tries) throw e;
      await sleep(2000 * 2 ** (i - 1));
    }
  }
}

async function evalClip(entry) {
  const { samples, rate } = decodeWav(await readFile(new URL(entry.file, TEST_DIR)));
  const duration = samples.length / rate, per = CHUNK_SEC * rate;
  const res = { ...entry, duration: +duration.toFixed(1), chunks: [], verdict: 'safe', maxRisk: 0, flags: new Set(), firstScamAt: null, errors: 0, t0: Date.now() };
  let context = '';
  for (let i = 0; i * per < samples.length; i++) {
    const slice = samples.subarray(i * per, Math.min(samples.length, (i + 1) * per));
    if (slice.length < rate * 0.3) break; // ignore a tiny tail
    const end = +Math.min(duration, (i + 1) * CHUNK_SEC).toFixed(1);
    try {
      const r = await analyzeWithRetry({ audioB64: encodeWav(slice, rate).toString('base64'), context });
      if (r.transcript) context += ` ${r.transcript}`;
      (r.red_flags || []).forEach((f) => res.flags.add(f));
      res.maxRisk = Math.max(res.maxRisk, r.risk || 0);
      res.chunks.push({ end, verdict: r.verdict, risk: r.risk, flags: r.red_flags, transcript: r.transcript, reason: r.reason_en });
      if (r.verdict === 'scam' && res.firstScamAt === null) res.firstScamAt = end;
      if (r.verdict === 'suspicious' && res.verdict === 'safe') res.verdict = 'suspicious';
      if (r.verdict === 'scam') res.verdict = 'scam';
      if (res.verdict === 'scam' && entry.expected === 'scam' && !args.full) break;
    } catch (e) {
      res.errors++;
      res.chunks.push({ end, error: e.message.slice(0, 200) });
    }
  }
  res.pass = entry.expected === 'scam' ? res.verdict === 'scam' : res.verdict !== 'scam';
  res.seconds = +((Date.now() - res.t0) / 1000).toFixed(1);
  res.flags = [...res.flags];
  delete res.t0;
  const mark = res.pass ? 'PASS' : 'FAIL';
  console.log(`${mark}  ${entry.file.split('/').pop().padEnd(28)} expected ${entry.expected.padEnd(4)} got ${res.verdict.padEnd(10)} risk ${String(res.maxRisk).padStart(3)}${res.firstScamAt !== null ? `  caught at ${res.firstScamAt}s` : ''}${res.errors ? `  (${res.errors} errors)` : ''}`);
  return res;
}

const all = [...DEMO, ...(await readManifest())].filter((e) => !args.only || e.file.includes(args.only));
if (!all.length) { console.log('No clips found. Run test/fetch-fleurs.mjs and test/make-dialogues.mjs first.'); process.exit(1); }
console.log(`Model: ${ANALYZE_MODEL}   clips: ${all.length}   concurrency: ${CONCURRENCY}\n`);

const queue = [...all], results = [];
await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
  while (queue.length) {
    const entry = queue.shift();
    try { results.push(await evalClip(entry)); } catch (e) {
      console.log(`ERROR ${entry.file}: ${e.message}`);
      results.push({ ...entry, pass: false, verdict: 'error', error: e.message });
    }
  }
}));

// ---------- summary ----------
const scams = results.filter((r) => r.expected === 'scam'), safes = results.filter((r) => r.expected === 'safe');
const caught = scams.filter((r) => r.verdict === 'scam');
const falseAlarms = safes.filter((r) => r.verdict === 'scam');
const cautions = safes.filter((r) => r.verdict === 'suspicious');
const times = caught.map((r) => r.firstScamAt).filter((t) => t !== null);
console.log('\n================ SUMMARY ================');
console.log(`Scams caught:        ${caught.length}/${scams.length}`);
console.log(`False alarms (scam): ${falseAlarms.length}/${safes.length}`);
console.log(`Safe but 'caution':  ${cautions.length}/${safes.length}`);
if (times.length) console.log(`Time to catch:       avg ${(times.reduce((a, b) => a + b, 0) / times.length).toFixed(1)}s, max ${Math.max(...times)}s`);
for (const r of results.filter((r) => !r.pass)) console.log(`  FAIL ${r.file}: ${r.note}`);

await mkdir(new URL('results/', TEST_DIR), { recursive: true });
const out = new URL(`results/${new Date().toISOString().replace(/[:.]/g, '-')}.json`, TEST_DIR);
results.sort((a, b) => a.file.localeCompare(b.file));
await writeFile(out, JSON.stringify({ model: ANALYZE_MODEL, chunkSec: CHUNK_SEC, results }, null, 2));
console.log(`\nFull per-chunk details: test/results/${out.pathname.split('/').pop()}`);
process.exit(falseAlarms.length || caught.length < scams.length ? 1 : 0);
