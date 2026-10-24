import http from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeChunk, speak, ANALYZE_MODEL } from './lib/gemini.mjs';
import { checkNumber, recordScamNumber, getAllScamNumbers } from './lib/scam-db.mjs';
import { evaluateMultiAgent } from './lib/scam-detector-engine.mjs';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'public');
const PORT = process.env.PORT || 8080;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.wav': 'audio/wav', '.svg': 'image/svg+xml' };

const readJson = (req) => {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  if (typeof req.body === 'string') {
    try { return Promise.resolve(JSON.parse(req.body)); } catch (e) { return Promise.reject(e); }
  }
  return new Promise((res, rej) => {
    let b = ''; req.on('data', (d) => { b += d; if (b.length > 25e6) req.destroy(); });
    req.on('end', () => { try { res(JSON.parse(b || '{}')); } catch (e) { rej(e); } });
  });
};
const send = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

export default async function handler(req, res) {
  try {
    if (req.method === 'GET' && (req.url === '/api/config' || req.url?.endsWith('/config'))) {
      const calls = await readdir(join(ROOT, 'calls')).catch(() => []);
      return send(res, 200, { hasKey: !!process.env.GEMINI_API_KEY, model: ANALYZE_MODEL, calls: calls.filter((f) => f.endsWith('.wav')) });
    }
    if (req.method === 'POST' && req.url === '/api/analyze') {
      const { audio, context, mime, callName, clientTranscript } = await readJson(req);
      const result = await evaluateMultiAgent({
        audioB64: audio,
        context,
        mime: mime || 'audio/wav',
        callName,
        clientTranscript,
        analyzeChunkFn: analyzeChunk
      });
      return send(res, 200, result);
    }
    if (req.method === 'POST' && req.url === '/api/tts') {
      const { text, voice } = await readJson(req);
      const wav = await speak(text, voice || 'Kore', 'Say slowly, calmly and reassuringly');
      return send(res, 200, { audio: wav.toString('base64') });
    }
    if (req.method === 'POST' && req.url === '/api/notify') {
      const { to, message } = await readJson(req);
      console.log(`[notify] -> ${to}: ${message}`);
      return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && req.url === '/api/check-number') {
      const { phone } = await readJson(req);
      const result = await checkNumber(phone);
      return send(res, 200, result);
    }
    if (req.method === 'POST' && req.url === '/api/record-scam') {
      const { phone, flags, risk, reason, category } = await readJson(req);
      const record = await recordScamNumber({ phone, flags, risk, notes: reason, category });
      return send(res, 200, { ok: true, record });
    }
    if (req.method === 'GET' && req.url === '/api/scam-numbers') {
      const numbers = await getAllScamNumbers();
      return send(res, 200, { numbers });
    }
    const path = normalize(req.url.split('?')[0]).replace(/^(\.\.[/\\])+/, '');
    const file = join(ROOT, path === '/' || path === '\\' ? 'index.html' : path);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    const data = await readFile(file);
    res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' });
    res.end(data);
  } catch (e) {
    if (e.code === 'ENOENT') { res.writeHead(404); return res.end('Not found'); }
    console.error(e.message);
    send(res, e.status || 500, { error: e.message });
  }
}

const isMain = process.argv[1] && (
  fileURLToPath(import.meta.url) === process.argv[1] ||
  process.argv[1].endsWith('server.mjs')
);

if (isMain) {
  http.createServer(handler).listen(PORT, () => console.log(`Scam Call Shield on http://localhost:${PORT}`));
}

