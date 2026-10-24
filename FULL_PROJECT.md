# Scam Call Shield: Full Project (single file)

Everything in one place: overview, plan, setup, demo script, and the complete source code.

---

# Part 1: README



Plays a call, sends it to Gemini in 4-second chunks, and warns the listener mid-call in Gujarati or Hindi. It names the red flags it heard (urgency, threats, OTP or money requests, police or bank claims). Optionally it prepares an alert for the user's emergency contact.

See [PLAN.md](PLAN.md) for the design.

## Run
Requires Node 20+ and a Gemini API key from [Google AI Studio](https://aistudio.google.com/). There are no npm dependencies.

```bash
## 1. Generate the four demo calls (3 scam, 1 genuine) with Gemini speech generation
GEMINI_API_KEY=your_key node scripts/generate-calls.mjs

## 2. Start the app, then open http://localhost:8080
GEMINI_API_KEY=your_key node server.mjs
```

PowerShell: `$env:GEMINI_API_KEY="your_key"; node server.mjs`

You can also put your own `.wav` files in `public/calls/` or use the upload box in the page. Real clips from [Google FLEURS](https://huggingface.co/datasets/google/fleurs) work too.

## Demo script
1. Pick **Gujarati "Digital arrest"** and press Play. Within about 8-12 seconds the banner turns red, the red-flag chips fill in, and a Gujarati voice warning plays while the call is still going.
2. Switch to Hindi in "Warn me in" and play the Hindi call.
3. Play **Swiggy delivery**. It must stay green with no warning.
4. Save an emergency contact. On the first scam verdict, a "Send on WhatsApp" button appears with "Your father may be on a scam call right now. Please call them."

## Configuration
| Env var | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | none | Required. Stays on the server. |
| `ANALYZE_MODEL` | `gemini-4-argon` | Audio understanding model |
| `TTS_MODEL` | `gemini-3.8-flash-tts` | Spoken warnings and demo calls |
| `TTS_FALLBACK_MODEL` | `gemini-2.5-pro-preview-tts` | Used if the first TTS request fails |
| `PORT` | `8080` | Server port |

## Notes
- No browser speech recognition is used. All speech understanding and speech output is Gemini.
- `/api/notify` only logs in this demo. For production, connect WhatsApp Business or Firebase Cloud Messaging there.
- The browser sends each chunk with the transcript so far, so the risk score reflects the whole call.
- Never share OTPs. In India, report cyber fraud on **1930** or cybercrime.gov.in.

---

# Part 2: Plan

## Scam Call Shield: Plan

## Goal
Play a scripted scam call. While the call is still running, the assistant flags it as a scam, names the red flags it heard, and explains in simple Gujarati or Hindi, spoken aloud and on screen. A genuine call must stay "safe".

## Google-only stack
| Need | Google tech |
|---|---|
| Understand call audio (Gujarati/Hindi/English) | Gemini audio understanding (`generateContent` with inline WAV, model `gemini-4-argon`, structured JSON output) |
| Spoken warning and demo recordings | Gemini speech generation (`gemini-3.8-flash-tts`, fallback `gemini-2.5-pro-preview-tts`) |
| Hosting (later) | Firebase Hosting or Cloud Run |

No Web Speech API anywhere.

## Architecture
```
Browser (public/)                         Node server (server.mjs)          Gemini
 <audio> plays call  ──timeupdate──►  slice 5s chunk, resample 16 kHz WAV
 POST /api/analyze {chunk, transcript so far} ───────────────►  analyzeChunk() ──► JSON verdict
 UI: transcript, risk meter, red-flag chips, warning banner  ◄── {flags, risk, verdict, warning_gu/hi}
 verdict == scam (first time) ──► POST /api/tts ──► spoken Gujarati/Hindi warning
                              ──► POST /api/notify ──► emergency contact message
```
The API key stays on the server and is never sent to the browser.

## Key design decisions
1. **Chunked, mid-call warning.** The browser cuts the playing audio into 5 s chunks and sends each as soon as playback reaches its end. Each request carries the transcript so far, so the model judges the whole call and the risk score rises as flags accumulate.
2. **Structured output.** One JSON schema per chunk: `transcript`, `red_flags[]` (urgency, threat, otp_request, money_request, authority_claim, isolation, remote_access, personal_info_request), `evidence[]` (quotes), `risk` 0-100, `verdict` safe/suspicious/scam, `warning_gu`, `warning_hi`.
3. **Does not cry wolf.** The prompt says to flag only what is actually said. The Swiggy delivery call is a built-in negative test and must end as "safe" with no warning.
4. **Elder-friendly UI.** Large text, a red full-width banner, a Gujarati/Hindi toggle, and the warning read aloud.
5. **Emergency contact (optional).** The user saves a name, relation and phone number (kept in the browser only). On the first "scam" verdict the app builds "Your {relation} may be on a scam call right now. Please call them." and offers a one-tap WhatsApp link, plus a `/api/notify` hook (logged in the demo; swap in WhatsApp Business or Firebase Cloud Messaging for production).

## Files
- `lib/gemini.mjs`: Gemini REST helpers (analysis and TTS). Written.
- `server.mjs`: static files plus `/api/config`, `/api/analyze`, `/api/tts`, `/api/notify`. Written.
- `scripts/generate-calls.mjs`: makes the four demo WAVs from the supplied scripts with Gemini TTS. Written.
- `public/index.html`, `public/app.js`, `public/style.css`: the UI. **Still to do.**
- `public/calls/*.wav`: `gu-scam`, `hi-scam`, `en-scam`, `en-genuine`. Generated by the script.
- `README.md`: setup and demo steps. **Still to do.**

## Open risks
- The TTS request shape and model IDs come from the docs as fetched. If one fails, the code falls back to the older `generateContent` TTS. Models are overridable with `ANALYZE_MODEL` and `TTS_MODEL`.
- I have no `GEMINI_API_KEY` in this environment, so I cannot generate the WAVs or call the model myself. You need to supply a key to run it end to end.
- Browsers may block autoplay. The Play button is a user click, so this should be fine.

## Remaining steps
1. Build the UI (`public/`).
2. Write `README.md`.
3. Syntax-check the server and run the UI in the browser pane (analysis calls will fail without a key).
4. With your key: `node scripts/generate-calls.mjs`, then `node server.mjs`, and test all four calls.

---

# Part 3: Source code

## `server.mjs`

````js
import http from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeChunk, speak, ANALYZE_MODEL } from './lib/gemini.mjs';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), 'public');
const PORT = process.env.PORT || 8080;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.wav': 'audio/wav', '.svg': 'image/svg+xml' };

const readJson = (req) => new Promise((res, rej) => {
  let b = ''; req.on('data', (d) => { b += d; if (b.length > 25e6) req.destroy(); });
  req.on('end', () => { try { res(JSON.parse(b || '{}')); } catch (e) { rej(e); } });
});
const send = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/api/config') {
      const calls = await readdir(join(ROOT, 'calls')).catch(() => []);
      return send(res, 200, { hasKey: !!process.env.GEMINI_API_KEY, model: ANALYZE_MODEL, calls: calls.filter((f) => f.endsWith('.wav')) });
    }
    if (req.method === 'POST' && req.url === '/api/analyze') {
      const { audio, context } = await readJson(req);
      return send(res, 200, await analyzeChunk({ audioB64: audio, context }));
    }
    if (req.method === 'POST' && req.url === '/api/tts') {
      const { text, voice } = await readJson(req);
      const wav = await speak(text, voice || 'Kore', 'Say slowly, calmly and reassuringly');
      return send(res, 200, { audio: wav.toString('base64') });
    }
    if (req.method === 'POST' && req.url === '/api/notify') {
      // Demo hook: swap this for WhatsApp Business / Firebase Cloud Messaging in production.
      const { to, message } = await readJson(req);
      console.log(`[notify] -> ${to}: ${message}`);
      return send(res, 200, { ok: true });
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
}).listen(PORT, () => console.log(`Scam Call Shield on http://localhost:${PORT}`));
````

## `lib/gemini.mjs`

````js
// Thin Gemini REST helpers (no SDK, no dependencies).
const BASE = 'https://generativelanguage.googleapis.com/v1beta';

export const ANALYZE_MODEL = process.env.ANALYZE_MODEL || 'gemini-4-argon';
export const TTS_MODEL = process.env.TTS_MODEL || 'gemini-3.8-flash-tts';
export const TTS_FALLBACK_MODEL = process.env.TTS_FALLBACK_MODEL || 'gemini-2.5-pro-preview-tts';

const key = () => {
  const k = process.env.GEMINI_API_KEY;
  if (!k) throw Object.assign(new Error('GEMINI_API_KEY is not set'), { status: 503 });
  return k;
};

async function post(path, body) {
  const r = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': key() },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw Object.assign(new Error(`Gemini ${r.status}: ${text.slice(0, 400)}`), { status: 502 });
  return JSON.parse(text);
}

// ---------- Audio understanding ----------
const FLAGS = ['urgency', 'threat', 'otp_request', 'money_request', 'authority_claim',
  'isolation', 'remote_access', 'personal_info_request'];

const SYSTEM = `You are "Scam Call Shield", a real-time guardian for elderly and first-time smartphone users in India.
You hear a SHORT CHUNK of a live phone call (Gujarati, Hindi, English or a mix). Earlier transcript is given as context.
Detect scam red flags: urgency ("do it now"), threats (arrest, blocking, legal action), OTP/PIN/CVV requests,
requests to transfer money, claims of being police/CBI/bank/KYC/courier/customs, "digital arrest" or "don't hang up"
(isolation), remote-access app requests, requests for Aadhaar/PAN/card details.
A normal call (e.g. a food delivery person asking which gate) is SAFE. Never cry wolf: only flag what is actually said.
verdict: "safe" (no red flags), "suspicious" (1-2 weak/partial signals), "scam" (authority claim or threat combined with
money/OTP request or isolation, or any clear OTP/money demand under pressure).
risk is 0-100 for the whole call so far. Only list red_flags actually heard in this chunk or earlier context.
evidence: short quotes (original language) for each flag. warning_gu / warning_hi: 1-2 very simple, calm sentences for an
elderly listener telling them what to do (hang up, never share OTP, call 1930), naming the red flags heard.
If verdict is "safe", warnings must be empty strings.`;

export async function analyzeChunk({ audioB64, mime = 'audio/wav', context = '' }) {
  const body = {
    systemInstruction: { parts: [{ text: SYSTEM }] },
    contents: [{
      role: 'user',
      parts: [
        { text: `Transcript so far (may be empty):\n${context || '(start of call)'}\n\nAnalyse the new audio chunk.` },
        { inlineData: { mimeType: mime, data: audioB64 } },
      ],
    }],
    generationConfig: {
      temperature: 0.1,
      responseMimeType: 'application/json',
      responseSchema: {
        type: 'OBJECT',
        properties: {
          transcript: { type: 'STRING', description: 'Verbatim transcript of this chunk in original script' },
          language: { type: 'STRING' },
          red_flags: { type: 'ARRAY', items: { type: 'STRING', enum: FLAGS } },
          evidence: { type: 'ARRAY', items: { type: 'STRING' } },
          risk: { type: 'INTEGER' },
          verdict: { type: 'STRING', enum: ['safe', 'suspicious', 'scam'] },
          reason_en: { type: 'STRING' },
          warning_gu: { type: 'STRING' },
          warning_hi: { type: 'STRING' },
        },
        required: ['transcript', 'red_flags', 'risk', 'verdict', 'reason_en', 'warning_gu', 'warning_hi'],
      },
    },
  };
  const res = await post(`/models/${ANALYZE_MODEL}:generateContent`, body);
  const text = res.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') || '{}';
  return JSON.parse(text);
}

// ---------- Speech generation ----------
export function pcmToWav(pcm, rate = 24000) {
  const h = Buffer.alloc(44);
  h.write('RIFF', 0); h.writeUInt32LE(36 + pcm.length, 4); h.write('WAVEfmt ', 8);
  h.writeUInt32LE(16, 16); h.writeUInt16LE(1, 20); h.writeUInt16LE(1, 22);
  h.writeUInt32LE(rate, 24); h.writeUInt32LE(rate * 2, 28); h.writeUInt16LE(2, 32); h.writeUInt16LE(16, 34);
  h.write('data', 36); h.writeUInt32LE(pcm.length, 40);
  return Buffer.concat([h, pcm]);
}

function findAudio(node) {
  if (!node || typeof node !== 'object') return null;
  if (typeof node.data === 'string' && node.data.length > 200) return node.data;
  for (const v of Object.values(node)) { const f = findAudio(v); if (f) return f; }
  return null;
}

/** Returns a WAV Buffer. Tries the Interactions API first, then classic generateContent TTS. */
export async function speak(text, voice = 'Kore', style = '') {
  const prompt = style ? `${style}: ${text}` : text;
  try {
    const res = await post('/interactions', {
      model: TTS_MODEL,
      input: [{ type: 'user_input', content: [{ type: 'text', text: prompt }] }],
      response_format: { type: 'audio' },
      generation_config: { speech_config: [{ voice }] },
    });
    const b64 = findAudio(res);
    if (b64) return Buffer.from(b64, 'base64');
  } catch (e) { if (e.status === 503) throw e; /* fall through */ }
  const res = await post(`/models/${TTS_FALLBACK_MODEL}:generateContent`, {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      responseModalities: ['AUDIO'],
      speechConfig: { voiceConfig: { prebuiltVoiceConfig: { voiceName: voice } } },
    },
  });
  const b64 = findAudio(res);
  if (!b64) throw new Error('No audio returned by TTS');
  const buf = Buffer.from(b64, 'base64');
  return buf.subarray(0, 4).toString() === 'RIFF' ? buf : pcmToWav(buf);
}
````

## `scripts/generate-calls.mjs`

````js
// Generates the demo call recordings with Gemini speech generation.
// Usage: GEMINI_API_KEY=... node scripts/generate-calls.mjs
import { writeFile, mkdir } from 'node:fs/promises';
import { speak } from '../lib/gemini.mjs';

const calls = [
  { file: 'gu-scam.wav', voice: 'Charon', style: 'Say in a stern, hurried, threatening tone, in Gujarati',
    text: 'નમસ્તે, હું મુંબઈ પોલીસ સાયબર સેલમાંથી બોલું છું. તમારા આધાર નંબર પર મોકલેલા પાર્સલમાં ડ્રગ્સ મળ્યા છે. તમે ડિજિટલ અરેસ્ટમાં છો, ફોન કાપશો નહીં. કેસ બંધ કરવા માટે અત્યારે જ ₹50,000 ટ્રાન્સફર કરો.' },
  { file: 'hi-scam.wav', voice: 'Orus', style: 'Say in a stern, hurried, threatening tone, in Hindi',
    text: 'नमस्ते, मैं मुंबई पुलिस साइबर सेल से बोल रहा हूँ। आपके आधार नंबर से भेजे गए पार्सल में ड्रग्स मिले हैं। आप डिजिटल अरेस्ट में हैं, कॉल मत काटिए। केस बंद करने के लिए अभी ₹50,000 ट्रांसफर कीजिए।' },
  { file: 'en-scam.wav', voice: 'Puck', style: 'Say in an urgent, officious tone, in Indian English',
    text: "Hello, this is your bank's KYC team. Your account will be blocked today because your KYC has expired. To keep it active, please share the OTP we just sent to your phone." },
  { file: 'en-genuine.wav', voice: 'Kore', style: 'Say in a friendly, casual tone, in Indian English',
    text: "Hi, this is the delivery partner from Swiggy. I'm outside your building with your order. Which gate should I come to?" },
];

await mkdir(new URL('../public/calls/', import.meta.url), { recursive: true });
for (const c of calls) {
  process.stdout.write(`Generating ${c.file} ... `);
  const wav = await speak(c.text, c.voice, c.style);
  await writeFile(new URL(`../public/calls/${c.file}`, import.meta.url), wav);
  console.log(`${(wav.length / 1024).toFixed(0)} KB`);
}
````

## `public/index.html`

````html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scam Call Shield</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header>
  <h1>🛡️ Scam Call Shield</h1>
  <p>સ્કેમ કોલ શિલ્ડ · स्कैम कॉल शील्ड — listens to the call and warns you while it is still going on</p>
</header>

<main>
  <section id="banner" class="banner idle" role="alert" aria-live="assertive">
    <div id="bannerTitle">Choose a call and press Play</div>
    <div id="bannerText"></div>
  </section>

  <div class="grid">
    <section class="card">
      <h2>1. The call</h2>
      <select id="callSelect"></select>
      <label class="upload">or upload a .wav <input type="file" id="upload" accept="audio/wav,audio/*"></label>
      <div class="row">
        <button id="play" class="primary">▶ Play call</button>
        <button id="stop">■ Stop</button>
      </div>
      <div class="row">
        <label>Warn me in
          <select id="lang"><option value="gu">ગુજરાતી</option><option value="hi">हिन्दी</option></select>
        </label>
        <label><input type="checkbox" id="speak" checked> Speak warning</label>
      </div>
      <div id="status" class="muted"></div>
    </section>

    <section class="card">
      <h2>2. What the assistant hears</h2>
      <div class="meter"><div id="risk"></div></div>
      <div class="muted">Scam risk: <b id="riskNum">0</b>%</div>
      <div id="flags" class="chips"></div>
      <div id="reason" class="reason"></div>
      <div id="transcript" class="transcript"></div>
    </section>

    <section class="card">
      <h2>3. Emergency contact (optional)</h2>
      <div class="form">
        <input id="cName" placeholder="Name, e.g. Rahul">
        <input id="cRel" placeholder="Relation, e.g. son / daughter">
        <input id="cPhone" placeholder="WhatsApp number with country code, e.g. 919876543210">
        <input id="myRel" placeholder="Their relation to you, e.g. father (I am the one on the call)">
      </div>
      <label><input type="checkbox" id="autoNotify" checked> Alert my contact when a scam is detected</label>
      <div id="notice" class="notice" hidden></div>
    </section>
  </div>
</main>
<script src="app.js"></script>
</body>
</html>
````

## `public/style.css`

````css
:root{--bg:#f6f7fb;--fg:#1c1f2a;--card:#fff;--mut:#667;--ok:#1b8a4b;--warn:#c77d00;--bad:#c62828;--br:#dde0ea}
@media (prefers-color-scheme:dark){:root{--bg:#12141b;--fg:#eceef5;--card:#1c2030;--mut:#9aa;--br:#2c3248}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:18px/1.5 system-ui,"Noto Sans Gujarati","Noto Sans Devanagari",sans-serif}
header{padding:20px 16px 4px;max-width:1100px;margin:auto}
h1{margin:0;font-size:28px}header p{margin:4px 0 0;color:var(--mut)}
main{max-width:1100px;margin:auto;padding:12px 16px 40px}
.banner{border-radius:14px;padding:18px 20px;margin-bottom:16px;color:#fff;transition:background .3s}
.banner.idle{background:#4a5170}.banner.safe{background:var(--ok)}.banner.suspicious{background:var(--warn)}
.banner.scam{background:var(--bad);animation:pulse 1s infinite}
#bannerTitle{font-size:26px;font-weight:700}#bannerText{font-size:22px;margin-top:6px}
@keyframes pulse{50%{box-shadow:0 0 0 10px rgba(198,40,40,.25)}}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}
.card{background:var(--card);border:1px solid var(--br);border-radius:14px;padding:16px}
h2{margin:0 0 10px;font-size:18px}
select,input:not([type=checkbox]):not([type=file]){width:100%;padding:10px;margin:4px 0;font:inherit;border:1px solid var(--br);border-radius:8px;background:var(--bg);color:var(--fg)}
.row{display:flex;gap:10px;margin:10px 0;align-items:center;flex-wrap:wrap}
.row label{flex:1;min-width:140px}
button{font:inherit;padding:10px 16px;border-radius:10px;border:1px solid var(--br);background:var(--card);color:var(--fg);cursor:pointer}
button.primary{background:#1a56db;color:#fff;border-color:#1a56db;font-weight:600}
button:disabled{opacity:.5;cursor:default}
.upload{display:block;font-size:14px;color:var(--mut);margin-top:6px}
.muted{color:var(--mut);font-size:14px}
.meter{height:16px;background:var(--br);border-radius:8px;overflow:hidden;margin:6px 0}
#risk{height:100%;width:0;background:var(--ok);transition:width .5s,background .5s}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
.chip{background:#fdeaea;color:var(--bad);border:1px solid #f3b7b7;border-radius:999px;padding:4px 12px;font-size:16px;font-weight:600}
@media (prefers-color-scheme:dark){.chip{background:#3a1d1f;border-color:#6b2c30;color:#ff8a8a}}
.reason{font-size:16px}
.transcript{margin-top:10px;font-size:16px;max-height:220px;overflow:auto;border-top:1px solid var(--br);padding-top:8px}
.transcript p{margin:4px 0}.transcript .t{color:var(--mut);font-size:12px}
.notice{margin-top:10px;padding:10px;border-radius:10px;background:#e8f1ff;color:#123}
@media (prefers-color-scheme:dark){.notice{background:#1b2a47;color:#dde}}
.notice a{display:inline-block;margin-top:6px;padding:8px 14px;background:#25d366;color:#000;border-radius:8px;text-decoration:none;font-weight:700}
@media (max-width:480px){#bannerTitle{font-size:22px}#bannerText{font-size:19px}}
````

## `public/app.js`

````js
const CHUNK_SEC = 4;      // warning can fire after the first few seconds
const RATE = 16000;       // Gemini downsamples audio to 16 kHz anyway
const $ = (id) => document.getElementById(id);

const FLAG_LABELS = {
  urgency:               { en: 'Urgency',          gu: 'ઉતાવળ',            hi: 'जल्दबाज़ी' },
  threat:                { en: 'Threats',          gu: 'ધમકી',             hi: 'धमकी' },
  otp_request:           { en: 'OTP / PIN asked',  gu: 'OTP/PIN માંગ્યો',   hi: 'OTP/PIN माँगा' },
  money_request:         { en: 'Money asked',      gu: 'પૈસા માંગ્યા',      hi: 'पैसे माँगे' },
  authority_claim:       { en: 'Police/bank claim', gu: 'પોલીસ/બેંકનો દાવો', hi: 'पुलिस/बैंक का दावा' },
  isolation:             { en: "Don't hang up",    gu: 'ફોન કાપવાની ના',    hi: 'फोन काटने से मना' },
  remote_access:         { en: 'Remote access',    gu: 'રિમોટ એપ',         hi: 'रिमोट ऐप' },
  personal_info_request: { en: 'Personal details', gu: 'અંગત માહિતી',      hi: 'निजी जानकारी' },
};
const CALL_LABELS = {
  'gu-scam.wav': '🇮🇳 Gujarati · "Digital arrest" police call (scam)',
  'hi-scam.wav': '🇮🇳 Hindi · "Digital arrest" police call (scam)',
  'en-scam.wav': 'English · Fake bank KYC / OTP call (scam)',
  'en-genuine.wav': 'English · Swiggy delivery call (genuine)',
};

let session = null;

// ---------- audio helpers ----------
function toWavB64(samples) {
  const buf = new ArrayBuffer(44 + samples.length * 2), v = new DataView(buf);
  const w = (o, s) => [...s].forEach((c, i) => v.setUint8(o + i, c.charCodeAt(0)));
  w(0, 'RIFF'); v.setUint32(4, 36 + samples.length * 2, true); w(8, 'WAVEfmt ');
  v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
  v.setUint32(24, RATE, true); v.setUint32(28, RATE * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
  w(36, 'data'); v.setUint32(40, samples.length * 2, true);
  samples.forEach((s, i) => v.setInt16(44 + i * 2, Math.max(-1, Math.min(1, s)) * 32767, true));
  let bin = ''; const u = new Uint8Array(buf);
  for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode(...u.subarray(i, i + 0x8000));
  return btoa(bin);
}

async function chunkToB64(decoded, startSec, endSec) {
  const sr = decoded.sampleRate;
  const a = Math.floor(startSec * sr), b = Math.min(decoded.length, Math.floor(endSec * sr));
  const ch = decoded.getChannelData(0).subarray(a, b);
  const ctx = new OfflineAudioContext(1, Math.max(1, Math.ceil((b - a) * RATE / sr)), RATE);
  const buf = ctx.createBuffer(1, ch.length, sr); buf.copyToChannel(ch, 0);
  const src = ctx.createBufferSource(); src.buffer = buf; src.connect(ctx.destination); src.start();
  return toWavB64((await ctx.startRendering()).getChannelData(0));
}

async function api(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

// ---------- UI ----------
function setBanner(kind, title, text = '') {
  $('banner').className = `banner ${kind}`;
  $('bannerTitle').textContent = title;
  $('bannerText').textContent = text;
}
function reset() {
  setBanner('idle', 'Choose a call and press Play');
  $('risk').style.width = '0'; $('riskNum').textContent = '0';
  $('flags').replaceChildren(); $('reason').textContent = ''; $('transcript').replaceChildren();
  $('notice').hidden = true; $('status').textContent = '';
}
function renderFlags(set) {
  const lang = $('lang').value;
  $('flags').replaceChildren(...[...set].map((f) => {
    const s = document.createElement('span'); s.className = 'chip';
    const l = FLAG_LABELS[f] || { en: f };
    s.textContent = `${l[lang] || l.en} · ${l.en}`; return s;
  }));
}

async function speakWarning(text) {
  if (!$('speak').checked || !text) return;
  try {
    const { audio } = await api('/api/tts', { text });
    new Audio(`data:audio/wav;base64,${audio}`).play();
  } catch (e) { $('status').textContent = `Voice warning unavailable: ${e.message}`; }
}

function notifyContact() {
  const name = $('cName').value.trim(), rel = $('myRel').value.trim() || 'family member';
  const phone = $('cPhone').value.replace(/\D/g, '');
  if (!$('autoNotify').checked || !phone) return;
  const msg = `Your ${rel} may be on a scam call right now. Please call them.`;
  api('/api/notify', { to: phone, message: msg }).catch(() => {});
  const n = $('notice'); n.hidden = false; n.replaceChildren();
  const p = document.createElement('div'); p.textContent = `Alert for ${name || 'your contact'}: “${msg}”`;
  const a = document.createElement('a'); a.target = '_blank'; a.rel = 'noopener';
  a.href = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`; a.textContent = 'Send on WhatsApp';
  n.append(p, a);
}

function handleResult(s, r, idx) {
  const lang = $('lang').value;
  if (r.transcript) {
    const p = document.createElement('p'); p.innerHTML = `<span class="t">${idx * CHUNK_SEC}s </span>`;
    p.append(document.createTextNode(r.transcript)); $('transcript').append(p);
    $('transcript').scrollTop = 1e9; s.context += ` ${r.transcript}`;
  }
  (r.red_flags || []).forEach((f) => s.flags.add(f)); renderFlags(s.flags);
  s.risk = Math.max(r.verdict === 'safe' ? 0 : s.risk, r.risk || 0);
  $('risk').style.width = `${s.risk}%`; $('riskNum').textContent = s.risk;
  $('risk').style.background = s.risk > 70 ? 'var(--bad)' : s.risk > 35 ? 'var(--warn)' : 'var(--ok)';
  $('reason').textContent = r.reason_en || '';
  const warn = lang === 'gu' ? r.warning_gu : r.warning_hi;
  if (r.verdict === 'scam') {
    setBanner('scam', lang === 'gu' ? '🚨 સ્કેમ કોલ! ફોન કાપી નાખો' : '🚨 स्कैम कॉल! फोन काट दीजिए', warn);
    if (!s.alerted) { s.alerted = true; speakWarning(warn); notifyContact(); }
  } else if (r.verdict === 'suspicious' && !s.alerted) {
    setBanner('suspicious', lang === 'gu' ? '⚠️ સાવચેત રહો' : '⚠️ सावधान रहें', warn);
  } else if (!s.alerted && s.risk < 20) {
    setBanner('safe', '✅ Looks like a normal call', 'No scam red flags heard so far.');
  }
}

// ---------- session ----------
async function start() {
  stop(); reset();
  const file = $('upload').files[0];
  let blob;
  try {
    blob = file || await (await fetch(`/calls/${$('callSelect').value}`)).blob();
  } catch { return ($('status').textContent = 'Could not load call'); }
  const decoded = await new AudioContext().decodeAudioData(await blob.arrayBuffer());
  const audio = new Audio(URL.createObjectURL(blob));
  const s = session = { audio, flags: new Set(), risk: 0, context: '', alerted: false, next: 0, queue: Promise.resolve(), timer: null };
  const total = Math.ceil(decoded.duration / CHUNK_SEC);
  setBanner('idle', 'Listening…', 'Analysing the call every few seconds');

  const dispatch = (i) => {
    const t0 = i * CHUNK_SEC, t1 = Math.min(decoded.duration, t0 + CHUNK_SEC);
    s.queue = s.queue.then(async () => {
      if (session !== s) return;
      $('status').textContent = `Analysing ${t0.toFixed(0)}–${t1.toFixed(0)}s…`;
      try {
        const r = await api('/api/analyze', { audio: await chunkToB64(decoded, t0, t1), context: s.context });
        if (session === s) handleResult(s, r, i);
      } catch (e) { $('status').textContent = `Analysis failed: ${e.message}`; }
      if (session === s && i === total - 1) $('status').textContent += ' Call ended.';
    });
  };
  s.timer = setInterval(() => {
    while (s.next < total && (audio.ended || audio.currentTime >= Math.min((s.next + 1) * CHUNK_SEC, decoded.duration - 0.05))) dispatch(s.next++);
    if (s.next >= total) clearInterval(s.timer);
  }, 200);
  audio.play();
}
function stop() {
  if (!session) return;
  clearInterval(session.timer); session.audio.pause(); session = null;
}

// ---------- init ----------
['cName', 'cRel', 'cPhone', 'myRel', 'lang'].forEach((id) => {
  try { const v = localStorage.getItem(`scs_${id}`); if (v) $(id).value = v; } catch {}
  $(id).addEventListener('change', () => { try { localStorage.setItem(`scs_${id}`, $(id).value); } catch {} });
});
$('play').onclick = start; $('stop').onclick = () => { stop(); reset(); };
$('upload').onchange = () => { $('callSelect').disabled = !!$('upload').files[0]; };

fetch('/api/config').then((r) => r.json()).then((c) => {
  const order = ['gu-scam.wav', 'hi-scam.wav', 'en-scam.wav', 'en-genuine.wav'];
  const files = [...new Set([...order.filter((f) => c.calls.includes(f)), ...c.calls])];
  $('callSelect').replaceChildren(...files.map((f) => new Option(CALL_LABELS[f] || f, f)));
  if (!files.length) $('status').textContent = 'No calls found: run  node scripts/generate-calls.mjs  or upload a .wav';
  if (!c.hasKey) setBanner('suspicious', 'GEMINI_API_KEY is not set', 'Set it and restart the server to enable analysis.');
});
````
