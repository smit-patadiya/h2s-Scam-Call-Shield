// Thin Gemini REST helpers (no SDK, no dependencies).
import './env.mjs';
const BASE = 'https://generativelanguage.googleapis.com/v1beta';

export const ANALYZE_MODEL = process.env.ANALYZE_MODEL || 'gemini-2.5-flash';
export const TTS_MODEL = process.env.TTS_MODEL || 'gemini-3.8-flash-tts';
export const TTS_FALLBACK_MODEL = process.env.TTS_FALLBACK_MODEL || 'gemini-2.5-pro-preview-tts';

const key = () => {
  const k = process.env.GEMINI_API_KEY;
  if (!k) throw Object.assign(new Error('GEMINI_API_KEY is not set'), { status: 503 });
  return k;
};

// ---------- Rate limiting ----------
// Free-tier limits are per model, so each model gets its own queue.
// GEMINI_RPM caps analysis models, GEMINI_TTS_RPM caps *-tts models (0 = no cap). Read at call time.
const nextSlot = new Map();
async function throttle(model) {
  const rpm = Number(/tts/i.test(model) ? process.env.GEMINI_TTS_RPM : process.env.GEMINI_RPM) || 0;
  if (!rpm) return;
  const now = Date.now(), at = Math.max(now, nextSlot.get(model) || 0);
  nextSlot.set(model, at + 60000 / rpm);
  if (at > now) await new Promise((r) => setTimeout(r, at - now));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function post(path, body, tries = 4) {
  const model = body.model || path.match(/models\/([^:]+)/)?.[1] || 'default';
  for (let i = 1; ; i++) {
    await throttle(model);
    const r = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': key() },
      body: JSON.stringify(body),
    });
    const text = await r.text();
    if (r.ok) return JSON.parse(text);
    if (r.status === 429) {
      const delay = Number(text.match(/"retryDelay":\s*"(\d+(?:\.\d+)?)s"/)?.[1]);
      // A long wait means the daily quota is used up; retrying now will not help.
      if (delay > 90) throw Object.assign(new Error(`Gemini 429: quota used up, resets in about ${(delay / 3600).toFixed(1)} h. Enable billing or use another model.`), { status: 429 });
      if (i < tries) {
        const wait = (delay ? delay * 1000 : 5000 * i) + 500;
        console.warn(`[gemini] 429 rate limit, waiting ${(wait / 1000).toFixed(0)}s (try ${i}/${tries - 1})`);
        await sleep(wait);
        continue;
      }
    }
    if (r.status >= 500 && i < tries) { await sleep(2000 * i); continue; }
    throw Object.assign(new Error(`Gemini ${r.status}: ${text.slice(0, 400)}`), { status: r.status === 429 ? 429 : 502 });
  }
}

// ---------- Audio understanding ----------
const FLAGS = [
  'urgency', 'threat', 'otp_request', 'money_request', 'authority_claim',
  'isolation', 'remote_access', 'personal_info_request',
  'emotional_manipulation', 'family_info_probing'
];

const SYSTEM = `You are "Scam Call Shield", a real-time guardian for elderly and first-time smartphone users in India.
You hear a live phone call (Gujarati, Hindi, Indian English or code-mixed). Earlier transcript is given as context.

### DETECTION & SOCIAL ENGINEERING TAXONOMY:
Detect 10 critical fraud indicators:
1. 'authority_claim': claiming to be Police, CBI, Customs, RBI, Bank manager, courier KYC.
2. 'threat': arrest, parcel seizure, bank account freeze, legal action.
3. 'isolation': "don't hang up", "digital arrest", stay in a room alone.
4. 'urgency': "do it now", "within 10 minutes", "before 5 PM".
5. 'otp_request': asking for OTP, PIN, CVV, password.
6. 'money_request': asking to transfer money, security deposit, penalty fee.
7. 'remote_access': asking to install AnyDesk, TeamViewer, RustDesk.
8. 'personal_info_request': asking for ID cards (Aadhaar, PAN card), date of birth, ATM card details.
9. 'emotional_manipulation': feigning medical emergency, accident of relative, gaining fake trust/sympathy.
10. 'family_info_probing': asking for parents' phone numbers, relatives' names, where family members work.

### CRITICAL CONTEXT & FUNNEL RULES:
- Scammers often do NOT attack in the first 10-20 seconds. They start with polite greetings, inquiry about well-being, or basic verification ("Are you Mr. Ramesh?").
- If earlier context established an authority claim, emergency pretext, or identity probing, any subsequent request in this chunk (such as "install AnyDesk", "open WhatsApp", "tell me the OTP", or "enter your PIN") is a CRITICAL SCAM EXPLOIT, even if spoken calmly.
- If a caller probes for family numbers, ID cards (Aadhaar, PAN), or creates emotional distress, flag it immediately.
- Normal calls (food delivery, cab driver, genuine friend) are SAFE.
- verdict:
  * "safe": No scam red flags heard (risk 0-25).
  * "suspicious": 1 mild signal without financial/threat demand (risk 26-65).
  * "scam": Authority claim/threat combined with money/OTP/isolation demand or aggressive ID harvesting (risk 70-100).
- If verdict is "safe", warning_gu and warning_hi MUST be empty strings.

### FEW-SHOT TRAINING EXAMPLES:

Example 1 (Gujarati Digital Arrest Scam):
Chunk: "નમસ્તે, હું મુંબઈ પોલીસમાંથી બોલું છું. તમારા પાર્સલમાં ડ્રગ્સ મળ્યા છે. તમે ડિજિટલ અરેસ્ટમાં છો, ફોન કાપશો નહીં. કેસ બંધ કરવા ₹50,000 ટ્રાન્સફર કરો."
Output JSON:
{
  "transcript": "નમસ્તે, હું મુંબઈ પોલીસમાંથી બોલું છું. તમારા પાર્સલમાં ડ્રગ્સ મળ્યા છે. તમે ડિજિટલ અરેસ્ટમાં છો, ફોન કાપશો નહીં. કેસ બંધ કરવા ₹50,000 ટ્રાન્સફર કરો.",
  "language": "Gujarati",
  "red_flags": ["authority_claim", "threat", "isolation", "money_request", "urgency"],
  "evidence": ["મુંબઈ પોલીસમાંથી બોલું છું", "પાર્સલમાં ડ્રગ્સ મળ્યા છે", "ડિજિટલ અરેસ્ટમાં છો", "ફોન કાપશો નહીં", "₹50,000 ટ્રાન્સફર કરો"],
  "risk": 95,
  "verdict": "scam",
  "reason_en": "Classic digital arrest scam: fake police officer claiming illicit parcel and demanding immediate money transfer under duress.",
  "warning_gu": "આ નકલી પોલીસ કોલ છે! પોલીસ ક્યારેય ફોન પર ધરપકડ કે પૈસાની માંગણી કરતી નથી. તરત ફોન કાપી 1930 પર ફરિયાદ કરો.",
  "warning_hi": "यह फर्जी पुलिस कॉल है! पुलिस कभी फोन पर गिरफ्तारी या पैसे की मांग नहीं करती। तुरंत फोन काटें और 1930 पर शिकायत करें."
}

Example 2 (Hindi Fake Bank KYC / OTP Scam):
Chunk: "नमस्ते, मैं आपके बैंक के मुख्य शाखा से बोल रहा हूँ। आपका बैंक खाता आज ब्लॉक हो जाएगा। इसे चालू रखने के लिए आपके फोन पर आया 6 अंकों का ओटीपी बताइए।"
Output JSON:
{
  "transcript": "नमस्ते, मैं आपके बैंक के मुख्य शाखा से बोल रहा हूँ। आपका बैंक खाता आज ब्लॉक हो जाएगा। इसे चालू रखने के लिए आपके फोन पर आया 6 अंकों का ओटीपी बताइए।",
  "language": "Hindi",
  "red_flags": ["authority_claim", "threat", "urgency", "otp_request"],
  "evidence": ["बैंक के मुख्य शाखा से बोल रहा हूँ", "खाता आज ब्लॉक हो जाएगा", "ओटीपी बताइए"],
  "risk": 92,
  "verdict": "scam",
  "reason_en": "Fake bank manager threatening account blockage to extort one-time password (OTP).",
  "warning_gu": "આ નકલી બેંક કોલ છે! બેંક ક્યારેય OTP માંગતી નથી. કોઈને પણ OTP આપશો નહીં અને તરત ફોન કાપી નાખો.",
  "warning_hi": "यह फर्जी बैंक कॉल है! बैंक कभी भी आपसे ओटीपी नहीं मांगता। किसी को भी ओटीपी न दें और तुरंत फोन काट दें."
}

Example 3 (Safe Delivery Call - Negative Example):
Chunk: "Hello bhaiya, Swiggy delivery boy bol raha hu. Mai aapki society ke bahar khada hu, kaun se gate pe aana hai?"
Output JSON:
{
  "transcript": "Hello bhaiya, Swiggy delivery boy bol raha hu. Mai aapki society ke bahar khada hu, kaun se gate pe aana hai?",
  "language": "Hindi/English",
  "red_flags": [],
  "evidence": [],
  "risk": 0,
  "verdict": "safe",
  "reason_en": "Routine food delivery navigation call. No financial, personal, or threat requests.",
  "warning_gu": "",
  "warning_hi": ""
}`;

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
      maxOutputTokens: 1000,
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
  const rawText = res.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') || '{}';
  
  // Safe JSON extraction
  let cleanText = rawText.trim();
  const match = cleanText.match(/```(?:json)?\s*([\s\S]*?)\s*```/) || cleanText.match(/(\{[\s\S]*\})/);
  if (match) cleanText = match[1].trim();
  
  try {
    return JSON.parse(cleanText);
  } catch (err) {
    const s = cleanText.indexOf('{'), e = cleanText.lastIndexOf('}');
    if (s !== -1 && e > s) {
      try { return JSON.parse(cleanText.slice(s, e + 1)); } catch {}
    }
    console.error('Failed to parse Gemini JSON output:', rawText);
    throw Object.assign(new Error(`Model output parsing error: ${err.message}`), { status: 502 });
  }
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

/**
 * Two-voice speech for a dialogue. turns = [{ speaker: 'Caller'|'Receiver', text }].
 * Returns a WAV Buffer.
 */
export async function speakDialogue(turns, voices = { Caller: 'Charon', Receiver: 'Kore' }, style = '') {
  const script = turns.map((t) => `${t.speaker}: ${t.text}`).join('\n');
  const prompt = `${style || 'Read this phone call naturally, like a real conversation'}:\n${script}`;
  const body = {
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      responseModalities: ['AUDIO'],
      speechConfig: {
        multiSpeakerVoiceConfig: {
          speakerVoiceConfigs: Object.entries(voices).map(([speaker, voiceName]) => ({
            speaker, voiceConfig: { prebuiltVoiceConfig: { voiceName } },
          })),
        },
      },
    },
  };
  let lastErr;
  for (const model of [TTS_MODEL, TTS_FALLBACK_MODEL]) {
    try {
      const b64 = findAudio(await post(`/models/${model}:generateContent`, body));
      if (!b64) throw new Error(`No audio returned by ${model}`);
      const buf = Buffer.from(b64, 'base64');
      return buf.subarray(0, 4).toString() === 'RIFF' ? buf : pcmToWav(buf);
    } catch (e) { if (e.status === 503) throw e; lastErr = e; }
  }
  throw lastErr;
}
