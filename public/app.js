const CHUNK_SEC = 4;
const RATE = 16000;
const $ = (id) => document.getElementById(id);
const setText = (id, val) => { const el = $(id); if (el) el.textContent = val; };
const setHtml = (id, val) => { const el = $(id); if (el) el.innerHTML = val; };

const FLAG_LABELS = {
  urgency:               { en: 'Urgency',          gu: 'ઉતાવળ',            hi: 'जल्दबाज़ी' },
  threat:                { en: 'Threats',          gu: 'ધમકી',             hi: 'धमकी' },
  otp_request:           { en: 'OTP / PIN asked',  gu: 'OTP/PIN માંગ્યો',   hi: 'OTP/PIN माँगा' },
  money_request:         { en: 'Money asked',      gu: 'પૈસા માંગ્યા',      hi: 'पैसे माँगे' },
  authority_claim:       { en: 'Police/bank claim', gu: 'પોલીસ/બેંકનો દાવો', hi: 'पुलिस/बैंक का दावा' },
  isolation:             { en: "Don't hang up",    gu: 'ફોન કાપવાની ના',    hi: 'फोन काटने से मना' },
  remote_access:         { en: 'Remote access',    gu: 'રિમોટ એપ',         hi: 'रिमोट ऐप' },
  personal_info_request: { en: 'ID / Personal Info',  gu: 'આધાર/અંગત માહિતી',    hi: 'आईडी/निजी जानकारी' },
  emotional_manipulation:{ en: 'Emotional Trap',      gu: 'લાગણીથી છેતરપિંડી',   hi: 'भावनात्मक जाल' },
  family_info_probing:   { en: 'Family Probing',      gu: 'પરિવારની વિગત માંગી',hi: 'परिवार की जानकारी' },
};

const CALL_LABELS = {
  'gu-scam.wav': '🇮🇳 ગુજરાતી · "Digital arrest" Fake Police Call (Scam)',
  'hi-scam.wav': '🇮🇳 हिन्दी · "Digital arrest" Fake Police Call (Scam)',
  'en-scam.wav': 'English · Fake Bank KYC / OTP Call (Scam)',
  'en-genuine.wav': 'English · Genuine Swiggy Delivery Call (Safe)',
};

let session = null;
let micSession = null;

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
  
  let sum = 0;
  for (let i = 0; i < ch.length; i++) sum += ch[i] * ch[i];
  const rms = Math.sqrt(sum / (ch.length || 1));
  if (rms < 0.005) return null;

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

function setBanner(kind, title, text = '') {
  const banner = $('banner');
  if (banner) banner.className = `banner banner-${kind}`;
  setText('bannerTitle', title);
  setText('bannerText', text);
  
  const iconEl = $('bannerIcon');
  const actionsEl = $('bannerActions');
  if (kind === 'scam') {
    if (iconEl) iconEl.textContent = '🚨';
    if (actionsEl) actionsEl.style.display = 'block';
  } else if (kind === 'suspicious') {
    if (iconEl) iconEl.textContent = '⚠️';
    if (actionsEl) actionsEl.style.display = 'none';
  } else if (kind === 'safe') {
    if (iconEl) iconEl.textContent = '✅';
    if (actionsEl) actionsEl.style.display = 'none';
  } else {
    if (iconEl) iconEl.textContent = '🛡️';
    if (actionsEl) actionsEl.style.display = 'none';
  }
}

function reset() {
  setBanner('idle', 'Ready to Protect', 'Select a call below or start the live microphone.');
  const riskBar = $('risk');
  if (riskBar) { riskBar.style.width = '0%'; riskBar.style.background = 'var(--ok)'; }
  setText('riskNum', '0');
  const flagsEl = $('flags'); if (flagsEl) flagsEl.replaceChildren();
  setText('reason', 'Ready to monitor call...');
  const tEl = $('transcript'); if (tEl) tEl.replaceChildren();
  const noticeEl = $('notice'); if (noticeEl) noticeEl.hidden = true;
  setText('status', '');
}

function renderFlags(set) {
  const flagsEl = $('flags');
  if (!flagsEl) return;
  const lang = $('lang')?.value || 'gu';
  flagsEl.replaceChildren(...[...set].map((f) => {
    const s = document.createElement('span'); s.className = 'chip';
    const l = FLAG_LABELS[f] || { en: f };
    s.textContent = `${l[lang] || l.en} · ${l.en}`; return s;
  }));
}

async function speakWarning(text) {
  const speakCheck = $('speak');
  if (speakCheck && !speakCheck.checked) return;
  if (!text) return;
  try {
    const { audio } = await api('/api/tts', { text });
    new Audio(`data:audio/wav;base64,${audio}`).play();
  } catch (e) {
    if ('speechSynthesis' in window) {
      const u = new SpeechSynthesisUtterance(text);
      u.lang = ($('lang')?.value === 'hi') ? 'hi-IN' : 'gu-IN';
      window.speechSynthesis.speak(u);
    }
  }
}

function notifyContact() {
  const cName = $('cName')?.value.trim() || 'Family Member';
  const myRel = $('myRel')?.value.trim() || 'family member';
  const phone = $('cPhone')?.value.replace(/\D/g, '') || '';
  const autoCheck = $('autoNotify');
  if (!autoCheck?.checked || !phone) return;
  
  const msg = `🚨 EMERGENCY ALERT: Your ${myRel} may be on an active scam call right now. Please call them immediately.`;
  api('/api/notify', { to: phone, message: msg }).catch(() => {});
  
  const n = $('notice');
  if (n) {
    n.hidden = false; n.replaceChildren();
    const p = document.createElement('div'); p.textContent = `Alert for ${cName}: “${msg}”`;
    const a = document.createElement('a'); a.target = '_blank'; a.rel = 'noopener';
    a.href = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`; a.textContent = 'Send on WhatsApp';
    n.append(p, a);
  }
}

function handleResult(s, r, idx) {
  const lang = $('lang')?.value || 'gu';
  if (r.transcript) {
    const tEl = $('transcript');
    if (tEl) {
      const p = document.createElement('p');
      p.innerHTML = `<span class="t">${idx * CHUNK_SEC}s </span>`;
      p.append(document.createTextNode(r.transcript));
      tEl.append(p);
      tEl.scrollTop = 1e9;
    }
    s.context += ` ${r.transcript}`;
  }

  (r.red_flags || []).forEach((f) => s.flags.add(f));
  renderFlags(s.flags);

  s.risk = Math.max(r.verdict === 'safe' ? 0 : s.risk, r.risk || 0);
  const riskBar = $('risk');
  if (riskBar) {
    riskBar.style.width = `${s.risk}%`;
    riskBar.style.background = s.risk > 70 ? 'var(--bad)' : s.risk > 35 ? 'var(--warn)' : 'var(--ok)';
  }
  setText('riskNum', s.risk);
  setText('reason', r.reason_en || '');

  const warn = lang === 'hi' ? (r.warning_hi || r.warning_gu) : (r.warning_gu || r.warning_hi);
  if (r.verdict === 'scam' || s.risk >= 75) {
    setBanner('scam', lang === 'gu' ? '🚨 સ્કેમ કોલ! ફોન કાપી નાખો' : '🚨 स्कैम कॉल! फोन काट दीजिए', warn);
    if (!s.alerted) {
      s.alerted = true;
      speakWarning(warn);
      notifyContact();
    }
  } else if (r.verdict === 'suspicious' && !s.alerted) {
    setBanner('suspicious', lang === 'gu' ? '⚠️ સાવચેત રહો' : '⚠️ सावधान रहें', warn);
  } else if (!s.alerted && s.risk < 20) {
    setBanner('safe', '✅ Normal Call Verified', 'No fraudulent patterns detected.');
  }
}

async function start() {
  stop(); reset();
  const select = $('callSelect');
  const callName = select?.value || 'gu-scam.wav';
  let blob;
  try {
    blob = await (await fetch(`/calls/${callName}`)).blob();
  } catch {
    return setText('status', 'Could not load call audio file');
  }

  const decoded = await new AudioContext().decodeAudioData(await blob.arrayBuffer());
  const audio = new Audio(URL.createObjectURL(blob));
  const s = session = { audio, flags: new Set(), risk: 0, context: '', alerted: false, next: 0, timer: null };
  const total = Math.ceil(decoded.duration / CHUNK_SEC);
  setBanner('idle', 'Protecting Call…', 'Analyzing audio stream in real-time');

  const WINDOW_SEC = 8;
  const dispatch = async (i) => {
    if (s.alerted && s.risk >= 85) {
      setText('status', `🚨 Scam already verified (${s.risk}%).`);
      return;
    }
    const t1 = Math.min(decoded.duration, (i + 1) * CHUNK_SEC);
    const t0 = Math.max(0, t1 - WINDOW_SEC);
    try {
      const audioB64 = await chunkToB64(decoded, t0, t1);
      if (session !== s) return;
      setText('status', `⚡ Shield analyzing ${t0.toFixed(0)}–${t1.toFixed(0)}s…`);
      const r = await api('/api/analyze', { audio: audioB64 || '', context: s.context, callName });
      if (session === s) handleResult(s, r, i);
    } catch (e) {
      if (session === s) setText('status', `Note: ${e.message}`);
    }
    if (session === s && i === total - 1) setText('status', 'Call completed.');
  };

  s.timer = setInterval(() => {
    while (s.next < total && (audio.ended || audio.currentTime >= Math.min((s.next + 1) * CHUNK_SEC, decoded.duration - 0.05))) {
      dispatch(s.next++);
    }
    if (s.next >= total) clearInterval(s.timer);
  }, 200);
  audio.play();
}

function stop() {
  if (session) {
    clearInterval(session.timer);
    session.audio.pause();
    session = null;
  }
}

async function startLiveMic() {
  stop(); stopLiveMic(); reset();
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const startBtn = $('micStart'); if (startBtn) startBtn.disabled = true;
    const stopBtn = $('micStop'); if (stopBtn) stopBtn.disabled = false;
    setText('micStatus', '🟢 LIVE SHIELD ACTIVE: Listening to speakerphone...');
    const statEl = $('micStatus'); if (statEl) statEl.style.color = '#16a34a';

    const mediaRecorder = new MediaRecorder(stream);
    const s = micSession = { stream, mediaRecorder, flags: new Set(), risk: 0, context: '', alerted: false, chunkIdx: 0 };
    setBanner('idle', '🎙️ Live Shield Listening', 'Put phone on speakerphone. We will alert you if a scam starts.');

    mediaRecorder.ondataavailable = async (e) => {
      if (e.data.size > 0 && micSession === s) {
        const arrayBuf = await e.data.arrayBuffer();
        const audioCtx = new AudioContext();
        const decoded = await audioCtx.decodeAudioData(arrayBuf);
        const b64 = await chunkToB64(decoded, 0, decoded.duration);
        if (!b64) return;
        setText('status', `⚡ Live Guardian analyzing slice #${s.chunkIdx + 1}…`);
        const r = await api('/api/analyze', { audio: b64, context: s.context });
        if (micSession === s) handleResult(s, r, s.chunkIdx++);
      }
    };
    mediaRecorder.start(5000);
  } catch (err) {
    setText('micStatus', `Microphone error: ${err.message}`);
    const statEl = $('micStatus'); if (statEl) statEl.style.color = '#dc2626';
  }
}

function stopLiveMic() {
  if (micSession) {
    try {
      if (micSession.mediaRecorder?.state !== 'inactive') micSession.mediaRecorder.stop();
      micSession.stream?.getTracks().forEach((t) => t.stop());
    } catch {}
    micSession = null;
    const startBtn = $('micStart'); if (startBtn) startBtn.disabled = false;
    const stopBtn = $('micStop'); if (stopBtn) stopBtn.disabled = true;
    setText('micStatus', 'Microphone is idle');
    const statEl = $('micStatus'); if (statEl) statEl.style.color = '#ea580c';
  }
}

// Mode switches
const tabDemo = $('tabDemo');
const tabMic = $('tabMic');
if (tabDemo && tabMic) {
  tabDemo.onclick = () => {
    tabDemo.className = 'mode-btn active'; tabMic.className = 'mode-btn';
    const pDemo = $('panelDemo'); if (pDemo) pDemo.style.display = 'block';
    const pMic = $('panelMic'); if (pMic) pMic.style.display = 'none';
    stopLiveMic();
  };
  tabMic.onclick = () => {
    tabMic.className = 'mode-btn active'; tabDemo.className = 'mode-btn';
    const pDemo = $('panelDemo'); if (pDemo) pDemo.style.display = 'none';
    const pMic = $('panelMic'); if (pMic) pMic.style.display = 'block';
    stop();
  };
}

const hangupBtn = $('hangupBtn');
if (hangupBtn) {
  hangupBtn.onclick = () => {
    stop(); stopLiveMic();
    setBanner('safe', '✅ Call Terminated', 'Great job! You avoided the scam call.');
    const lang = $('lang')?.value || 'gu';
    speakWarning(lang === 'gu' ? 'કોલ કાપી નાખવામાં આવ્યો છે. તમે હવે સુરક્ષિત છો.' : 'कॉल काट दिया गया है. आप सुरक्षित हैं.');
  };
}

const playBtn = $('play'); if (playBtn) playBtn.onclick = start;
const stopBtn = $('stop'); if (stopBtn) stopBtn.onclick = () => { stop(); reset(); };
const micStartBtn = $('micStart'); if (micStartBtn) micStartBtn.onclick = startLiveMic;
const micStopBtn = $('micStop'); if (micStopBtn) micStopBtn.onclick = stopLiveMic;

// Init persistent settings
['cName', 'cRel', 'cPhone', 'myRel', 'lang'].forEach((id) => {
  const el = $(id);
  if (el) {
    try { const v = localStorage.getItem(`scs_${id}`); if (v) el.value = v; } catch {}
    el.addEventListener('change', () => { try { localStorage.setItem(`scs_${id}`, el.value); } catch {} });
  }
});

// Load calls
fetch('/api/config').then((r) => r.json()).then((c) => {
  const order = ['gu-scam.wav', 'hi-scam.wav', 'en-scam.wav', 'en-genuine.wav'];
  const files = [...new Set([...order.filter((f) => c.calls?.includes(f)), ...(c.calls || [])])];
  const select = $('callSelect');
  if (select) {
    select.replaceChildren(...files.map((f) => new Option(CALL_LABELS[f] || f, f)));
  }
});
