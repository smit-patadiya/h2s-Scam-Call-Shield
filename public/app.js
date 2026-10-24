const CHUNK_SEC = 4;      // warning can fire after the first few seconds
const RATE = 16000;       // Gemini downsamples audio to 16 kHz anyway
const $ = (id) => document.getElementById(id);

const FLAG_LABELS = {
  urgency:               { en: 'Urgency',          gu: 'ઉતાવળ',            hi: 'જલ્દબાઝી' },
  threat:                { en: 'Threats',          gu: 'ધમકી',             hi: 'ધમકી' },
  otp_request:           { en: 'OTP / PIN asked',  gu: 'OTP/PIN માંગ્યો',   hi: 'OTP/PIN માઁગા' },
  money_request:         { en: 'Money asked',      gu: 'પૈસા માંગ્યા',      hi: 'પૈસે માઁગે' },
  authority_claim:       { en: 'Police/bank claim', gu: 'પોલીસ/બેંકનો દાવો', hi: 'પોલીસ/બૈંક કા દાવા' },
  isolation:             { en: "Don't hang up",    gu: 'ફોન કાપવાની ના',    hi: 'ફોન કાટને સે મના' },
  remote_access:         { en: 'Remote access',    gu: 'રિમોટ એપ',         hi: 'રિમોટ ઐપ' },
  personal_info_request: { en: 'ID / Personal Info',  gu: 'આધાર/અંગત માહિતી',    hi: 'આઈડી/નિજી જાનકારી' },
  emotional_manipulation:{ en: 'Emotional Trap',      gu: 'લાગણીથી છેતરપિંડી',   hi: 'ભાવનાત્મક જાલ' },
  family_info_probing:   { en: 'Family Probing',      gu: 'પરિવારની વિગત માંગી',hi: 'પરિવાર કી જાનકારી' },
};
const CALL_LABELS = {
  'gu-scam.wav': '🇮🇳 Gujarati · "Digital arrest" police call (scam)',
  'hi-scam.wav': '🇮🇳 Hindi · "Digital arrest" police call (scam)',
  'en-scam.wav': 'English · Fake bank KYC / OTP call (scam)',
  'en-genuine.wav': 'English · Swiggy delivery call (genuine)',
};

let session = null;
let micSession = null;

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
  
  // Client-Side VAD (Voice Activity Detection): Skip silence to conserve API quota
  let sum = 0;
  for (let i = 0; i < ch.length; i++) sum += ch[i] * ch[i];
  const rms = Math.sqrt(sum / (ch.length || 1));
  if (rms < 0.006) return null; // Pure silence or pause: skip Gemini call completely

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

// ---------- UI Helpers ----------
function setBanner(kind, title, text = '') {
  const banner = $('banner');
  banner.className = `banner banner-${kind}`;
  $('bannerTitle').textContent = title;
  $('bannerText').textContent = text;
  
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
  setBanner('idle', 'Guardian Active & Ready', 'Select a call scenario or start the Live Mic Guardian on speakerphone.');
  $('risk').style.width = '0%'; $('riskNum').textContent = '0';
  $('flags').replaceChildren(); $('reason').textContent = 'Awaiting call start...'; $('transcript').replaceChildren();
  $('notice').hidden = true; $('status').textContent = '';
  $('dimensionsBox').replaceChildren();
  if ($('riskBadge')) {
    $('riskBadge').textContent = 'SAFE';
    $('riskBadge').style.background = 'rgba(16, 185, 129, 0.15)';
    $('riskBadge').style.color = 'var(--accent-green)';
  }

  // Reset Agent Telemetry cards
  $('statusAgent1').textContent = 'PASS · 0ms'; $('statusAgent1').className = 'agent-badge pass';
  $('detailAgent1').textContent = 'Watching for UPI inversion & APK traps';
  $('statusAgent2').textContent = 'STANDBY'; $('statusAgent2').className = 'agent-badge idle';
  $('detailAgent2').textContent = 'Awaiting audio input stream...';
  $('statusAgent3').textContent = 'P×T×M×E (1.0x)'; $('statusAgent3').className = 'agent-badge purple';
  $('detailAgent3').textContent = 'Phase 1: Initial Monitoring';
  $('statusAgent4').textContent = 'ARMED'; $('statusAgent4').className = 'agent-badge ok';
  $('detailAgent4').textContent = 'Spoken alerts configured for elder';
  
  if ($('metricLatency')) $('metricLatency').textContent = '0.4 ms';
  if ($('metricAcousticRisk')) $('metricAcousticRisk').textContent = 'Normal';
  if ($('metricDims')) $('metricDims').textContent = '0 / 4';
  if ($('metricMultiplier')) $('metricMultiplier').textContent = '1.00x';
}

function renderFlags(set) {
  const lang = $('lang').value;
  $('flags').replaceChildren(...[...set].map((f) => {
    const s = document.createElement('span'); s.className = 'chip';
    const l = FLAG_LABELS[f] || { en: f };
    s.textContent = `${l[lang] || l.en} · ${l.en}`; return s;
  }));
}

function renderDimensions(dims = []) {
  const dimNames = {
    P: 'P · Persona (Authority)',
    T: 'T · Trigger (Pretext)',
    M: 'M · Pressure (Duress)',
    E: 'E · Extraction (Exploit)'
  };
  $('dimensionsBox').replaceChildren(...dims.map((d) => {
    const s = document.createElement('span'); s.className = 'dim-pill';
    s.textContent = dimNames[d] || d;
    return s;
  }));
  if ($('metricDims')) $('metricDims').textContent = `${dims.length} / 4`;
}

async function speakWarning(text) {
  if (!$('speak').checked || !text) return;
  try {
    const { audio } = await api('/api/tts', { text });
    new Audio(`data:audio/wav;base64,${audio}`).play();
  } catch (e) {
    if ('speechSynthesis' in window) {
      const u = new SpeechSynthesisUtterance(text);
      u.lang = $('lang').value === 'gu' ? 'gu-IN' : 'hi-IN';
      window.speechSynthesis.speak(u);
      $('status').textContent = `Spoken warning played via voice backup (${e.message})`;
    } else {
      $('status').textContent = `Voice warning unavailable: ${e.message}`;
    }
  }
}

function notifyContact() {
  const name = $('cName').value.trim(), rel = $('myRel').value.trim() || 'family member';
  const phone = $('cPhone').value.replace(/\D/g, '');
  if (!$('autoNotify').checked || !phone) return;
  const msg = `🚨 EMERGENCY ALERT: Your ${rel} may be on an active scam / digital arrest call right now. Please call them immediately.`;
  api('/api/notify', { to: phone, message: msg }).catch(() => {});
  const n = $('notice'); n.hidden = false; n.replaceChildren();
  const p = document.createElement('div'); p.textContent = `Alert for ${name || 'your contact'}: “${msg}”`;
  const a = document.createElement('a'); a.target = '_blank'; a.rel = 'noopener';
  a.href = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`; a.textContent = 'Send on WhatsApp';
  n.append(p, a);
}

// ---------- Multi-Agent Telemetry Handler ----------
function updateAgentTelemetry(agents = {}) {
  // Agent 1: Sentinel
  if (agents.agent_sentinel) {
    const a1 = agents.agent_sentinel;
    $('statusAgent1').textContent = `${a1.status} · ${a1.latency_ms || 1}ms`;
    $('statusAgent1').className = `agent-badge ${a1.status === 'ALERT' ? 'alert' : 'pass'}`;
    $('detailAgent1').textContent = a1.upi_trap?.isExploit
      ? a1.upi_trap.reason
      : (a1.matches?.[0] || 'Clean - No deterministic exploit found');
    if ($('metricLatency')) $('metricLatency').textContent = `${a1.latency_ms || 1} ms`;
  }

  // Agent 2: Acoustic
  if (agents.agent_acoustic) {
    const a2 = agents.agent_acoustic;
    $('statusAgent2').textContent = `${a2.language || 'ACTIVE'} · ${a2.acoustic_risk || 0}%`;
    $('statusAgent2').className = `agent-badge ${a2.acoustic_risk >= 70 ? 'alert' : 'ok'}`;
    $('detailAgent2').textContent = `Model: ${a2.model} · Tone: ${a2.detected_flags?.join(', ') || 'Normal'}`;
    if ($('metricAcousticRisk')) $('metricAcousticRisk').textContent = `${a2.acoustic_risk || 0}%`;
  }

  // Agent 3: Cognitive Vector
  if (agents.agent_cognitive) {
    const a3 = agents.agent_cognitive;
    const mult = a3.diversity_multiplier ? `${a3.diversity_multiplier}x` : '1.0x';
    $('statusAgent3').textContent = `Vector [${a3.active_dimensions?.join('') || '—'}] ${mult}`;
    $('statusAgent3').className = `agent-badge ${a3.fused_risk >= 75 ? 'alert' : 'purple'}`;
    $('detailAgent3').textContent = a3.funnel_stage || 'Analyzing conversation progression';
    if ($('metricMultiplier')) $('metricMultiplier').textContent = mult;
    renderDimensions(a3.active_dimensions || []);
  }

  // Agent 4: Guardian Shield
  if (agents.agent_guardian) {
    const a4 = agents.agent_guardian;
    const isTriggered = a4.action?.includes('TRIGGERED');
    $('statusAgent4').textContent = isTriggered ? 'TRIGGERED' : 'ARMED';
    $('statusAgent4').className = `agent-badge ${isTriggered ? 'alert' : 'ok'}`;
    $('detailAgent4').textContent = a4.action || 'Monitoring in background';
  }
}

// ---------- Structured Context Builder ----------
function buildStructuredContext(s) {
  if (!s.timeline || !s.timeline.length) return s.context || '';
  
  const timelineText = s.timeline.map((t) => `* [${t.time}]: "${t.text}"`).join('\n');
  const flagsList = Array.from(s.flags).join(', ') || 'None';
  
  return `### CUMULATIVE CALL CONTEXT & FUNNEL PROGRESSION:
- Active Red Flags So Far: [${flagsList}]
- Cumulative Risk Level: ${s.risk}%
- Call Timeline:
${timelineText}

### INSTRUCTIONS FOR THIS CHUNK:
Evaluate whether this new audio continues the scam funnel (e.g. pivoting to isolation, intimidation, OTP/UPI/remote access).`;
}

function handleResult(s, r, idx) {
  const lang = $('lang').value;
  if (r.transcript) {
    const p = document.createElement('p'); p.innerHTML = `<span class="t">${idx * CHUNK_SEC}s </span>`;
    p.append(document.createTextNode(r.transcript)); $('transcript').append(p);
    $('transcript').scrollTop = 1e9;
    s.context += ` ${r.transcript}`;
    s.timeline.push({ time: `${idx * CHUNK_SEC}s`, text: r.transcript });
  }

  (r.red_flags || []).forEach((f) => s.flags.add(f));
  renderFlags(s.flags);

  s.risk = Math.max(r.verdict === 'safe' ? 0 : s.risk, r.risk || 0);
  $('risk').style.width = `${s.risk}%`; $('riskNum').textContent = s.risk;
  $('risk').style.background = s.risk > 70 ? 'var(--accent-red)' : s.risk > 35 ? 'var(--accent-amber)' : 'var(--accent-green)';
  $('reason').textContent = r.reason_en || '';

  // Update Risk Badge
  if ($('riskBadge')) {
    if (s.risk >= 75) {
      $('riskBadge').textContent = '🚨 SCAM ALERT';
      $('riskBadge').style.background = 'rgba(239, 68, 68, 0.2)';
      $('riskBadge').style.color = 'var(--accent-red)';
      $('riskBadge').style.borderColor = 'var(--accent-red)';
    } else if (s.risk >= 35) {
      $('riskBadge').textContent = '⚠️ SUSPICIOUS';
      $('riskBadge').style.background = 'rgba(245, 158, 11, 0.2)';
      $('riskBadge').style.color = 'var(--accent-amber)';
      $('riskBadge').style.borderColor = 'var(--accent-amber)';
    } else {
      $('riskBadge').textContent = 'SAFE';
      $('riskBadge').style.background = 'rgba(16, 185, 129, 0.15)';
      $('riskBadge').style.color = 'var(--accent-green)';
    }
  }

  // Update Multi-Agent Dashboard
  if (r.agents) updateAgentTelemetry(r.agents);

  const warn = lang === 'gu' ? r.warning_gu : r.warning_hi;
  if (r.verdict === 'scam' || s.risk >= 75) {
    setBanner('scam', lang === 'gu' ? '🚨 સ્કેમ કોલ! ફોન કાપી નાખો' : '🚨 स्कैम कॉल! फोन काट दीजिए', warn);
    if (!s.alerted) {
      s.alerted = true;
      speakWarning(warn);
      notifyContact();
      // Auto-save caller number to Fraud Blacklist Registry
      const callerPhone = $('callerPhone').value.trim();
      if (callerPhone) {
        api('/api/record-scam', {
          phone: callerPhone,
          flags: [...s.flags],
          risk: s.risk,
          reason: r.reason_en,
          category: r.red_flags?.includes('authority_claim') ? 'Digital Arrest Fraud' : 'Cyber Fraud'
        }).then(() => {
          checkCallerNumber();
          refreshBlacklist();
        }).catch(() => {});
      }
    }
  } else if (r.verdict === 'suspicious' && !s.alerted) {
    setBanner('suspicious', lang === 'gu' ? '⚠️ સાવચેત રહો' : '⚠️ सावधान रहें', warn);
  } else if (!s.alerted && s.risk < 20) {
    setBanner('safe', '✅ Looks like a normal call', 'No scam red flags heard so far.');
  }
}

// ---------- Session (File Mode) ----------
async function start() {
  stop(); reset();
  const file = $('upload').files[0];
  let blob;
  try {
    blob = file || await (await fetch(`/calls/${$('callSelect').value}`)).blob();
  } catch { return ($('status').textContent = 'Could not load call'); }
  const decoded = await new AudioContext().decodeAudioData(await blob.arrayBuffer());
  const audio = new Audio(URL.createObjectURL(blob));
  const s = session = {
    audio,
    flags: new Set(),
    risk: 0,
    context: '',
    timeline: [],
    alerted: false,
    next: 0,
    timer: null
  };
  const total = Math.ceil(decoded.duration / CHUNK_SEC);
  setBanner('idle', 'Listening…', 'Multi-Agent pipeline analyzing call slices in real-time');

  const WINDOW_SEC = 8; // Merges 2 slots into a rolling window so sentences are complete
  const dispatch = async (i) => {
    if (s.alerted && s.risk >= 85) {
      $('status').textContent = `🚨 Scam already verified (${s.risk}%). Analysis paused to save API quota.`;
      return;
    }
    const t1 = Math.min(decoded.duration, (i + 1) * CHUNK_SEC);
    const t0 = Math.max(0, t1 - WINDOW_SEC);
    try {
      const audioB64 = await chunkToB64(decoded, t0, t1);
      if (!audioB64) {
        $('status').textContent = `⏸️ Silence/pause in ${t0.toFixed(0)}–${t1.toFixed(0)}s · VAD Skipped API call`;
        return;
      }
      if (session !== s) return;
      $('status').textContent = `⚡ Multi-Agent Swarm analyzing ${t0.toFixed(0)}–${t1.toFixed(0)}s…`;
      
      const structuredContext = buildStructuredContext(s);
      const r = await api('/api/analyze', { audio: audioB64, context: structuredContext });
      if (session === s) handleResult(s, r, i);
    } catch (e) {
      if (session === s) $('status').textContent = `Analysis note: ${e.message}`;
    }
    if (session === s && i === total - 1) $('status').textContent += ' Call ended.';
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

// ---------- Live Microphone Guardian (Option 2) ----------
async function startLiveMic() {
  stop(); stopLiveMic(); reset();
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    $('micStart').disabled = true;
    $('micStop').disabled = false;
    $('micStatus').innerHTML = '🟢 <b>LIVE GUARDIAN ACTIVE:</b> Listening to speakerphone audio in room...';
    $('micStatus').style.color = 'var(--accent-green)';

    const mediaRecorder = new MediaRecorder(stream);
    const s = micSession = {
      stream,
      mediaRecorder,
      flags: new Set(),
      risk: 0,
      context: '',
      timeline: [],
      alerted: false,
      chunkIdx: 0
    };

    setBanner('idle', '🎙️ Live Room Guardian Active', 'Listening to speakerphone call in the room...');

    mediaRecorder.ondataavailable = async (e) => {
      if (e.data.size > 0 && micSession === s) {
        const arrayBuf = await e.data.arrayBuffer();
        const audioCtx = new AudioContext();
        const decoded = await audioCtx.decodeAudioData(arrayBuf);
        const b64 = await chunkToB64(decoded, 0, decoded.duration);
        
        if (!b64) {
          $('status').textContent = '⏸️ Room silence · VAD skipped API dispatch';
          return;
        }

        $('status').textContent = `⚡ Live Guardian analyzing slice #${s.chunkIdx + 1}…`;
        const structuredContext = buildStructuredContext(s);
        const r = await api('/api/analyze', { audio: b64, context: structuredContext });
        if (micSession === s) {
          handleResult(s, r, s.chunkIdx++);
        }
      }
    };

    mediaRecorder.start(6000); // 6-second slices
  } catch (err) {
    $('micStatus').textContent = `Microphone error: ${err.message}`;
    $('micStatus').style.color = 'var(--accent-red)';
  }
}

function stopLiveMic() {
  if (micSession) {
    try {
      if (micSession.mediaRecorder?.state !== 'inactive') micSession.mediaRecorder.stop();
      micSession.stream?.getTracks().forEach((t) => t.stop());
    } catch {}
    micSession = null;
    $('micStart').disabled = false;
    $('micStop').disabled = true;
    $('micStatus').textContent = 'Microphone is currently idle';
    $('micStatus').style.color = 'var(--accent-amber)';
  }
}

// ---------- Tab Mode Switching ----------
$('tabDemo').onclick = () => {
  $('tabDemo').className = 'pill-btn active';
  $('tabMic').className = 'pill-btn';
  $('panelDemo').style.display = 'block';
  $('panelMic').style.display = 'none';
  stopLiveMic();
};

$('tabMic').onclick = () => {
  $('tabMic').className = 'pill-btn active';
  $('tabDemo').className = 'pill-btn';
  $('panelDemo').style.display = 'none';
  $('panelMic').style.display = 'block';
  stop();
};

$('micStart').onclick = startLiveMic;
$('micStop').onclick = stopLiveMic;

// ---------- Elder View Toggle & Hang Up ----------
let elderMode = false;
const elderToggle = $('elderToggle');
if (elderToggle) {
  elderToggle.onclick = () => {
    elderMode = !elderMode;
    document.body.classList.toggle('elder-mode', elderMode);
    elderToggle.innerHTML = `👵 Elder View: <b>${elderMode ? 'ON' : 'OFF'}</b>`;
    elderToggle.className = elderMode ? 'pill-btn active' : 'pill-btn';
  };
}

const hangupBtn = $('hangupBtn');
if (hangupBtn) {
  hangupBtn.onclick = () => {
    stop();
    stopLiveMic();
    setBanner('safe', '✅ Call Terminated', 'Great job! You avoided the scam call. Your family and account are safe.');
    const lang = $('lang').value;
    const msg = lang === 'gu'
      ? 'કોલ કાપી નાખવામાં આવ્યો છે. તમે હવે સંપૂર્ણ સુરક્ષિત છો.'
      : 'कॉल काट दिया गया है. आप अब पूरी तरह सुरक्षित हैं.';
    speakWarning(msg);
  };
}

// ---------- Init & Persistent Config ----------
['cName', 'cRel', 'cPhone', 'myRel', 'lang'].forEach((id) => {
  try { const v = localStorage.getItem(`scs_${id}`); if (v) $(id).value = v; } catch {}
  $(id).addEventListener('change', () => { try { localStorage.setItem(`scs_${id}`, $(id).value); } catch {} });
});
$('play').onclick = start;
$('stop').onclick = () => { stop(); reset(); };
$('upload').onchange = () => { $('callSelect').disabled = !!$('upload').files[0]; };

// ---------- Fraud Database Integration ----------
async function checkCallerNumber() {
  const phone = $('callerPhone').value.trim();
  const badge = $('callerBadge');
  if (!phone) { badge.style.display = 'none'; return; }
  try {
    const res = await api('/api/check-number', { phone });
    if (res.isKnownScam) {
      badge.style.display = 'block';
      badge.style.background = 'rgba(239, 68, 68, 0.15)';
      badge.style.color = 'var(--accent-red)';
      badge.style.border = '1px solid rgba(239, 68, 68, 0.3)';
      badge.innerHTML = `🚨 <b>Known Scam Number</b> (${res.details.reportsCount}x reports) &bull; ${res.details.category}`;
      if (!session && !micSession) {
        setBanner('suspicious', '⚠️ Known Fraud Number Alert', `This number was previously reported for ${res.details.category}. Do not share OTP or money.`);
      }
    } else {
      badge.style.display = 'block';
      badge.style.background = 'rgba(16, 185, 129, 0.15)';
      badge.style.color = 'var(--accent-green)';
      badge.style.border = '1px solid rgba(16, 185, 129, 0.3)';
      badge.textContent = '✓ Clean Number · No previous fraud reports in database';
    }
  } catch {}
}

async function refreshBlacklist() {
  try {
    const r = await fetch('/api/scam-numbers').then((res) => res.json());
    $('blacklistCount').textContent = r.numbers?.length || 0;
    const list = $('blacklistList');
    list.replaceChildren(...(r.numbers || []).map((n) => {
      const d = document.createElement('div');
      d.style.cssText = 'padding: 6px 0; border-bottom: 1px solid var(--card-border); display: flex; justify-content: space-between; align-items: center;';
      d.innerHTML = `<span><b>${n.phone}</b> &bull; ${n.category}</span><span style="color:var(--accent-red); font-weight:700;">${n.reportsCount}x</span>`;
      return d;
    }));
  } catch {}
}

$('callerPhone').addEventListener('input', checkCallerNumber);

fetch('/api/config').then((r) => r.json()).then((c) => {
  const order = ['gu-scam.wav', 'hi-scam.wav', 'en-scam.wav', 'en-genuine.wav'];
  const files = [...new Set([...order.filter((f) => c.calls.includes(f)), ...c.calls])];
  $('callSelect').replaceChildren(...files.map((f) => new Option(CALL_LABELS[f] || f, f)));
  if (!files.length) $('status').textContent = 'No calls found: run  node scripts/generate-calls.mjs  or upload a .wav';
  if (!c.hasKey) setBanner('suspicious', 'GEMINI_API_KEY is not set', 'Set it and restart the server to enable analysis.');
  checkCallerNumber();
  refreshBlacklist();
});
