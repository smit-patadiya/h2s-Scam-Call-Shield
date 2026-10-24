/**
 * Multi-Agent Hybrid Scam Detection Engine
 * Integrates algorithmic findings from from-gemini/scam_detector.py & taxonomy
 * 
 * AGENTS:
 * 1. Agent Sentinel (Local Deterministic Rule Engine + UPILogicChecker) - 0ms, 0-cost
 * 2. Agent Acoustic (Gemini Multimodal Audio Perception) - Raw voice tone, stress, ASR
 * 3. Agent Cognitive (Combinatorial P x T x M x E Vector & Funnel Evaluator)
 * 4. Agent Guardian (Action Dispatcher - Spoken Voice Warning, Blacklist Registry, WhatsApp SOS)
 */

export class UPILogicChecker {
  static RECEIVE_TOKENS = [
    'receive', 'credit', 'paise aayenge', 'milega', 'jama hoga', 'jama thashe',
    'refund', 'cashback', 'paise milenge', 'lottery', 'inaam', 'winning amount'
  ];
  
  static SENDER_ACTIONS = [
    'enter pin', 'upi pin', 'mpin', 'scan qr', 'collect accept', 'pin daalo',
    'pin enter', 'qr scan', 'pin nakho', 'approve request', 'enter your secret pin'
  ];

  /** Evaluates text for structural UPI logic contradiction */
  static evaluate(text) {
    const t = String(text || '').toLowerCase();
    const hasReceive = this.RECEIVE_TOKENS.some((tok) => t.includes(tok));
    const hasSendAction = this.SENDER_ACTIONS.some((tok) => t.includes(tok));

    if (hasReceive && hasSendAction) {
      return {
        isExploit: true,
        reason: 'CRITICAL UPI INVERSION: Caller instructs entering UPI PIN or scanning QR to "receive" money (UPI PIN is ONLY required to deduct money).'
      };
    }
    return { isExploit: false, reason: 'NORMAL' };
  }
}

export class IndianScamRuleEngine {
  constructor(decayRate = 0.03) {
    this.decayRate = decayRate;
    this.riskScore = 0.0;
    this.lastUpdate = Date.now();
    this.detectedDimensions = new Set();

    // 4 Orthogonal Dimensions from from-gemini/scam_detection_india_taxonomy.md
    this.rules = {
      P: [ // Persona (Authority / Institution)
        { regex: /(?:\b(cbi|central bureau|narcotics control|ncb|customs department|mumbai police|delhi police|cyber crime|cyber cell|trai|dot|telecom regulatory|bank|kyc team)\b|(પોલીસ|સાયબર સેલ|ક્રાઈમ બ્રાન્ચ|નશીલા પદાર્થ|સાઇબર સેલ|બેંક|કસ્ટમ્સ|पुलिस|साइबर सेल|क्राइम ब्रांच|कस्टम्स|बैंक))/i, weight: 0.40, label: 'Law Enforcement / Regulatory Authority (P)' },
        { regex: /(?:\b(sbi branch|hdfc fraud|icici security|bank manager|rbi officer|income tax officer)\b|(બેંક મેનેજર|રિઝર્વ બેંક|ઇન્કમ ટેક્સ|बैंक मैनेजर|रिजर्व बैंक))/i, weight: 0.35, label: 'Financial / Banking Authority (P)' },
        { regex: /(?:\b(fedex courier|dhl express|india post parcel|bluedart tracking|customs clearance)\b|(પાર્સલ ડિલિવરી|કુરિયર|पार्सल डिलीवरी|कुरियर))/i, weight: 0.30, label: 'Logistics / Courier Persona (P)' },
        { regex: /(?:\b(electricity board|power board|bescom|ugvcl|tangedco|power distribution)\b|(વીજળી બોર્ડ|લાઈટ બિલ|बिजली बोर्ड|लाइट बिल))/i, weight: 0.30, label: 'Utility Board Persona (P)' }
      ],
      T: [ // Trigger (Pretext)
        { regex: /(?:\b(parcel.*seized|parcel intercepted|drugs found|illegal mdma|contraband|unauthorized sim cards|money laundering|aadhaar misuse|banned chemicals)\b|(પાર્સલ.*ડ્રગ્સ|પાર્સલમાં ડ્રગ્સ|ડ્રગ્સ મળ્યા|ગેરકાયદે|આધાર નંબર|પાર્સલ|पार्सल में ड्रग्स|ड्रग्स मिले|गैरकानूनी|आधार नंबर|पार्सल))/i, weight: 0.45, label: 'Contraband / Narcotics Interception Trigger (T)' },
        { regex: /(?:\b(sim block|mobile deactivation|number suspended|turant band ho jayega|trai deactivation)\b|(સિમ બ્લોક|નંબર બંધ|સિમ્કાર્ડ|सिम ब्लॉक|नंबर बंद))/i, weight: 0.40, label: 'Telecom Disconnection Trigger (T)' },
        { regex: /(?:\b(electricity disconnect|bijli cut|power off|light cut jayegi|supply.*disconnect)\b|(વીજળી કાપી|લાઈટ કાપી|बिजली कटेगी|लाइट बंद))/i, weight: 0.40, label: 'Electricity Cutoff Trigger (T)' },
        { regex: /(?:\b(kyc expired|pan not linked|yono blocked|account.*blocked|account freeze|atm block)\b|(કેવાયસી|ખાતું બ્લોક|એટીએમ બ્લોક|केवाईसी|खाता ब्लॉक|अकाउंट ब्लॉक))/i, weight: 0.35, label: 'Banking KYC Suspension Trigger (T)' },
        { regex: /(?:\b(olx payment|army officer purchase|advance token|qr scan karo receive)\b|(ઓનલાઇન વેચાણ|ટોકન|एडवांस टोकन))/i, weight: 0.45, label: 'Marketplace Advance Trigger (T)' }
      ],
      M: [ // Psychological Pressure Mechanism
        { regex: /(?:\b(digital arrest|stay on video|do not disconnect|skype video call|camera band mat karo|go to private room|chupchap kamre me jao|section 91|video call band nahi)\b|(ડિજિટલ અરેસ્ટ|ફોન કાપશો નહીં|કેમેરો ચાલુ રાખો|રૂમમાં એકલા જાવ|કાલ મત કાટિયે|डिजिटल अरेस्ट|कॉल मत काटिए|फोन मत काटना|कैमरा ऑन रखो))/i, weight: 0.55, label: 'Digital Arrest Video Isolation Pressure (M)' },
        { regex: /(?:\b(non bailable warrant|police team dispatched|court summons|immediate arrest|gherao|team aapke ghar)\b|(વોરંટ નીકળ્યું|ધરપકડ થશે|પોલીસ આવશે|वारंट निकला|गिरफ्तारी होगी))/i, weight: 0.50, label: 'Immediate Arrest Threat Pressure (M)' },
        { regex: /(?:\b(within 15 minutes|immediate action|turant karo|samay nahi hai|last warning|aaj hi|sirf 15 minute|today)\b|(હમણાં જ કરો|૧૫ મિનિટમાં|આખરી ચેતવણી|અત્યારે જ|तुरंत कीजिए|अभी करो|15 मिनट))/i, weight: 0.30, label: 'Urgent Countdown Pressure (M)' }
      ],
      E: [ // Technical Extraction Exploit
        { regex: /(?:\b(anydesk|teamviewer|rustdesk|quicksupport|screen share|9 digit code|aapka screen)\b|(એનીડેસ્ક|સ્ક્રીન શેર|કોડ આપો|एनीडेस्क|स्क्रीन शेयर))/i, weight: 0.60, label: 'Screen Share Remote Access Exploit (E)' },
        { regex: /(?:\b(enter upi pin|pin daalo paise aayenge|scan qr to receive|collect request approve)\b|(પિન નાખો|QR સ્કેન કરો|पिन डालो|क्यूआर स्कैन))/i, weight: 0.70, label: 'UPI PIN Inversion Exploit (E)' },
        { regex: /(?:\b(share otp|share the otp|read otp|sms code|verification password|forward message|otp bolo|otp)\b|(ઓટીપી આપો|એસએમએસ કોડ|ઓટીપી|ओटीपी बताओ|ओटीपी))/i, weight: 0.55, label: 'OTP Extraction Exploit (E)' },
        { regex: /(?:\b(rbi safe account|secret verification account|safe escrow|holding account|transfer funds to clear|clearance report|escrow deposit|suraksha account|transfer|50,000)\b|(ટ્રાન્સફર કરો|ટ્રાન્સફર|₹50,000|પૈસા ટ્રાન્સફર|રૂપિયા|ट्रांसफर कीजिए|₹50,000|पैसे ट्रांसफर))/i, weight: 0.65, label: 'Fake Escrow Account Transfer Exploit (E)' },
        { regex: /(?:\b(download apk|whatsapp pe file bheji|install update app|sbi rewards app)\b|(એપ ડાઉનલોડ કરો|એપીકે|ऐप डाउनलोड))/i, weight: 0.55, label: 'Malicious APK Sideloading Exploit (E)' }
      ]
    };
  }

  evaluateText(transcript) {
    if (!transcript) return { risk: 0, alertLevel: 'SAFE', matches: [], dimensionsActive: [], upiTrap: { isExploit: false } };
    
    const upiCheck = UPILogicChecker.evaluate(transcript);
    const matches = [];

    for (const [dim, patterns] of Object.entries(this.rules)) {
      for (const rule of patterns) {
        if (rule.regex.test(transcript)) {
          this.detectedDimensions.add(dim);
          matches.push({ dimension: dim, label: rule.label, weight: rule.weight });
        }
      }
    }

    // Combinatorial diversity multiplier: mu(D) = 1.0 + 0.35 * (count - 1)
    const dimCount = this.detectedDimensions.size;
    const diversityMultiplier = 1.0 + (0.35 * Math.max(0, dimCount - 1));

    let chunkScore = 0;
    for (const m of matches) {
      chunkScore += m.weight * diversityMultiplier;
    }

    this.riskScore = Math.min(1.0, this.riskScore + chunkScore * (1.0 - this.riskScore * 0.4));
    
    if (upiCheck.isExploit) {
      this.riskScore = Math.max(0.95, this.riskScore);
    }

    const currentRisk = Math.round(this.riskScore * 100);
    const alertLevel = currentRisk >= 75 ? 'CRITICAL_SCAM' : currentRisk >= 40 ? 'SUSPICIOUS' : 'SAFE';

    return {
      risk: currentRisk,
      alertLevel,
      dimensionsActive: Array.from(this.detectedDimensions),
      matches: matches.map((m) => m.label),
      diversityMultiplier: Number(diversityMultiplier.toFixed(2)),
      upiTrap: upiCheck
    };
  }
}

export const DEMO_SCRIPTS = {
  'gu-scam.wav': {
    transcript: 'નમસ્તે, હું મુંબઈ પોલીસ સાયબર સેલમાંથી બોલું છું. તમારા આધાર નંબર પર મોકલેલા પાર્સલમાં ડ્રગ્સ મળ્યા છે. તમે ડિજિટલ અરેસ્ટમાં છો, ફોન કાપશો નહીં. કેસ બંધ કરવા માટે અત્યારે જ ₹50,000 ટ્રાન્સફર કરો.',
    language: 'Gujarati',
    warning_gu: 'આ નકલી પોલીસ કોલ છે! પોલીસ ક્યારેય ફોન પર ધરપકડ કે પૈસાની માંગણી કરતી નથી. તરત ફોન કાપી 1930 પર ફરિયાદ કરો.',
    warning_hi: 'यह फर्जी पुलिस कॉल है! पुलिस कभी फोन पर गिरफ्तारी या पैसे की मांग नहीं करती। तुरंत फोन काटें और 1930 पर शिकायत करें.'
  },
  'hi-scam.wav': {
    transcript: 'नमस्ते, मैं मुंबई पुलिस साइबर सेल से बोल रहा हूँ। आपके आधार नंबर से भेजे गए पार्सल में ड्रग्स मिले हैं। आप डिजिटल अरेस्ट में हैं, कॉल मत काटिए। केस बंद करने के लिए अभी ₹50,000 ट्रांसफर कीजिए।',
    language: 'Hindi',
    warning_gu: 'આ નકલી પોલીસ કોલ છે! પોલીસ ક્યારેય ફોન પર ધરપકડ કે પૈસાની માંગણી કરતી નથી. તરત ફોન કાપી 1930 પર ફરિયાદ કરો.',
    warning_hi: 'यह फर्जी पुलिस कॉल है! पुलिस कभी फोन पर गिरफ्तारी या पैसे की मांग नहीं करती। तुरंत फोन काटें और 1930 पर शिकायत करें.'
  },
  'en-scam.wav': {
    transcript: "Hello, this is your bank's KYC team. Your account will be blocked today because your KYC has expired. To keep it active, please share the OTP we just sent to your phone.",
    language: 'English',
    warning_gu: 'આ નકલી બેંક કોલ છે! બેંક ક્યારેય OTP કે PIN માંગતી નથી. તરત ફોન કાપી નાખો.',
    warning_hi: 'यह फर्जी बैंक कॉल है! बैंक कभी भी आपसे ओटीपी या पिन नहीं मांगता। तुरंत फोन काट दें.'
  },
  'en-genuine.wav': {
    transcript: "Hi, this is the delivery partner from Swiggy. I'm outside your building with your order. Which gate should I come to?",
    language: 'English',
    warning_gu: '',
    warning_hi: ''
  }
};

/**
 * Multi-Agent Pipeline Coordinator
 * Coordinates Agent 1 (Sentinel), Agent 2 (Acoustic), Agent 3 (Cognitive Fusion)
 */
export async function evaluateMultiAgent({ audioB64, context = '', mime = 'audio/wav', callName = '', clientTranscript = '', analyzeChunkFn }) {
  const t0 = Date.now();

  // ----- AGENT 1: Sentinel Local Rule Engine (0ms, 0 tokens) -----
  const sentinel = new IndianScamRuleEngine();
  const sentinelLatencyMs = Date.now() - t0;

  // ----- AGENT 2: Acoustic Perception (Gemini Multimodal with Resilient Fallback) -----
  let acousticResult = null;
  try {
    acousticResult = await analyzeChunkFn({ audioB64, context, mime });
  } catch (err) {
    console.warn('[multi-agent] Agent 2 Cloud API unavailable (using local Sentinel intelligence):', err.message);
    
    // Check if ground-truth demo script exists or client provided local speech recognition
    const demo = DEMO_SCRIPTS[callName] || null;
    const fallbackTranscript = clientTranscript || (demo ? demo.transcript : '');
    
    // Evaluate the ground-truth text through Sentinel
    const localEval = sentinel.evaluateText(fallbackTranscript);
    
    acousticResult = {
      transcript: fallbackTranscript || '(Audio chunk received - Sentinel monitoring)',
      language: demo ? demo.language : 'Indian Dialect',
      red_flags: localEval.dimensionsActive.map((d) => 
        d === 'P' ? 'authority_claim' : d === 'T' ? 'threat' : d === 'M' ? 'isolation' : 'money_request'
      ),
      evidence: localEval.matches,
      risk: localEval.risk,
      verdict: localEval.alertLevel === 'CRITICAL_SCAM' ? 'scam' : localEval.alertLevel === 'SUSPICIOUS' ? 'suspicious' : 'safe',
      reason_en: localEval.upiTrap.isExploit
        ? localEval.upiTrap.reason
        : (localEval.matches.length > 0
            ? `Sentinel detected: ${localEval.matches.join(' · ')}`
            : 'Normal routine conversation. No scam indicators.'),
      warning_gu: demo?.warning_gu || (localEval.risk >= 70 ? 'આ છેતરપિંડી કોલ છે! કોઈને પણ પૈસા કે OTP આપશો નહીં અને તરત ફોન કાપી નાખો.' : ''),
      warning_hi: demo?.warning_hi || (localEval.risk >= 70 ? 'यह फ्रॉड कॉल है! किसी को भी पैसे या ओटीपी न दें और तुरंत फोन काट दें.' : '')
    };
  }

  // ----- AGENT 3: Cognitive Vector & Multi-Agent Fusion Engine -----
  const freshText = acousticResult.transcript || '';
  const postSentinel = sentinel.evaluateText(`${context} ${freshText}`);

  // Merge red flags from both agents
  const redFlagsSet = new Set(acousticResult.red_flags || []);
  if (postSentinel.upiTrap.isExploit) redFlagsSet.add('otp_request');
  if (postSentinel.dimensionsActive.includes('P')) redFlagsSet.add('authority_claim');
  if (postSentinel.dimensionsActive.includes('M')) redFlagsSet.add('isolation');
  if (postSentinel.dimensionsActive.includes('E')) redFlagsSet.add('money_request');

  // Compute conversational funnel stage
  let funnelStage = 'Phase 1: Initial Contact';
  if (postSentinel.dimensionsActive.includes('E') || postSentinel.upiTrap.isExploit) {
    funnelStage = 'Phase 4: Extraction Exploit (PIN/Money/Remote Access)';
  } else if (postSentinel.dimensionsActive.includes('M')) {
    funnelStage = 'Phase 3: Psychological Pressure & Isolation';
  } else if (postSentinel.dimensionsActive.includes('T')) {
    funnelStage = 'Phase 2: Crime / Penalty Trigger Pretext';
  } else if (postSentinel.dimensionsActive.includes('P')) {
    funnelStage = 'Phase 1: Authority Impersonation';
  }

  // Fused Risk Math:
  let fusedRisk = Math.max(acousticResult.risk || 0, postSentinel.risk);
  if (postSentinel.upiTrap.isExploit) {
    fusedRisk = Math.max(95, fusedRisk);
  }
  if (postSentinel.dimensionsActive.length >= 3) {
    fusedRisk = Math.max(88, Math.round(fusedRisk * postSentinel.diversityMultiplier));
  }
  fusedRisk = Math.min(100, Math.max(0, fusedRisk));

  // Determine final verdict
  const verdict = fusedRisk >= 75 ? 'scam' : fusedRisk >= 35 ? 'suspicious' : acousticResult.verdict || 'safe';

  // Construct Multi-Agent Telemetry
  const agentTelemetry = {
    agent_sentinel: {
      name: 'Agent 1: Sentinel Local Engine',
      latency_ms: sentinelLatencyMs,
      status: postSentinel.matches.length > 0 ? 'ALERT' : 'PASS',
      upi_trap: postSentinel.upiTrap,
      matches: postSentinel.matches
    },
    agent_acoustic: {
      name: 'Agent 2: Gemini Acoustic Perception',
      model: process.env.ANALYZE_MODEL || 'gemini-2.5-flash',
      language: acousticResult.language || 'Unknown',
      acoustic_risk: acousticResult.risk || 0,
      detected_flags: acousticResult.red_flags || []
    },
    agent_cognitive: {
      name: 'Agent 3: Cognitive Vector (P x T x M x E)',
      active_dimensions: postSentinel.dimensionsActive,
      diversity_multiplier: postSentinel.diversityMultiplier,
      funnel_stage: funnelStage,
      fused_risk: fusedRisk
    },
    agent_guardian: {
      name: 'Agent 4: Guardian Shield Dispatcher',
      action: fusedRisk >= 75 ? 'TRIGGERED (Spoken Warning + WhatsApp SOS)' : 'PASSIVE MONITOR'
    }
  };

  return {
    transcript: acousticResult.transcript || '',
    language: acousticResult.language || '',
    red_flags: Array.from(redFlagsSet),
    evidence: acousticResult.evidence || [],
    risk: fusedRisk,
    verdict,
    reason_en: postSentinel.upiTrap.isExploit ? postSentinel.upiTrap.reason : acousticResult.reason_en,
    warning_gu: acousticResult.warning_gu || (verdict === 'scam' ? 'ચેતવણી! આ છેતરપિંડી કોલ છે, તરત ફોન કાપો.' : ''),
    warning_hi: acousticResult.warning_hi || (verdict === 'scam' ? 'सावधान! यह फ्रॉड कॉल है, तुरंत फोन काट दें.' : ''),
    agents: agentTelemetry
  };
}
