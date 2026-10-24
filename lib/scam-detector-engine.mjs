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
        { regex: /\b(cbi|central bureau|narcotics control|ncb|customs department|mumbai police|delhi police|cyber crime|cyber cell|trai|dot|telecom regulatory|પોલીસ|ક્રાઈમ બ્રાન્ચ|નશીલા પદાર્થ)\b/i, weight: 0.40, label: 'Law Enforcement / Regulatory Authority (P)' },
        { regex: /\b(sbi branch|hdfc fraud|icici security|bank manager|rbi officer|income tax officer|કસ્ટમ્સ વિભાગ|બેંક મેનેજર|રિઝર્વ બેંક)\b/i, weight: 0.35, label: 'Financial / Banking Authority (P)' },
        { regex: /\b(fedex courier|dhl express|india post parcel|bluedart tracking|customs clearance|પાર્સલ ડિલિવરી)\b/i, weight: 0.30, label: 'Logistics / Courier Persona (P)' },
        { regex: /\b(electricity board|power board|bescom|ugvcl|tangedco|power distribution|વીજળી બોર્ડ|લાઈટ બિલ)\b/i, weight: 0.30, label: 'Utility Board Persona (P)' }
      ],
      T: [ // Trigger (Pretext)
        { regex: /\b(parcel.*seized|parcel intercepted|drugs found|illegal mdma|contraband|unauthorized sim cards|money laundering complaint|aadhaar misuse|banned chemicals|પાર્સલમાં ડ્રગ્સ|ગેરકાયદે દવાઓ|આધાર કાર્ડ ગેરઉપયોગ)\b/i, weight: 0.45, label: 'Contraband / Narcotics Interception Trigger (T)' },
        { regex: /\b(sim block|mobile deactivation|number suspended within 2 hours|turant band ho jayega|trai deactivation|સિમ કાર્ડ બ્લોક)\b/i, weight: 0.40, label: 'Telecom Disconnection Trigger (T)' },
        { regex: /\b(electricity disconnect|bijli cut|power off at 9:30|light cut jayegi|supply.*disconnect|વીજળી કાપી નાખવામાં આવશે)\b/i, weight: 0.40, label: 'Electricity Cutoff Trigger (T)' },
        { regex: /\b(kyc expired|pan not linked|yono blocked|account freeze|atm block|ખાતું બ્લોક)\b/i, weight: 0.35, label: 'Banking KYC Suspension Trigger (T)' },
        { regex: /\b(olx payment|army officer purchase|advance token|qr scan karo receive|ઓનલાઇન વેચાણ)\b/i, weight: 0.45, label: 'Marketplace Advance Trigger (T)' }
      ],
      M: [ // Psychological Pressure Mechanism
        { regex: /\b(digital arrest|stay on video|do not disconnect|skype video call|camera band mat karo|go to private room|chupchap kamre me jao|section 91|video call band nahi|ડિજિટલ અરેસ્ટ|ફોન કાપશો નહીં|કેમેરો ચાલુ રાખો|રૂમમાં એકલા જાવ)\b/i, weight: 0.55, label: 'Digital Arrest Video Isolation Pressure (M)' },
        { regex: /\b(non bailable warrant|police team dispatched|court summons|immediate arrest|gherao|team aapke ghar|વોરંટ નીકળ્યું|ધરપકડ થશે)\b/i, weight: 0.50, label: 'Immediate Arrest Threat Pressure (M)' },
        { regex: /\b(within 15 minutes|immediate action|turant karo|samay nahi hai|last warning|aaj hi|sirf 15 minute|હમણાં જ કરો|૧૫ મિનિટમાં|આખરી ચેતવણી)\b/i, weight: 0.30, label: 'Urgent Countdown Pressure (M)' }
      ],
      E: [ // Technical Extraction Exploit
        { regex: /\b(anydesk|teamviewer|rustdesk|quicksupport|screen share|9 digit code|aapka screen|એનીડેસ્ક|સ્ક્રીન શેર|કોડ આપો)\b/i, weight: 0.60, label: 'Screen Share Remote Access Exploit (E)' },
        { regex: /\b(enter upi pin|pin daalo paise aayenge|scan qr to receive|collect request approve|પિન નાખો|QR સ્કેન કરો)\b/i, weight: 0.70, label: 'UPI PIN Inversion Exploit (E)' },
        { regex: /\b(share otp|read otp|sms code|verification password|forward message|otp bolo|ઓટીપી આપો|એસએમએસ કોડ)\b/i, weight: 0.55, label: 'OTP Extraction Exploit (E)' },
        { regex: /\b(rbi safe account|secret verification account|safe escrow|holding account|transfer funds to clear|clearance report|escrow deposit|suraksha account|સરકારી ખાતામાં ટ્રાન્સફર)\b/i, weight: 0.65, label: 'Fake Escrow Account Transfer Exploit (E)' },
        { regex: /\b(download apk|whatsapp pe file bheji|install update app|sbi rewards app|એપ ડાઉનલોડ કરો)\b/i, weight: 0.55, label: 'Malicious APK Sideloading Exploit (E)' }
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

/**
 * Multi-Agent Pipeline Coordinator
 * Coordinates Agent 1 (Sentinel), Agent 2 (Acoustic), Agent 3 (Cognitive Fusion)
 */
export async function evaluateMultiAgent({ audioB64, context = '', mime = 'audio/wav', analyzeChunkFn }) {
  const t0 = Date.now();

  // ----- AGENT 1: Sentinel Local Rule Engine (0ms, 0 tokens) -----
  const sentinel = new IndianScamRuleEngine();
  const sentinelResult = sentinel.evaluateText(context);
  const sentinelLatencyMs = Date.now() - t0;

  // ----- AGENT 2: Acoustic Perception (Gemini Multimodal) -----
  let acousticResult = null;
  try {
    acousticResult = await analyzeChunkFn({ audioB64, context, mime });
  } catch (err) {
    console.warn('[multi-agent] Agent 2 fallback:', err.message);
    acousticResult = {
      transcript: '(Acoustic agent fallback: local Sentinel analyzing context)',
      language: 'Indian Dialect',
      red_flags: [],
      evidence: [],
      risk: sentinelResult.risk,
      verdict: sentinelResult.alertLevel === 'CRITICAL_SCAM' ? 'scam' : sentinelResult.alertLevel === 'SUSPICIOUS' ? 'suspicious' : 'safe',
      reason_en: sentinelResult.upiTrap.isExploit ? sentinelResult.upiTrap.reason : (sentinelResult.matches[0] || 'Monitoring via Agent 1 Sentinel rules'),
      warning_gu: 'ચેતવણી! સંભવિત છેતરપિંડી કોલ છે, સાવધાન રહો.',
      warning_hi: 'सावधान! यह संभावित फ्रॉड कॉल है, सतर्क रहें.'
    };
  }

  // ----- AGENT 3: Cognitive Vector & Multi-Agent Fusion Engine -----
  // Also pass the freshly transcribed text from Agent 2 through Sentinel to catch immediate words
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
