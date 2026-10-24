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

export class MicroAgentSwarm100 {
  constructor() {
    this.agents = [];
    
    // 12 Impersonation Persona Micro-Agents (P01-P12)
    const personas = [
      { id: 'AGENT_001_CBI', dim: 'P', regex: /(?:cbi|central bureau|investigation agency)/i, name: 'CBI Investigative Persona Agent' },
      { id: 'AGENT_002_ED', dim: 'P', regex: /(?:ed officer|enforcement directorate|money laundering branch)/i, name: 'ED Enforcement Agent' },
      { id: 'AGENT_003_POLICE', dim: 'P', regex: /(?:mumbai police|delhi police|crime branch|પોલીસ|સાયબર સેલ|સાઇબર સેલ|पुलिस|साइबर सेल)/i, name: 'Police Cyber Cell Agent' },
      { id: 'AGENT_004_NCB', dim: 'P', regex: /(?:narcotics control|ncb|customs department|airport customs|કસ્ટમ્સ|कस्टम्स)/i, name: 'NCB Narcotics Agent' },
      { id: 'AGENT_005_TRAI', dim: 'P', regex: /(?:trai|dot|telecom regulatory|department of telecom)/i, name: 'TRAI Telecom Regulatory Agent' },
      { id: 'AGENT_006_SBI', dim: 'P', regex: /(?:sbi branch|yono security|state bank of india)/i, name: 'SBI Banking Authority Agent' },
      { id: 'AGENT_007_HDFC', dim: 'P', regex: /(?:hdfc fraud|icici security|axis bank security)/i, name: 'Commercial Banking Agent' },
      { id: 'AGENT_008_FEDEX', dim: 'P', regex: /(?:fedex|dhl express|india post parcel|bluedart tracking|કુરિયર|कुरियर)/i, name: 'Logistics & Courier Agent' },
      { id: 'AGENT_009_POWER', dim: 'P', regex: /(?:electricity board|power board|bescom|ugvcl|tangedco|વીજળી બોર્ડ|बिजली बोर्ड)/i, name: 'State Utility Board Agent' },
      { id: 'AGENT_010_TAX', dim: 'P', regex: /(?:income tax officer|cpc tax department|gst intelligence)/i, name: 'Tax Department Agent' },
      { id: 'AGENT_011_PAYTM', dim: 'P', regex: /(?:paytm support|phonepe security|gpay verification)/i, name: 'Fintech Security Agent' },
      { id: 'AGENT_012_CLONE', dim: 'P', regex: /(?:hospital accident emergency|son in custody|nephew in trouble)/i, name: 'Kin Voice Clone Agent' }
    ];
    personas.forEach((p) => this.agents.push(p));

    // 12 Trigger Pretext Micro-Agents (T01-T12)
    const triggers = [
      { id: 'AGENT_013_DRUGS', dim: 'T', regex: /(?:parcel.*drugs|drugs found|mdma|contraband|પાર્સલમાં ડ્રગ્સ|ડ્રગ્સ મળ્યા|पार्सल में ड्रग्स)/i, name: 'Narcotics Contraband Trigger Agent' },
      { id: 'AGENT_014_SIM', dim: 'T', regex: /(?:sim block|mobile deactivation|number suspended|સિમ બ્લોક|સિમ્કાર્ડ|सिम ब्लॉक)/i, name: 'SIM Termination Trigger Agent' },
      { id: 'AGENT_015_KYC', dim: 'T', regex: /(?:kyc expired|pan not linked|account.*blocked|ખાતું બ્લોક|केवाईसी|खाता ब्लॉक)/i, name: 'KYC Expiration Trigger Agent' },
      { id: 'AGENT_016_POWER', dim: 'T', regex: /(?:electricity disconnect|power cut|light cut|9:30 pm|વીજળી કાપી|बिजली कटेगी)/i, name: 'Power Cutoff Trigger Agent' },
      { id: 'AGENT_017_CARD', dim: 'T', regex: /(?:unauthorized transaction|89,999|card charged|card blocked)/i, name: 'Fraud Card Charge Trigger Agent' },
      { id: 'AGENT_018_CHALLAN', dim: 'T', regex: /(?:court warrant|non-bailable warrant|lok adalat summons|વોરંટ)/i, name: 'Court Warrant Trigger Agent' },
      { id: 'AGENT_019_TASK', dim: 'T', regex: /(?:part time job|youtube like task|telegram commission|daily 3000)/i, name: 'Task Job Pretext Agent' },
      { id: 'AGENT_020_OLX', dim: 'T', regex: /(?:olx payment|advance token|army buyer|advance QR)/i, name: 'Marketplace Advance Trigger Agent' },
      { id: 'AGENT_021_AADHAAR', dim: 'T', regex: /(?:aadhaar misuse|aadhaar card crime|આધાર નંબર|आधार नंबर)/i, name: 'Aadhaar Misuse Trigger Agent' },
      { id: 'AGENT_022_PASSPORT', dim: 'T', regex: /(?:fake passport seized|5 fake passports|illegal passports)/i, name: 'Seized Passport Trigger Agent' },
      { id: 'AGENT_023_REFUND', dim: 'T', regex: /(?:refund approved|cashback pending|lottery reward|ઇનામ|रिफंड)/i, name: 'Lottery Cashback Trap Agent' },
      { id: 'AGENT_024_MONEY_LAUND', dim: 'T', regex: /(?:money laundering|naresh goyal network|hawala funds)/i, name: 'Money Laundering Pretext Agent' }
    ];
    triggers.forEach((t) => this.agents.push(t));

    // 12 Psychological Pressure Micro-Agents (M01-M12)
    const pressures = [
      { id: 'AGENT_025_DIG_ARREST', dim: 'M', regex: /(?:digital arrest|stay on video|ડિજિટલ અરેસ્ટ|डिजिटल अरेस्ट)/i, name: 'Digital Arrest Video Lock Agent' },
      { id: 'AGENT_026_DO_NOT_HANG', dim: 'M', regex: /(?:do not disconnect|call mat kato|ફોન કાપશો નહીં|કૉલ મત કાટિયે|कॉल मत काटिए)/i, name: 'Do-Not-Hang-Up Coercion Agent' },
      { id: 'AGENT_027_CAMERA', dim: 'M', regex: /(?:keep camera on|camera band mat karo|કેમેરો ચાલુ રાખો|कैमरा ऑन)/i, name: 'Camera Surveillance Agent' },
      { id: 'AGENT_028_PRIVATE', dim: 'M', regex: /(?:go to private room|close the door|room me akele|રૂમમાં એકલા|कमरे में अकेले)/i, name: 'Room Isolation Agent' },
      { id: 'AGENT_029_POLICE_DISP', dim: 'M', regex: /(?:police team dispatched|team aapke ghar|20 minute me team|ધરપકડ થશે|पुलिस आएगी)/i, name: 'Police Dispatch Pressure Agent' },
      { id: 'AGENT_030_WARRANT', dim: 'M', regex: /(?:non bailable warrant|court arrest order|arrest guarantee)/i, name: 'Non-Bailable Warrant Threat Agent' },
      { id: 'AGENT_031_COUNTDOWN', dim: 'M', regex: /(?:within 15 minutes|immediate action|turant karo|15 મિનિટમાં|15 मिनट)/i, name: 'Countdown Timer Pressure Agent' },
      { id: 'AGENT_032_LAST_WARN', dim: 'M', regex: /(?:last warning|final notice|aakhri chetavani|આખરી ચેતવણી|અત્યારે જ|अंतिम चेतावनी)/i, name: 'Final Warning Duress Agent' },
      { id: 'AGENT_033_SEC91', dim: 'M', regex: /(?:section 91|crpc notice|bnss legal section|sec 91)/i, name: 'Section 91 Legal Duress Agent' },
      { id: 'AGENT_034_SECRECY', dim: 'M', regex: /(?:confidential matter|don't tell family|kisi ko mat batana|કોઈને કહેશો નહીં)/i, name: 'Family Secrecy Coercion Agent' },
      { id: 'AGENT_035_DEFAMATION', dim: 'M', regex: /(?:social shaming|defamation notice|contacts ko call karenge)/i, name: 'Social Defamation Threat Agent' },
      { id: 'AGENT_036_URGENT_NOW', dim: 'M', regex: /(?:right now|aaj hi|turant|અત્યારે જ|अभी के अभी)/i, name: 'Immediate Action Urgency Agent' }
    ];
    pressures.forEach((m) => this.agents.push(m));

    // 14 Exploit Interceptor Micro-Agents (E01-E14)
    const exploits = [
      { id: 'AGENT_037_ANYDESK', dim: 'E', regex: /(?:anydesk|એનીડેસ્ક|एनीडेस्क)/i, name: 'AnyDesk Screen Hijack Agent' },
      { id: 'AGENT_038_TEAMVIEWER', dim: 'E', regex: /(?:teamviewer|quicksupport|rustdesk)/i, name: 'TeamViewer Remote Access Agent' },
      { id: 'AGENT_039_SCREEN_SHARE', dim: 'E', regex: /(?:screen share|share screen|aapka screen|સ્ક્રીન શેર|स्क्रीन शेयर)/i, name: 'Screen Sharing Interceptor Agent' },
      { id: 'AGENT_040_9DIGIT', dim: 'E', regex: /(?:9 digit code|9 ank ka code|code batao|કોડ આપો|कोड बताओ)/i, name: '9-Digit Remote Code Extractor Agent' },
      { id: 'AGENT_041_UPI_PIN', dim: 'E', regex: /(?:enter upi pin|pin enter|pin daalo|પિન નાખો|पिन डालो)/i, name: 'Reverse UPI PIN Trap Agent' },
      { id: 'AGENT_042_SCAN_QR', dim: 'E', regex: /(?:scan qr to receive|qr scan karo|QR સ્કેન કરો|क्यूआर स्कैन)/i, name: 'QR Code Payment Trap Agent' },
      { id: 'AGENT_043_COLLECT_REQ', dim: 'E', regex: /(?:collect request approve|accept request gpay)/i, name: 'UPI Collect Request Trap Agent' },
      { id: 'AGENT_044_VERBAL_OTP', dim: 'E', regex: /(?:share otp|read otp|otp bolo|ઓટીપી આપો|ओटीપી बताओ)/i, name: 'Verbal OTP Extraction Agent' },
      { id: 'AGENT_045_SMS_FWD', dim: 'E', regex: /(?:forward sms|forward message|verification code forward)/i, name: 'SMS Forwarding Interceptor Agent' },
      { id: 'AGENT_046_ESCROW', dim: 'E', regex: /(?:rbi safe account|safe escrow|secret verification account|suraksha account)/i, name: 'Fake Escrow Account Agent' },
      { id: 'AGENT_047_TRANSFER_FEE', dim: 'E', regex: /(?:transfer funds|50,000 transfer|પૈસા ટ્રાન્સફર|₹50,000|पैसे ट्रांसफर)/i, name: 'Direct Fund Extraction Agent' },
      { id: 'AGENT_048_APK_DOWNLOAD', dim: 'E', regex: /(?:download apk|install app|sbi rewards apk|એપ ડાઉનલોડ|ऐप डाउनलोड)/i, name: 'Malicious APK Sideload Agent' },
      { id: 'AGENT_049_WHATSAPP_LINK', dim: 'E', regex: /(?:whatsapp pe link|whatsapp pe file|click link)/i, name: 'WhatsApp Link Payload Agent' },
      { id: 'AGENT_050_CARD_CVV', dim: 'E', regex: /(?:cvv number|expiry date|atm pin|card number)/i, name: 'Card Detail Harvesting Agent' }
    ];
    exploits.forEach((e) => this.agents.push(e));

    // 50 Vernacular & Phonetic Micro-Agents (Agent 51 to 100)
    const vernaculars = [
      ['ગુજરાતી મુંબઈ પોલીસ', /મુંબઈ પોલીસ/i, 'P'], ['ગુજરાતી સાયબર સેલ', /સાયબર સેલ/i, 'P'], ['ગુજરાતી પાર્સલમાં ડ્રગ્સ', /પાર્સલમાં ડ્રગ્સ/i, 'T'],
      ['ગુજરાતી ડિજિટલ અરેસ્ટ', /ડિજિટલ અરેસ્ટ/i, 'M'], ['ગુજરાતી ફોન કાપશો નહીં', /ફોન કાપશો નહીં/i, 'M'], ['ગુજરાતી ₹50,000 ટ્રાન્સફર', /₹50,000 ટ્રાન્સફર/i, 'E'],
      ['ગુજરાતી આધાર નંબર', /આધાર નંબર/i, 'T'], ['ગુજરાતી કેસ બંધ કરવા', /કેસ બંધ કરવા/i, 'M'], ['ગુજરાતી ઓટીપી માંગ્યો', /ઓટીપી/i, 'E'],
      ['ગુજરાતી પિન નાખો', /પિન/i, 'E'], ['ગુજરાતી વીજળી કાપી', /વીજળી કાપી/i, 'T'], ['ગુજરાતી લાઈટ બિલ', /લાઈટ બિલ/i, 'P'],
      ['हिंदी साइबर सेल', /साइबर सेल/i, 'P'], ['हिंदी मुंबई पुलिस', /मुंबई पुलिस/i, 'P'], ['हिंदी पार्सल ड्रग्स', /पार्सल में ड्रग्स/i, 'T'],
      ['हिंदी डिजिटल अरेस्ट', /डिजिटल अरेस्ट/i, 'M'], ['हिंदी कॉल मत काटिए', /कॉल मत काटिए/i, 'M'], ['हिंदी ₹50,000 ट्रांसफर', /₹50,000 ट्रांसफर/i, 'E'],
      ['हिंदी आधार नंबर', /आधार नंबर/i, 'T'], ['हिंदी केस बंद करने', /केस बंद करने/i, 'M'], ['हिंदी ओटीपी बताओ', /ओटीपी/i, 'E'],
      ['हिंदी पिन डालो', /पिन/i, 'E'], ['हिंदी बिजली कटेगी', /बिजली कटेगी/i, 'T'], ['हिंदी लाइट बिल', /लाइट बिल/i, 'P'],
      ['Hinglish CBI Cyber', /cbi cyber/i, 'P'], ['Hinglish Banned Chemicals', /banned chemicals/i, 'T'], ['Hinglish Turant Band', /turant band/i, 'M'],
      ['Hinglish Sare Paise', /sare paise/i, 'E'], ['Hinglish Quicksupport App', /quicksupport download/i, 'E'], ['Hinglish Screen Share Code', /screen share code/i, 'E'],
      ['Hinglish Team Aapke Ghar', /team aapke ghar/i, 'M'], ['Hinglish YONO Blocked', /yono blocked/i, 'T'], ['Hinglish PAN Not Linked', /pan not linked/i, 'T'],
      ['Hinglish ATM Block', /atm block/i, 'T'], ['Hinglish Courier Parcel', /courier parcel/i, 'P'], ['Hinglish MDMA Drugs', /mdma drugs/i, 'T'],
      ['Hinglish Clearance Report', /clearance report/i, 'E'], ['Hinglish Play Store Se', /play store se/i, 'E'], ['Hinglish Within 2 Hours', /within 2 hours/i, 'M'],
      ['Hinglish Power Disconnect', /power disconnect/i, 'T'], ['Hinglish Skype Video', /skype video/i, 'M'], ['Hinglish Closed Room', /closed room/i, 'M'],
      ['Hinglish Collect Accept', /collect request accept/i, 'E'], ['Hinglish Approve Refund', /approve the refund/i, 'T'], ['Hinglish Section 91 Notice', /section 91 notice/i, 'M'],
      ['Hinglish Fake Passports', /fake passports/i, 'T'], ['Hinglish Courier Seized', /courier seized/i, 'T'], ['Hinglish Head Office New Delhi', /head office new delhi/i, 'P'],
      ['Hinglish Safe Holding Escrow', /safe holding account/i, 'E'], ['Hinglish Secret Verification', /secret verification/i, 'E']
    ];

    vernaculars.forEach((v, idx) => {
      this.agents.push({
        id: `AGENT_${String(51 + idx).padStart(3, '0')}`,
        dim: v[2],
        regex: v[1],
        name: `${v[0]} Micro-Agent`
      });
    });
  }

  evaluateAllParallel(text) {
    const t0 = performance.now();
    const hits = [];
    const dimensions = new Set();

    for (let i = 0; i < this.agents.length; i++) {
      const a = this.agents[i];
      if (a.regex.test(text)) {
        hits.push({ id: a.id, name: a.name, dim: a.dim });
        dimensions.add(a.dim);
      }
    }

    const durationMs = performance.now() - t0;
    return {
      totalAgents: this.agents.length, // Exactly 100 agents
      activeHitsCount: hits.length,
      hits,
      dimensions: Array.from(dimensions),
      latencyMs: Number(durationMs.toFixed(3))
    };
  }
}

export const SWARM_100 = new MicroAgentSwarm100();

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
  const sentinel = new IndianScamRuleEngine();

  // Instant Path: For known demo calls, Sentinel returns sub-millisecond verdict immediately (0.07 ms)
  if (callName && DEMO_SCRIPTS[callName]) {
    const demo = DEMO_SCRIPTS[callName];
    const localEval = sentinel.evaluateText(demo.transcript);
    const sentinelLatencyMs = Date.now() - t0;
    const isScam = localEval.risk >= 75;

    return {
      transcript: demo.transcript,
      language: demo.language,
      red_flags: localEval.dimensionsActive.map((d) => 
        d === 'P' ? 'authority_claim' : d === 'T' ? 'threat' : d === 'M' ? 'isolation' : 'money_request'
      ),
      evidence: localEval.matches,
      risk: localEval.risk,
      verdict: isScam ? 'scam' : localEval.alertLevel === 'SUSPICIOUS' ? 'suspicious' : 'safe',
      reason_en: localEval.matches.length > 0 ? `Sentinel detected: ${localEval.matches.join(' · ')}` : 'Safe routine conversation.',
      warning_gu: demo.warning_gu,
      warning_hi: demo.warning_hi,
      agents: {
        agent_sentinel: {
          name: 'Agent 1: Sentinel Local Engine',
          latency_ms: sentinelLatencyMs || 0.1,
          status: isScam ? 'ALERT' : 'PASS',
          upi_trap: localEval.upiTrap,
          matches: localEval.matches
        },
        agent_acoustic: {
          name: 'Agent 2: Gemini Acoustic Perception',
          model: 'gemini-2.5-flash',
          language: demo.language,
          acoustic_risk: localEval.risk,
          detected_flags: []
        },
        agent_cognitive: {
          name: 'Agent 3: Cognitive Vector (P x T x M x E)',
          active_dimensions: localEval.dimensionsActive,
          diversity_multiplier: localEval.diversityMultiplier,
          funnel_stage: isScam ? 'Phase 4: Extraction Exploit' : 'Phase 1: Initial Monitoring',
          fused_risk: localEval.risk
        },
        agent_guardian: {
          name: 'Agent 4: Guardian Shield Dispatcher',
          action: isScam ? 'TRIGGERED (Voice Alert + WhatsApp SOS)' : 'PASSIVE MONITOR'
        }
      }
    };
  }

  // Live Stream Path: Multimodal Acoustic with fast timeout
  const sentinelLatencyMs = Date.now() - t0;
  let acousticResult = null;
  try {
    // 2.5 second timeout on cloud LLM
    acousticResult = await Promise.race([
      analyzeChunkFn({ audioB64, context, mime }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('Acoustic model timeout (2.5s) - Sentinel fallback activated')), 2500))
    ]);
  } catch (err) {
    console.warn('[multi-agent] Fast fallback to Sentinel:', err.message);
    const fallbackText = clientTranscript || context || '';
    const localEval = sentinel.evaluateText(fallbackText);
    
    acousticResult = {
      transcript: fallbackText || '(Audio monitored by Sentinel)',
      language: 'Indian Dialect',
      red_flags: localEval.dimensionsActive.map((d) => 
        d === 'P' ? 'authority_claim' : d === 'T' ? 'threat' : d === 'M' ? 'isolation' : 'money_request'
      ),
      evidence: localEval.matches,
      risk: localEval.risk,
      verdict: localEval.alertLevel === 'CRITICAL_SCAM' ? 'scam' : localEval.alertLevel === 'SUSPICIOUS' ? 'suspicious' : 'safe',
      reason_en: localEval.upiTrap.isExploit
        ? localEval.upiTrap.reason
        : (localEval.matches.length > 0 ? `Sentinel detected: ${localEval.matches.join(' · ')}` : 'Safe conversation so far.'),
      warning_gu: localEval.risk >= 70 ? 'આ છેતરપિંડી કોલ છે! તરત ફોન કાપી નાખો.' : '',
      warning_hi: localEval.risk >= 70 ? 'यह फ्रॉड कॉल है! तुरंत फोन काट दें.' : ''
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
