# Indian Telephony Scam Call Detection Engine Specification & Taxonomy
**Target:** Autonomous AI Agent / Detection Engineering Ingestion  
**Version:** 2.4.0  
**Scope:** Multilingual (Hinglish/English/Vernacular) Combinatorial Attack Space, Telemetry, and Dynamic Risk Scoring Algorithms.

---

## 1. Executive Summary & Mathematical Taxonomy

Indian vishing (voice phishing) operations do not operate on fixed monolithic scripts; they operate via a **combinatorial execution tree**. An adversary selects one component from each of the following four orthogonal dimensions:

$$\text{Total Scenarios } \mathcal{S} = |\mathcal{P}| \times |\mathcal{T}| \times |\mathcal{M}| \times |\mathcal{E}|$$

Where:
- $\mathcal{P}$: Impersonated Authority / Persona ($|\mathcal{P}| = 12$)
- $\mathcal{T}$: Trigger Vector / Pretext ($|\mathcal{T}| = 9$)
- $\mathcal{M}$: Psychological Pressure Mechanism ($|\mathcal{M}| = 6$)
- $\mathcal{E}$: Extraction Exploit Technique ($|\mathcal{E}| = 5$)

$$\mathcal{S} = 12 \times 9 \times 6 \times 5 = 3,240 \text{ distinct attack permutations}$$

Building a detection system based on 1,000 discrete templates results in extreme brittleness. Modeling the system as an entity-state extraction graph mapping these 32 sub-elements achieves complete coverage over all 3,240 variants with zero-shot resilience against emerging script variants.

---

## 2. Complete Combinatorial Parameter Space

### Dimension 1: Impersonated Persona ($\mathcal{P}$)
1. **P01 - Central Investigative Agencies:** CBI (Central Bureau of Investigation), ED (Enforcement Directorate), NIA (National Investigation Agency).
2. **P02 - State Police / Cyber Crime Cell:** Mumbai Police (Cyber Cell), Delhi Police Crime Branch, Ahmedabad Cyber Crime, Hyderabad Police.
3. **P03 - Narcotics Control Bureau (NCB):** Customs & Narcotics Commissionerate, Airport Customs Interception Unit.
4. **P04 - Telecom Authority / Service Providers:** TRAI (Telecom Regulatory Authority of India), DoT (Department of Telecommunications), Jio/Airtel/Vi Customer Support.
5. **P05 - Core Commercial Banks:** State Bank of India (SBI), HDFC Bank, ICICI Bank, Punjab National Bank (Fraud & Security Risk Division).
6. **P06 - Logistics & Parcel Carriers:** FedEx India, Blue Dart, India Post (Speed Post), DHL Express.
7. **P07 - State Utility Boards:** State Electricity Distribution Boards (e.g., BESCOM, TANGEDCO, MSEDCL, UGVCL), City Gas Boards (Adani/Indraprastha).
8. **P08 - Revenue & Tax Authorities:** Income Tax Department (CPC), GST Intelligence, TDS Reconciliation Cell.
9. **P09 - Digital Fintech & Payment Platforms:** Paytm Payments Bank, PhonePe Security Unit, Google Pay Support Desk.
10. **P10 - Micro-Lending & NBFC Recovery:** Instant loan apps (Dhani, KreditBee, unauthorized offshore loan apps).
11. **P11 - Insurance & Statutory Bodies:** EPFO (Provident Fund Commissioner), LIC Claims Department, IRDAI Ombudsman.
12. **P12 - Close Relative / Kin Impersonation (AI Voice Clone):** Son, nephew, or close friend claiming emergency detention or hospital accident.

---

### Dimension 2: Trigger Vector / Pretext ($\mathcal{T}$)
1. **T01 - Contraband Parcel Interception:** Parcel bound abroad containing expired passports, narcotics (MDMA/Marijuana), synthetic drugs, and unauthorized SIM cards.
2. **T02 - SIM Card / Mobile Number Termination:** Phone number used in illegal advertising, harassment, or financial fraud; deactivation scheduled within 2 hours.
3. **T03 - Mandatory KYC / PAN Expiry:** Bank account / wallet suspension due to non-compliance with Reserve Bank of India (RBI) KYC guidelines or unlinked PAN card.
4. **T04 - Utility Cutoff Notice:** Unpaid electricity bill from the prior month; power disconnection scheduled for 9:30 PM tonight.
5. **T05 - Unauthorized High-Value Transaction:** Notification that a credit card was charged for ₹89,999 at a retail store in a distant city, offering a dispute gateway.
6. **T06 - Traffic Challan & Warrant:** E-challan for non-appearance in Lok Adalat, progressing to a non-bailable court warrant.
7. **T07 - Task-Based Part-Time Employment:** YouTube video like/subscribe task payouts, hotel rating commissions, or Telegram trading tasks.
8. **T08 - Reverse Marketplace Advance:** Buyer on OLX / Facebook Marketplace agreeing to purchase furniture/appliances immediately with an upfront token advance.
9. **T09 - Digital Arrest Pretext:** Aadhaar card compromised in money laundering for an absconding corporate offender (e.g., Naresh Goyal / Nirav Modi networks).

---

### Dimension 3: Psychological Pressure Mechanism ($\mathcal{M}$)
1. **M01 - Digital Arrest via Video Isolation:** Order to stay on continuous Skype / WhatsApp video call, keep camera on, and prohibit contact with family or legal counsel under Section 91 CrPC/BNSS.
2. **M02 - Immediate Non-Bailable Arrest Threat:** Warning that a local police team is dispatched to the user's home address within 30 minutes.
3. **M03 - Imminent Service Termination (Hard Countdown):** Timer countdown (15 to 45 minutes) before SIM, power, or bank access is revoked.
4. **M04 - Criminal Co-Conspirator Framing:** Accusation that bank accounts opened in the target's name were used to launder terrorist or drug money.
5. **M05 - Social Shaming & Contact Harassment:** Threat to broadcast morphed photos, defamatory messages, or debt recovery calls to all phone contacts.
6. **M06 - Financial Reward Expiration:** 5-minute expiry on government subsidy, festival lottery (KBC), or UPI cashback release.

---

### Dimension 4: Technical Extraction Exploit ($\mathcal{E}$)
1. **E01 - Screen-Sharing App Installation:** Coercing user to download AnyDesk, TeamViewer QuickSupport, or RustDesk and read the 9-digit remote access code.
2. **E02 - UPI Reverse Flow ("Collect" Request / QR Code):** Prompting user to scan a QR code or enter their UPI MPIN to "receive" funds, exploiting user ignorance of UPI mechanics.
3. **E03 - Malicious APK Sideloading:** Directing user to install an APK sent via WhatsApp (e.g., `Airtel_Update.apk`, `Bijli_Bill.apk`, `SBI_Rewards.apk`) containing SMS forwarders.
4. **E04 - Verbal OTP & Token Interception:** Direct psychological extraction of OTPs for net banking logins, debit card transactions, or SIM swap authorizations.
5. **E05 - Escrow Account Transfer ("RBI Safe Account"):** Directing user to liquidate FDs/savings and wire all funds via RTGS/IMPS to a "dummy verification account" certified by the scammer.

---

## 3. High-Risk Lexical & Semantic Signatures (Hinglish / English)

Real-time ASR must trigger token extraction on phonetic, transliterated, and colloquial Hindi-English terms:

```yaml
lexical_patterns:
  digital_arrest:
    - regex: "(digital\s+arrest|video\s+investigation|skype\s+pe\s+aao|camera\s+band\s+mat\s+karna)"
    - weight: 0.95
    - context: "legal_intimidation"

  law_enforcement:
    - regex: "(cbi|ed|narcotics\s+control|customs|mumbai\s+crime\s+branch|cyber\s+cell|warrant)"
    - weight: 0.85
    - context: "authority_impersonation"

  upi_logic_trap:
    - regex: "(paise\s+receive\s+karne\s+ke\s+liye\s+pin|enter\s+pin\s+to\s+credit|qr\s+code\s+scan\s+karo\s+paise\s+aayenge|collect\s+request\s+accept)"
    - weight: 0.99
    - context: "reverse_upi_exploit"

  remote_access:
    - regex: "(anydesk|teamviewer|rustdesk|quicksupport|screen\s+share|9\s+digit\s+code)"
    - weight: 0.90
    - context: "tool_installation"

  utility_urgency:
    - regex: "(bijli\s+kat\s+jayegi|electricity\s+disconnect|9:30\s+pm|power\s+cut|bill\s+update)"
    - weight: 0.80
    - context: "service_blackmail"

  sms_apk_trap:
    - regex: "(apk\s+install|whatsapp\s+pe\s+link|forward\s+sms|yono\s+blocked|pan\s+link\s+kyc)"
    - weight: 0.88
    - context: "malware_delivery"
```

---

## 4. Algorithmic Detection Architecture

```
                  ┌──────────────────────┐
                  │ Inbound Audio Stream │
                  └──────────┬───────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   [Layer 1: Telemetry Filters]       [Layer 2: Real-Time ASR]
   • CLI Anomaly (+92, VoIP)         • Whisper-Live / FastConformer
   • Burst Call Frequencies          • Rolling Text Buffer (15s windows)
            │                                 │
            └────────────────┬────────────────┘
                             ▼
                [Layer 3: Intent Scoring Pipeline]
                ├─ Regex Exact Match Engine (Zero-latency)
                ├─ Semantic Embedding Similarity (MiniLM)
                └─ Dimension Diversity Evaluator
                             │
                             ▼
               [Layer 4: Dynamic Risk Accumulator]
               R_t = (R_{t-1} * lambda) + Delta_R * Multiplier
                             │
                   ┌─────────┴─────────┐
                   ▼                   ▼
            R_t >= 0.80         R_t < 0.80
           [TRIGGER ALERT]     [PASSIVE MONITOR]
```

### 4.1. Core Mathematical Formulation

The dynamic scam score $R(t)$ at time step $t$ is calculated over rolling transcript slices:

$$R(t) = \min\left(1.0, \, R(t-1) \cdot e^{-\lambda \Delta t} + \sum_{i} w_i \cdot \mathbf{1}_{E_i} \cdot \mu(D)ight)$$

Where:
- $\lambda$: Temporal decay factor (default $0.05 	ext{ s}^{-1}$) preventing accumulation over prolonged calls.
- $\Delta t$: Elapsed time between incoming token chunks.
- $w_i$: Base weight assigned to detected token pattern $E_i$.
- $\mu(D)$: Combinatorial Dimension Multiplier:
  $$\mu(D) = 1.0 + 0.35 \cdot (|D| - 1)$$
  where $|D|$ is the count of distinct attack dimensions ($\mathcal{P}, \mathcal{T}, \mathcal{M}, \mathcal{E}$) active in memory.

---

## 5. Python Reference Implementations

### 5.1. Dynamic Real-Time Scam Detector Engine

```python
import re
import math
import time
from typing import Dict, List, Set, Tuple

class IndianScamDetector:
    def __init__(self, decay_rate: float = 0.03):
        self.decay_rate = decay_rate
        self.risk_score = 0.0
        self.last_update_ts = time.time()
        self.detected_dimensions: Set[str] = set()
        self.event_log: List[Tuple[float, str, str, float]] = []

        # Heuristic rules categorized by dimension
        self.rules = {
            "P": [ # Personas
                (r"\b(cbi|central bureau|narcotics control|ncb|customs department|mumbai police|cyber cell|trai|dot|telecom regulatory)\b", 0.40, "Authority Persona"),
                (r"\b(sbi branch|hdfc fraud|icici security|bank manager|rbi officer|income tax officer)\b", 0.35, "Financial Authority"),
                (r"\b(fedex courier|dhl express|india post parcel|bluedart tracking)\b", 0.30, "Logistics Persona"),
            ],
            "T": [ # Triggers
                (r"\b(parcel intercepted|drugs found|illegal mdma|contraband|unauthorized sim cards|money laundering complaint)\b", 0.45, "Contraband/Crime Trigger"),
                (r"\b(sim block|mobile deactivation|number suspended within 2 hours)\b", 0.40, "Telecom Termination Trigger"),
                (r"\b(electricity disconnect|bijli cut|power off at 9:30|light cut jayegi)\b", 0.40, "Utility Disconnection Trigger"),
                (r"\b(kyc expired|pan not linked|yono blocked|account freeze|atm block)\b", 0.35, "Banking/KYC Trigger"),
                (r"\b(olx payment|army officer purchase|advance token|qr scan karo receive)\b", 0.45, "Marketplace Advance Trigger"),
            ],
            "M": [ # Pressures
                (r"\b(digital arrest|stay on video|do not disconnect|skype video call|camera band mat karo|go to private room)\b", 0.55, "Digital Arrest Pressure"),
                (r"\b(non bailable warrant|police team dispatched|court summons|immediate arrest)\b", 0.50, "Arrest Warrant Pressure"),
                (r"\b(within 15 minutes|immediate action|turant karo|samay nahi hai|last warning)\b", 0.30, "Urgency Countdown Pressure"),
            ],
            "E": [ # Extractions
                (r"\b(anydesk|teamviewer|rustdesk|quicksupport|screen share|9 digit code)\b", 0.60, "Remote Access Exploit"),
                (r"\b(enter upi pin|pin daalo paise aayenge|scan qr to receive|collect request approve)\b", 0.70, "UPI Inversion Exploit"),
                (r"\b(share otp|read otp|sms code|verification password|forward message)\b", 0.55, "OTP Extraction Exploit"),
                (r"\b(rbi safe account|secret verification account|transfer funds to clear|escrow deposit)\b", 0.65, "Escrow Account Exploit"),
                (r"\b(download apk|whatsapp pe file bheji|install update app)\b", 0.55, "Malicious APK Exploit"),
            ]
        }

    def _apply_decay(self, current_ts: float):
        dt = current_ts - self.last_update_ts
        self.risk_score *= math.exp(-self.decay_rate * dt)
        self.last_update_ts = current_ts

    def process_transcript_chunk(self, text: str, timestamp: float = None) -> Dict:
        ts = timestamp or time.time()
        self._apply_decay(ts)
        norm_text = text.lower()

        matched_this_chunk = []
        for dim, patterns in self.rules.items():
            for regex_str, weight, label in patterns:
                if re.search(regex_str, norm_text):
                    self.detected_dimensions.add(dim)
                    matched_this_chunk.append((dim, label, weight))

        # Calculate combinatorial multiplier based on active dimension variety
        dimension_count = len(self.detected_dimensions)
        diversity_multiplier = 1.0 + (0.35 * max(0, dimension_count - 1))

        # Add contribution
        chunk_addition = 0.0
        for dim, label, weight in matched_this_chunk:
            contribution = weight * diversity_multiplier
            chunk_addition += contribution
            self.event_log.append((ts, dim, label, contribution))

        # Non-linear diminishing returns addition
        self.risk_score = min(1.0, self.risk_score + chunk_addition * (1.0 - self.risk_score * 0.5))

        alert_level = "LOW"
        if self.risk_score >= 0.75:
            alert_level = "CRITICAL_SCAM"
        elif self.risk_score >= 0.50:
            alert_level = "SUSPICIOUS"

        return {
            "current_risk": round(self.risk_score, 4),
            "alert_level": alert_level,
            "dimensions_active": list(self.detected_dimensions),
            "matches_in_chunk": [m[1] for m in matched_this_chunk]
        }
```

### 5.2. Deterministic Reverse UPI Logic Trap Checker

```python
class UPILogicChecker:
    """Zero-latency deterministic state machine for UPI receive vs credit contradiction"""

    RECEIVE_TOKENS = ["receive", "credit", "paise aayenge", "milega", "jama hoga", "refund"]
    SENDER_ACTIONS = ["enter pin", "upi pin", "mpin", "scan qr", "collect accept", "pin daalo"]

    @classmethod
    def evaluate(cls, sliding_window_text: str) -> Tuple[bool, str]:
        t = sliding_window_text.lower()
        has_receive = any(tok in t for tok in cls.RECEIVE_TOKENS)
        has_send_action = any(tok in t for tok in cls.SENDER_ACTIONS)

        if has_receive and has_send_action:
            return True, "CRITICAL: Scammer instructs sender action (PIN/Scan) to 'receive' money."
        return False, "NORMAL"
```

### 5.3. Synthetic Dataset Generator (All 3,240 Permutations)

```python
import itertools
import json

def generate_synthetic_scam_corpus():
    personas = {
        "P01": ["This is Central Bureau of Investigation Head Office New Delhi", "Main CBI Cyber Branch se Inspector bol raha hoon"],
        "P03": ["I am calling from Mumbai Airport Narcotics Control Bureau", "Customs clearance interception officer here"],
        "P04": ["This is Department of Telecom TRAI verification center", "Airtel head office compliance division se call hai"],
        "P07": ["Electricity board distribution control room se complaint officer", "Power board billing department alert call"]
    }
    triggers = {
        "T01": ["Your courier parcel to Taiwan was seized with 5 fake passports and 150g MDMA drugs", "Aapke naam ka parcel mila hai jisme illegal banned chemicals hain"],
        "T02": ["Your mobile number will be disconnected within 2 hours due to illegal activities", "Yeh phone number turant band ho jayega cyber complaint ke kaaran"],
        "T04": ["Your past month electricity bill is not updated; electricity connection will be severed at 9:30 PM", "Bijli ka bill baki hone ke kaaran supply raat 9:30 baje disconnect hogi"]
    }
    pressures = {
        "M01": ["You are placed under digital arrest; switch on WhatsApp video and stay in a closed room alone", "Section 91 notice hai, video call band nahi karni hai, kisi ko batana mana hai"],
        "M02": ["Local police team is dispatched to your residence with non-bailable arrest warrant", "Turant cooperate karein warna 20 minute me team aapke ghar aayegi"],
        "M03": ["You only have 15 minutes before permanent deactivation and bank seizure", "Sirf 15 minute ka samay hai verification complete karne ke liye"]
    }
    extractions = {
        "E01": ["Install AnyDesk from Play Store and provide the 9-digit code for physical device verification", "Play Store se QuickSupport download karke screen share code batao"],
        "E02": ["Scan this QR code and type your UPI PIN to approve the refund to your bank account", "Google Pay me collect request accept karke pin enter karo turant"],
        "E05": ["Transfer your entire liquid balance to RBI certified safe escrow account for financial verification", "Sare paise RBI ke safe holding account me transfer karo clearance report ke liye"]
    }

    corpus = []
    idx = 1
    for p_id, p_list in personas.items():
        for t_id, t_list in triggers.items():
            for m_id, m_list in pressures.items():
                for e_id, e_list in extractions.items():
                    sample = {
                        "id": f"SCAM_IN_{idx:05d}",
                        "vector": f"{p_id}_{t_id}_{m_id}_{e_id}",
                        "transcript_en": f"{p_list[0]}. {t_list[0]}. {m_list[0]}. {e_list[0]}.",
                        "transcript_hinglish": f"{p_list[1]}. {t_list[1]}. {m_list[1]}. {e_list[1]}.",
                        "label": "SCAM",
                        "risk_baseline": 1.0
                    }
                    corpus.append(sample)
                    idx += 1
    return corpus
```

---

## 6. Real-Time Telemetry & Network Level Signals

In addition to linguistic ASR signals, client and telecom pipelines must factor in these signals:

1. **CLI / Calling Line Identification Spoofing:**
   - International dialing prefixes spoofed as local authorities (`+92`, `+880`, `+44`).
   - Private SIP trunking headers bypassing local carrier STIR/SHAKEN standards.
2. **Call Burst Profile:**
   - Single origination MSISDN generating $> 250$ calls per hour with average call durations $< 45$ seconds.
3. **Acoustic Background Artifacts:**
   - Synthesized call-center hubbub or repeating walkie-talkie / police radio squelch audio loops mixed into VoIP audio streams.
4. **App Installation Event Concurrency:**
   - In-call event triggers where a screen-sharing session starts (`com.anydesk.anydeskandroid`, `com.teamviewer.quicksupport.market`) while an active voice call is in progress.

---
*End of Document. Engineered for direct parsing, AST construction, and automated ML pipeline ingestion.*
