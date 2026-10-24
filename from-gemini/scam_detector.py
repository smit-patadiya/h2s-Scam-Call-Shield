"""
Indian Telephony Scam Detection Reference Engine
"""
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

        self.rules = {
            "P": [  # Personas
                (r"\b(cbi|central bureau|narcotics control|ncb|customs department|mumbai police|cyber cell|trai|dot|telecom regulatory)\b", 0.40, "Authority Persona"),
                (r"\b(sbi branch|hdfc fraud|icici security|bank manager|rbi officer|income tax officer)\b", 0.35, "Financial Authority"),
                (r"\b(fedex courier|dhl express|india post parcel|bluedart tracking)\b", 0.30, "Logistics Persona"),
            ],
            "T": [  # Triggers
                (r"\b(parcel intercepted|drugs found|illegal mdma|contraband|unauthorized sim cards|money laundering complaint)\b", 0.45, "Contraband/Crime Trigger"),
                (r"\b(sim block|mobile deactivation|number suspended within 2 hours)\b", 0.40, "Telecom Termination Trigger"),
                (r"\b(electricity disconnect|bijli cut|power off at 9:30|light cut jayegi)\b", 0.40, "Utility Disconnection Trigger"),
                (r"\b(kyc expired|pan not linked|yono blocked|account freeze|atm block)\b", 0.35, "Banking/KYC Trigger"),
                (r"\b(olx payment|army officer purchase|advance token|qr scan karo receive)\b", 0.45, "Marketplace Advance Trigger"),
            ],
            "M": [  # Pressures
                (r"\b(digital arrest|stay on video|do not disconnect|skype video call|camera band mat karo|go to private room)\b", 0.55, "Digital Arrest Pressure"),
                (r"\b(non bailable warrant|police team dispatched|court summons|immediate arrest)\b", 0.50, "Arrest Warrant Pressure"),
                (r"\b(within 15 minutes|immediate action|turant karo|samay nahi hai|last warning)\b", 0.30, "Urgency Countdown Pressure"),
            ],
            "E": [  # Extractions
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

        dimension_count = len(self.detected_dimensions)
        diversity_multiplier = 1.0 + (0.35 * max(0, dimension_count - 1))

        chunk_addition = 0.0
        for dim, label, weight in matched_this_chunk:
            contribution = weight * diversity_multiplier
            chunk_addition += contribution
            self.event_log.append((ts, dim, label, contribution))

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

if __name__ == "__main__":
    detector = IndianScamDetector()
    sample_text = "I am calling from Mumbai Cyber Crime Branch. We found drugs under your name. Come on Skype video call right now."
    res = detector.process_transcript_chunk(sample_text)
    print("Test Detection Result:", res)
