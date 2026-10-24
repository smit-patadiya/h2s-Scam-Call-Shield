# 🛡️ Scam Call Shield · Multi-Agent AI Guardian for India

[![Benchmark Accuracy](https://img.shields.io/badge/Accuracy-100%25-brightgreen)](scripts/benchmark-accuracy.mjs)
[![Latency](https://img.shields.io/badge/Sentinel%20Latency-0.071ms-blue)](scripts/benchmark-accuracy.mjs)
[![Cloud Run Ready](https://img.shields.io/badge/Google%20Cloud%20Run-Ready-orange)](Dockerfile)
[![Languages](https://img.shields.io/badge/Languages-Gujarati%20%7C%20Hindi%20%7C%20English-purple)]()

> **Real-time elder-friendly telephony scam guardian** designed specifically for Indian voice fraud patterns (Digital Arrest, fake CBI/Police, KYC expiry, power cut threats, and reverse UPI traps).

---

## ⚡ Multi-Agent Swarm Architecture

Rather than relying on a single slow cloud model, Scam Call Shield operates a **4-Agent Swarm**:

```
                       ┌─────────────────────────┐
                       │ Inbound Live/File Audio │
                       └────────────┬────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌───────────────────────────┐                     ┌───────────────────────────┐
│   AGENT 1: Sentinel       │                     │  AGENT 2: Acoustic Audio  │
│  • Zero-latency local     │                     │  • Gemini 2.5 Flash       │
│  • UPILogicChecker        │                     │  • Tone & cadence audit   │
│  • Fast Regex Token Match │                     │  • Multilingual ASR       │
│  (0.07ms latency, $0 cost)│                     │  (Gujarati/Hindi/English) │
└─────────────┬─────────────┘                     └─────────────┬─────────────┘
              │                                                 │
              └─────────────────────┬───────────────────────────┘
                                    ▼
                     ┌─────────────────────────────┐
                     │   AGENT 3: Cognitive Vector │
                     │  • P x T x M x E Matrix     │
                     │  • Funnel tracker (Trust -> │
                     │    Fear -> Isolation -> Pin)│
                     │  • Diversity μ(D) multiplier│
                     └──────────────┬──────────────┘
                                    ▼
                     ┌─────────────────────────────┐
                     │   AGENT 4: Guardian Shield  │
                     │  • Spoken Gujarati/Hindi TTS│
                     │  • WhatsApp Family SOS      │
                     │  • Auto Fraud DB Registry   │
                     └─────────────────────────────┘
```

1. **Agent 1: Sentinel Engine (Local Rule & Reverse UPI Logic)**:
   - Detects structural mathematical traps (e.g. `UPILogicChecker`: entering a UPI PIN to "receive" money) in **0.071 ms** with **0 API tokens**.
2. **Agent 2: Acoustic Perception (Gemini 2.5 Flash Multimodal)**:
   - Listens to raw speech audio, background boiler-room noise, aggressive pacing, and dialect nuances.
3. **Agent 3: Cognitive Matrix ($P \times T \times M \times E$)**:
   - Tracks 4 orthogonal dimensions (Persona, Trigger, Pressure, Extraction) across 3,240 combinations and applies non-linear diversity scaling: $\mu(D) = 1.0 + 0.35 \times (|D| - 1)$.
4. **Agent 4: Guardian Action Dispatcher**:
   - Speaks an instant emergency warning in the elder's native language (*"આ નકલી પોલીસ કોલ છે! તરત ફોન કાપો / तुरंत फोन काट दें"*), alerts designated family contacts via WhatsApp, and logs caller numbers to the blacklist database.

---

## 📊 Benchmark Accuracy Results

Tested against 114 permutations from [`from-gemini/sample_scam_corpus.json`](from-gemini/sample_scam_corpus.json) and genuine negative control calls:

| Metric | Result |
| :--- | :--- |
| **Total Test Samples** | 114 calls |
| **Scams Caught (True Positives)** | **108 / 108 (100.0%)** |
| **Genuine Calls Cleared (True Negatives)** | **6 / 6 (100.0%)** |
| **False Positives (False Alarms)** | **0** |
| **Overall Accuracy** | **100.00%** |
| **Precision** | **100.00%** |
| **Recall** | **100.00%** |
| **F1 Score** | **100.00%** |
| **Average Sentinel Latency** | **0.071 ms** |
| **Sentinel Token Usage** | **0 tokens ($0.00 cost)** |

To re-run the benchmark suite:
```bash
node scripts/benchmark-accuracy.mjs
```

---

## 🚀 Quick Start (Local Run)

Requires Node.js 20+ (zero external npm dependencies).

```bash
# 1. Set your Gemini API key in .env (git-ignored)
cp .env-example .env
# Edit .env and paste: GEMINI_API_KEY=your_key_here

# 2. Start the application
node server.mjs

# 3. Open in browser
http://localhost:8080
```

---

## ☁️ Deploy to Google Cloud Run

This repository includes a production-grade [`Dockerfile`](Dockerfile) ready for Cloud Run.

### Option A: Via Google Cloud Console (Recommended)
1. Push this repository to GitHub via **GitHub Desktop** (`Publish repository`).
2. Go to [Google Cloud Console > Cloud Run](https://console.cloud.google.com/run).
3. Click **Create Service**.
4. Select **Continuously deploy from a repository** and choose this GitHub repo.
5. In **Environment Variables**, add:
   - `GEMINI_API_KEY` = `your_gemini_api_key`
6. Click **Create**. Cloud Run will build the container and deploy your live HTTPS endpoint!

### Option B: Via `gcloud` CLI
```bash
gcloud run deploy scam-call-shield \
  --source . \
  --platform managed \
  --region asia-south1 \
  --allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY="your_api_key"
```

---

## 👵 Elder Accessibility Features
- **Elder View Mode**: One-click toggle for high contrast and extra-large readable text.
- **Dual Guardian Modes**:
  - `📁 Demo Call Mode`: Instant evaluation of pre-recorded scam scenarios.
  - `🎙️ Live Mic Guardian`: Place phone on speakerphone next to laptop; browser captures live room audio with client-side Voice Activity Detection (silence skip).
- **Golden Hour Cyber Alert**: Quick reference to India's National Cyber Crime Helpline (**1930**).
