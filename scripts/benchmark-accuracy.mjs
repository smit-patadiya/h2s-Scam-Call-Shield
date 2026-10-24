/**
 * Benchmark Accuracy & Latency Test
 * Evaluates the Multi-Agent Hybrid Detection Engine against the Indian Scam Corpus
 * from from-gemini/sample_scam_corpus.json and negative genuine control dialogues.
 */

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { IndianScamRuleEngine, UPILogicChecker } from '../lib/scam-detector-engine.mjs';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');

// Genuine Negative Control Samples (Must be classified as SAFE)
const GENUINE_CONTROLS = [
  {
    id: 'SAFE_001',
    text: 'Hello sir, Swiggy delivery partner here. I am waiting outside your building gate, please come down to collect the food parcel.',
    expected: 'SAFE'
  },
  {
    id: 'SAFE_002',
    text: 'Namaste aunty, mai Ramesh ka dost bol raha hu. Kal college ka reunion hai, kya Ramesh ghar par hai?',
    expected: 'SAFE'
  },
  {
    id: 'SAFE_003',
    text: 'Dear customer, your SBI OTP for login is 482910. Do NOT share this OTP with anyone, including bank staff. State Bank of India.',
    expected: 'SAFE'
  },
  {
    id: 'SAFE_004',
    text: 'Hello madam, Apollo Clinic appointment reminder for tomorrow 11 AM with Dr. Mehta for routine dental checkup.',
    expected: 'SAFE'
  },
  {
    id: 'SAFE_005',
    text: 'Bhaiya Ola cab location par pahunch gayi hai. White Swift Dzire, number 4821.',
    expected: 'SAFE'
  },
  {
    id: 'SAFE_006',
    text: 'Beta, mummy bol rahi hu. Bazar se aate waqt 1 kilo tamatar aur doodh le aana.',
    expected: 'SAFE'
  }
];

async function runBenchmark() {
  console.log('================================================================');
  console.log('   INDIAN SCAM CALL MULTI-AGENT DETECTION BENCHMARK HARNESS   ');
  console.log('================================================================\n');

  // Load sample scam corpus
  const raw = await readFile(join(ROOT, 'from-gemini', 'sample_scam_corpus.json'), 'utf-8');
  const scamCorpus = JSON.parse(raw);

  console.log(`Loaded ${scamCorpus.length} scam permutation scenarios from from-gemini/sample_scam_corpus.json`);
  console.log(`Loaded ${GENUINE_CONTROLS.length} genuine negative control scenarios\n`);

  let tp = 0; // Scam correctly flagged
  let fn = 0; // Scam missed
  let tn = 0; // Genuine correctly safe
  let fp = 0; // Genuine wrongly flagged

  const latencies = [];
  const dimensionDistribution = { P: 0, T: 0, M: 0, E: 0 };

  console.log('Testing Scam Vectors (English + Hinglish Transcripts)...');

  for (const item of scamCorpus) {
    // Test both English and Hinglish variants
    const sampleText = `${item.transcript_en} ${item.transcript_hinglish}`;

    const t0 = performance.now();
    const engine = new IndianScamRuleEngine();
    const res = engine.evaluateText(sampleText);
    const dt = performance.now() - t0;
    latencies.push(dt);

    res.dimensionsActive.forEach((d) => {
      if (dimensionDistribution[d] !== undefined) dimensionDistribution[d]++;
    });

    if (res.alertLevel === 'CRITICAL_SCAM' || res.alertLevel === 'SUSPICIOUS' || res.risk >= 40) {
      tp++;
    } else {
      fn++;
      console.warn(`[MISSED SCAM] ID: ${item.id} | Vector: ${item.vector}`);
    }
  }

  console.log('Testing Genuine Control Calls...');
  for (const item of GENUINE_CONTROLS) {
    const t0 = performance.now();
    const engine = new IndianScamRuleEngine();
    const res = engine.evaluateText(item.text);
    const dt = performance.now() - t0;
    latencies.push(dt);

    if (res.alertLevel === 'SAFE' && res.risk < 40) {
      tn++;
    } else {
      fp++;
      console.warn(`[FALSE POSITIVE] ID: ${item.id} | Flagged as: ${res.alertLevel} (${res.risk}%)`);
    }
  }

  // Calculate Metrics
  const total = scamCorpus.length + GENUINE_CONTROLS.length;
  const accuracy = ((tp + tn) / total) * 100;
  const precision = (tp / (tp + fp)) * 100;
  const recall = (tp / (tp + fn)) * 100;
  const f1 = 2 * ((precision * recall) / (precision + recall));
  const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
  const p95Latency = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];

  console.log('\n----------------------------------------------------------------');
  console.log('                     BENCHMARK RESULTS MATRIX                   ');
  console.log('----------------------------------------------------------------');
  console.log(`Total Test Samples Evaluated : ${total}`);
  console.log(`True Positives (Scams Caught): ${tp} / ${scamCorpus.length}`);
  console.log(`True Negatives (Safe Calls)  : ${tn} / ${GENUINE_CONTROLS.length}`);
  console.log(`False Positives (False Alarm): ${fp}`);
  console.log(`False Negatives (Missed Scam): ${fn}`);
  console.log('----------------------------------------------------------------');
  console.log(`Detection Accuracy           : ${accuracy.toFixed(2)}%`);
  console.log(`Precision (Confidence)       : ${precision.toFixed(2)}%`);
  console.log(`Recall (Coverage)            : ${recall.toFixed(2)}%`);
  console.log(`F1 Score                     : ${f1.toFixed(2)}%`);
  console.log('----------------------------------------------------------------');
  console.log(`Average Latency              : ${avgLatency.toFixed(3)} ms`);
  console.log(`95th Percentile Latency (P95): ${p95Latency.toFixed(3)} ms`);
  console.log(`API Tokens Used by Sentinel  : 0 (Pure Local Execution)`);
  console.log('----------------------------------------------------------------');
  console.log('Active Vector Dimension Breakdown:');
  console.log(`  - P (Persona / Authority) : ${dimensionDistribution.P} hits`);
  console.log(`  - T (Trigger / Pretext)   : ${dimensionDistribution.T} hits`);
  console.log(`  - M (Pressure / Duress)   : ${dimensionDistribution.M} hits`);
  console.log(`  - E (Extraction / Exploit): ${dimensionDistribution.E} hits`);
  console.log('================================================================\n');
}

runBenchmark().catch(console.error);
