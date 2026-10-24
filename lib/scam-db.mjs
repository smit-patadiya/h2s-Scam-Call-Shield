// Scam Number Registry (Zero-dependency persistent JSON store)
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const DB_FILE = join(fileURLToPath(new URL('.', import.meta.url)), '../data/scam-numbers.json');

// Initialize with sample known fraud numbers (like 1930 cyber fraud reports)
const SEED_DATA = [
  {
    phone: '+919876500001',
    category: 'Digital Arrest',
    flags: ['authority_claim', 'threat', 'isolation'],
    risk: 95,
    reportedAt: '2026-10-20T10:15:00Z',
    reportsCount: 14,
    notes: 'Impersonating Mumbai Police Cyber Crime / Narcotics Department'
  },
  {
    phone: '+919876500002',
    category: 'Bank KYC Freeze',
    flags: ['authority_claim', 'urgency', 'otp_request'],
    risk: 92,
    reportedAt: '2026-10-22T14:30:00Z',
    reportsCount: 8,
    notes: 'Fake SBI / HDFC KYC expiration threat demanding OTP'
  }
];

async function loadDb() {
  try {
    const raw = await readFile(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    if (e.code === 'ENOENT') {
      await saveDb(SEED_DATA);
      return SEED_DATA;
    }
    return [];
  }
}

async function saveDb(data) {
  await mkdir(join(fileURLToPath(new URL('.', import.meta.url)), '../data'), { recursive: true });
  await writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

/** Check if a number is already flagged in the database */
export async function checkNumber(rawPhone) {
  if (!rawPhone) return { isKnownScam: false };
  const clean = String(rawPhone).replace(/\D/g, '');
  const db = await loadDb();
  const match = db.find((entry) => entry.phone.replace(/\D/g, '').endsWith(clean.slice(-10)));
  if (match) {
    return {
      isKnownScam: true,
      details: match
    };
  }
  return { isKnownScam: false };
}

/** Store / update a scam number upon AI detection */
export async function recordScamNumber({ phone, category = 'Detected Fraud', flags = [], risk = 90, notes = '' }) {
  if (!phone) return null;
  const cleanPhone = String(phone).trim();
  const db = await loadDb();
  const cleanDigits = cleanPhone.replace(/\D/g, '');
  
  const existingIndex = db.findIndex((e) => e.phone.replace(/\D/g, '').endsWith(cleanDigits.slice(-10)));
  const now = new Date().toISOString();
  
  let entry;
  if (existingIndex >= 0) {
    entry = db[existingIndex];
    entry.reportsCount = (entry.reportsCount || 1) + 1;
    entry.risk = Math.max(entry.risk, risk);
    entry.reportedAt = now;
    if (notes && !entry.notes.includes(notes)) entry.notes += ` | ${notes}`;
    flags.forEach((f) => { if (!entry.flags.includes(f)) entry.flags.push(f); });
  } else {
    entry = {
      phone: cleanPhone,
      category,
      flags,
      risk,
      reportedAt: now,
      reportsCount: 1,
      notes: notes || 'Automatically flagged by Scam Call Shield AI'
    };
    db.unshift(entry);
  }
  
  await saveDb(db);
  console.log(`[ScamDB] 🚨 Stored fraud number: ${cleanPhone} (Reports: ${entry.reportsCount})`);
  return entry;
}

/** Get list of all known numbers */
export async function getAllScamNumbers() {
  return await loadDb();
}
