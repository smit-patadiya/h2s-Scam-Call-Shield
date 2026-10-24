// Shared helpers for the test scripts: manifest file and minimal WAV read/write.
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';

export const TEST_DIR = new URL('./', import.meta.url);
export const CLIPS_DIR = new URL('./clips/', import.meta.url);

/**
 * Manifest entries: { file, expected: 'scam'|'safe', source, note } (file is relative to test/).
 * Each source has its own clips/manifest.<source>.json so scripts can run in parallel safely.
 */
export async function readManifest() {
  const files = (await readdir(CLIPS_DIR).catch(() => [])).filter((f) => /^manifest\..+\.json$/.test(f)).sort();
  const all = await Promise.all(files.map(async (f) => JSON.parse(await readFile(new URL(f, CLIPS_DIR), 'utf8'))));
  return all.flat();
}

export async function updateManifest(source, entries) {
  await ensureClipsDir();
  await writeFile(new URL(`manifest.${source}.json`, CLIPS_DIR), JSON.stringify(entries, null, 2) + '\n');
}

export async function ensureClipsDir() {
  await mkdir(CLIPS_DIR, { recursive: true });
}

/** Parses a PCM16 or float32 WAV into mono Float32 samples. */
export function decodeWav(buf) {
  if (buf.toString('ascii', 0, 4) !== 'RIFF' || buf.toString('ascii', 8, 12) !== 'WAVE') throw new Error('Not a WAV file');
  let fmt, data;
  for (let o = 12; o + 8 <= buf.length;) {
    const id = buf.toString('ascii', o, o + 4);
    let size = buf.readUInt32LE(o + 4);
    if (id === 'data' && (size === 0 || size === 0xffffffff || o + 8 + size > buf.length)) size = buf.length - o - 8;
    if (id === 'fmt ') fmt = { format: buf.readUInt16LE(o + 8), channels: buf.readUInt16LE(o + 10), rate: buf.readUInt32LE(o + 12), bits: buf.readUInt16LE(o + 22) };
    if (id === 'data') data = buf.subarray(o + 8, o + 8 + size);
    o += 8 + size + (size % 2);
  }
  if (!fmt || !data) throw new Error('WAV missing fmt or data chunk');
  const { format, channels, rate, bits } = fmt;
  const bytes = bits / 8, frames = Math.floor(data.length / (bytes * channels));
  const read = format === 3 && bits === 32 ? (o) => data.readFloatLE(o)
    : bits === 16 ? (o) => data.readInt16LE(o) / 32768
    : null;
  if (!read) throw new Error(`Unsupported WAV format ${format}/${bits}-bit`);
  const out = new Float32Array(frames);
  for (let i = 0; i < frames; i++) {
    let s = 0;
    for (let c = 0; c < channels; c++) s += read((i * channels + c) * bytes);
    out[i] = s / channels;
  }
  return { samples: out, rate };
}

/** Encodes mono Float32 samples as a PCM16 WAV Buffer. */
export function encodeWav(samples, rate) {
  const h = Buffer.alloc(44), n = samples.length;
  h.write('RIFF', 0); h.writeUInt32LE(36 + n * 2, 4); h.write('WAVEfmt ', 8);
  h.writeUInt32LE(16, 16); h.writeUInt16LE(1, 20); h.writeUInt16LE(1, 22);
  h.writeUInt32LE(rate, 24); h.writeUInt32LE(rate * 2, 28); h.writeUInt16LE(2, 32); h.writeUInt16LE(16, 34);
  h.write('data', 36); h.writeUInt32LE(n * 2, 40);
  const body = Buffer.alloc(n * 2);
  for (let i = 0; i < n; i++) body.writeInt16LE(Math.round(Math.max(-1, Math.min(1, samples[i])) * 32767), i * 2);
  return Buffer.concat([h, body]);
}

/** GET JSON from the Hugging Face datasets server, with a few retries (it returns 5xx sometimes). */
export async function hfRows(params, tries = 4) {
  const url = `https://datasets-server.huggingface.co/rows?${new URLSearchParams(params)}`;
  for (let i = 1; ; i++) {
    const r = await fetch(url);
    if (r.ok) return r.json();
    if (i >= tries) throw new Error(`HF ${r.status} for ${url}`);
    await new Promise((res) => setTimeout(res, 1500 * i));
  }
}
