// Downloads real speech clips from Google FLEURS (validation split) as "must stay safe" tests.
// Per language it picks one clip that mentions police/bank/courier (tricky negatives) and one ordinary clip.
// Usage: node test/fetch-fleurs.mjs
import { writeFile } from 'node:fs/promises';
import { CLIPS_DIR, ensureClipsDir, hfRows, updateManifest } from './lib.mjs';

const LANGS = [
  { config: 'gu_in', code: 'gu', keywords: ['પોલીસ', 'બેંક', 'કુરિયર', 'પૈસા'] },
  { config: 'hi_in', code: 'hi', keywords: ['पुलिस', 'बैंक', 'कूरियर', 'पैसे'] },
  { config: 'en_us', code: 'en', keywords: ['police', 'bank', 'courier', 'money'] },
];

await ensureClipsDir();
const entries = [];
for (const { config, code, keywords } of LANGS) {
  const { rows } = await hfRows({ dataset: 'google/fleurs', config, split: 'validation', offset: 0, length: 100 });
  const text = (r) => r.row.raw_transcription || r.row.transcription || '';
  const tricky = rows.find((r) => keywords.some((k) => text(r).toLowerCase().includes(k.toLowerCase())));
  const plain = rows.find((r) => r !== tricky && !keywords.some((k) => text(r).toLowerCase().includes(k.toLowerCase())));
  for (const [kind, r] of [['keyword', tricky], ['plain', plain]]) {
    if (!r) { console.log(`${code}: no ${kind} clip found in first 100 rows`); continue; }
    const file = `clips/fleurs-${code}-${kind}.wav`;
    const audio = await fetch(r.row.audio[0].src);
    if (!audio.ok) throw new Error(`Download failed (${audio.status}) for ${file}`);
    const buf = Buffer.from(await audio.arrayBuffer());
    await writeFile(new URL(file.replace('clips/', ''), CLIPS_DIR), buf);
    entries.push({ file, expected: 'safe', source: 'fleurs', note: `${config} #${r.row.id}: ${text(r).slice(0, 90)}` });
    console.log(`${file}  ${(buf.length / 1024).toFixed(0)} KB  "${text(r).slice(0, 60)}..."`);
  }
}
await updateManifest('fleurs', entries);
console.log(`Saved ${entries.length} FLEURS clips.`);
