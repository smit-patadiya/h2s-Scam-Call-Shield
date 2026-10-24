// Turns BothBosu/scam-dialogue text into two-voice call recordings with Gemini TTS.
// Picks one full dialogue per type (8 types, half scam and half genuine).
// Usage: node test/make-dialogues.mjs
import { writeFile } from 'node:fs/promises';
import { speakDialogue } from '../lib/gemini.mjs';
import { CLIPS_DIR, ensureClipsDir, hfRows, updateManifest } from './lib.mjs';

const TOTAL = 1280, PAGE = 100;

// Splits "caller: ... receiver: ..." into turns.
function toTurns(dialogue) {
  return dialogue.split(/\b(caller|receiver):/i).slice(1).reduce((acc, part, i, arr) => {
    if (i % 2 === 0) {
      const text = (arr[i + 1] || '').trim();
      if (text) acc.push({ speaker: part.toLowerCase() === 'caller' ? 'Caller' : 'Receiver', text });
    }
    return acc;
  }, []);
}

// One row per type: the first one whose length is close to the median, so clips are typical, not extreme.
const byType = new Map();
for (let offset = 0; offset < TOTAL; offset += PAGE) {
  const { rows } = await hfRows({ dataset: 'BothBosu/scam-dialogue', config: 'default', split: 'train', offset, length: PAGE });
  for (const { row_idx, row } of rows) {
    const len = row.dialogue.length;
    if (!byType.has(row.type) && len > 900 && len < 1700) byType.set(row.type, { row_idx, ...row });
  }
}
console.log(`Types found: ${[...byType.keys()].join(', ')}`);

await ensureClipsDir();
const CONCURRENCY = 1; // pacing comes from GEMINI_RPM in .env
const jobs = [...byType].map(([type, d]) => async () => {
  const expected = d.label === 1 ? 'scam' : 'safe';
  const file = `clips/dlg-${expected}-${type}.wav`;
  const turns = toTurns(d.dialogue);
  const wav = await speakDialogue(turns);
  await writeFile(new URL(file.replace('clips/', ''), CLIPS_DIR), wav);
  console.log(`${file} (${turns.length} turns) ${(wav.length / 1024).toFixed(0)} KB`);
  return { file, expected, source: 'scam-dialogue', note: `row ${d.row_idx}, type ${type}` };
});
const entries = [];
await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
  while (jobs.length) {
    const job = jobs.shift();
    try { entries.push(await job()); } catch (e) { console.error(`FAILED: ${e.message.slice(0, 200)}`); }
  }
}));
entries.sort((a, b) => a.file.localeCompare(b.file));
await updateManifest('scam-dialogue', entries);
console.log(`Saved ${entries.length} dialogue clips.`);
