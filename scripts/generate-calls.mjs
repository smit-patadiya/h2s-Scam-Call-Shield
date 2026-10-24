// Generates the demo call recordings with Gemini speech generation.
// Usage: GEMINI_API_KEY=... node scripts/generate-calls.mjs
import { writeFile, mkdir } from 'node:fs/promises';
import { speak } from '../lib/gemini.mjs';

const calls = [
  { file: 'gu-scam.wav', voice: 'Charon', style: 'Say in a stern, hurried, threatening tone, in Gujarati',
    text: 'નમસ્તે, હું મુંબઈ પોલીસ સાયબર સેલમાંથી બોલું છું. તમારા આધાર નંબર પર મોકલેલા પાર્સલમાં ડ્રગ્સ મળ્યા છે. તમે ડિજિટલ અરેસ્ટમાં છો, ફોન કાપશો નહીં. કેસ બંધ કરવા માટે અત્યારે જ ₹50,000 ટ્રાન્સફર કરો.' },
  { file: 'hi-scam.wav', voice: 'Orus', style: 'Say in a stern, hurried, threatening tone, in Hindi',
    text: 'नमस्ते, मैं मुंबई पुलिस साइबर सेल से बोल रहा हूँ। आपके आधार नंबर से भेजे गए पार्सल में ड्रग्स मिले हैं। आप डिजिटल अरेस्ट में हैं, कॉल मत काटिए। केस बंद करने के लिए अभी ₹50,000 ट्रांसफर कीजिए।' },
  { file: 'en-scam.wav', voice: 'Puck', style: 'Say in an urgent, officious tone, in Indian English',
    text: "Hello, this is your bank's KYC team. Your account will be blocked today because your KYC has expired. To keep it active, please share the OTP we just sent to your phone." },
  { file: 'en-genuine.wav', voice: 'Kore', style: 'Say in a friendly, casual tone, in Indian English',
    text: "Hi, this is the delivery partner from Swiggy. I'm outside your building with your order. Which gate should I come to?" },
];

await mkdir(new URL('../public/calls/', import.meta.url), { recursive: true });
for (const c of calls) {
  process.stdout.write(`Generating ${c.file} ... `);
  const wav = await speak(c.text, c.voice);
  await writeFile(new URL(`../public/calls/${c.file}`, import.meta.url), wav);
  console.log(`${(wav.length / 1024).toFixed(0)} KB`);
}
