# Indian Telephony Scam Call Detection Package

This archive contains the engineering specification, algorithmic matrix, and executable reference code for an Indian scam call detection system.

## Contents
1. `scam_detection_india_taxonomy.md`: The complete technical specification, combinatorial taxonomy ($3,240$ vectors), Hinglish regex patterns, and detection algorithms.
2. `scam_detector.py`: Pure Python module with the `IndianScamDetector` sliding-window risk engine, `UPILogicChecker`, and `generate_synthetic_scam_corpus()` generator.
3. `sample_scam_corpus.json`: A sample generated dataset containing combinatorial permutations across Hindi/English/Hinglish transcripts for testing model classifiers.

## Quick Start
To run the reference engine in Python:
```python
from scam_detector import IndianScamDetector, UPILogicChecker

detector = IndianScamDetector()
res = detector.process_transcript_chunk("Hello sir, this is Mumbai Police Cyber Cell. Your parcel has drugs. Come on Skype video call.")
print(res)
```
