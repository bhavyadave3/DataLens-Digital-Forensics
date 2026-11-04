DataLens Analysis + Chain-of-Custody Update
==========================================

Replace these files in the DataLens project root:
- forensics.py
- evidence_manager.py
- javascript.js

No index.html, app.py, API route, acquisition flow, or database schema is changed.

What this update changes
------------------------
- Rule Severity is simplified to CRITICAL (risk score 50 or above) or NOT CRITICAL.
  The numeric risk score remains visible as a separate value.
- Random Forest output uses NORMAL / SUSPICIOUS labels instead of baseline / review.
- The Confidence column is populated with the forest's maximum class probability
  (scikit-learn) or tree-vote agreement (dependency-free fallback). This is an
  in-sample model score based on heuristic-derived labels; it is NOT a calibrated
  probability of maliciousness or independently validated confidence.
- Isolation Forest now runs for cases containing at least two analyzable files,
  rather than refusing all cases below 10 files. It reports Anomaly / Not flagged
  and a decision score. With very small cases, treat this as a preliminary,
  case-relative signal; an anomaly is not proof of maliciousness.
- Evidence custody events store the rule findings, RF prediction and score,
  Isolation Forest result and score, integrity, features, and full analysis data.
- Case-level analysis completion is recorded in the case chain of custody; case
  and evidence custody reports include the corresponding event details.

Install and test
----------------
1. Back up the existing three files.
2. Extract this ZIP and replace the three files in the DataLens project root.
3. Run:
     python -m py_compile forensics.py evidence_manager.py
     node --check javascript.js
4. Restart DataLens, select a case with at least two evidence files, and run analysis.
5. Confirm the Analysis table shows CRITICAL / NOT CRITICAL, NORMAL / SUSPICIOUS,
   a percentage model score, and Anomaly / Not flagged.
6. Open Chain of Custody and verify both EVIDENCE_ANALYZED and
   CASE_ANALYSIS_COMPLETED entries. Generate both evidence and case reports.

Important limitation
-------------------
The Random Forest is still a demonstration classifier trained on labels generated
from forensic heuristics. Its score is model agreement / in-sample class score,
not a trustworthy malware probability. For validated ML confidence, train and
evaluate on an independently labeled dataset with held-out test data.
The rule risk score is a triage priority, not a probability of maliciousness.
Preserve originals and independently verify findings.
