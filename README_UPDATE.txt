DataLens Analysis + Chain-of-Custody Update
==========================================

Files in this package (replace existing files in the DataLens project root):
1. forensics.py
2. evidence_manager.py
3. javascript.js

No index.html, app.py, database schema, acquisition logic, or API route is changed.

What this update changes
------------------------
- Adds rule-engine risk score, number of risk factors, integrity status, and
  supported-analysis status to the Random Forest feature vector. The existing
  demonstration RF therefore sees content-derived indicators, not only filename,
  extension, and entropy.
- Raises the minimum case size for Isolation Forest to 10 files. Smaller cases
  explicitly report "Insufficient reference set (minimum 10 files)" instead of
  producing unstable case-relative anomaly labels.
- Stores the complete per-evidence analysis payload in the EVIDENCE_ANALYZED
  custody event: rule findings, risk factors, integrity, AI model outputs,
  features, analysis status, and interpretation.
- Adds a CASE_ANALYSIS_COMPLETED custody event with the case-level analysis
  summary and all per-file model outputs.
- Formats custody event details as readable JSON in the existing UI table.
- Existing case and evidence PDF reports already include custody event details,
  so these new analysis events are included in both report scopes.

Install / replace
-----------------
1. Back up the current three files.
2. Extract this ZIP.
3. Copy the three files into the project root, replacing the existing files.
4. Run:
     python -m py_compile forensics.py evidence_manager.py
     node --check javascript.js
5. Run DataLens locally and analyze a test case.
6. Confirm the Chain of Custody page shows:
   - EVIDENCE_ANALYZED rows for each evidence item, with complete model/rule data.
   - CASE_ANALYSIS_COMPLETED row with the case summary.
7. Generate both an evidence custody PDF and a case custody PDF to confirm
   the same analysis details are present in their event histories.

Important ML limitation
-----------------------
The existing Random Forest remains a demonstration classifier whose training
labels are derived from heuristic rules. This patch adds the rule engine's
content-derived indicators to its features, but does NOT turn that model into
an independently validated malware classifier. Its prediction is experimental;
confidence remains unavailable rather than presenting an uncalibrated value as
reliable confidence.

Isolation Forest is case-relative anomaly detection, not a malware verdict.
It now abstains on cases with fewer than 10 evidence items to reduce unstable
small-sample false positives.

The rule risk score is a triage priority, not a probability of maliciousness.
Keep original evidence and verify findings independently.
