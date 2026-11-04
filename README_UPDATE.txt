DATALENS ANALYSIS + CHAIN-OF-CUSTODY UPDATE

Files included
--------------
1. forensics.py
2. evidence_manager.py
3. javascript.js

Installation
------------
1. Stop the DataLens server.
2. Make a backup copy of these three existing files.
3. Replace:
   - project-root/forensics.py
   - project-root/evidence_manager.py
   - project-root/javascript.js
4. Do not delete or replace datalens_data, datalens.db, evidence_vault, or reports.
5. Restart DataLens and open an existing case.
6. Run AI Analysis, then open Chain of Custody.

What this update changes
------------------------
- Keeps rule-based risk score and adds Random Forest output to each saved
  evidence analysis.
- Maps the model's demonstration labels to readable NORMAL / SUSPICIOUS values.
- Adds rule-derived risk score and factor count to the Random Forest feature
  inputs, so content findings can influence the model's demonstration output.
- Isolation Forest abstains when fewer than 10 evidence files are available,
  or when the case has no meaningful feature variation. This avoids presenting
  unstable tiny-sample results as a reliable anomaly verdict.
- Saves the full per-file analysis details in each EVIDENCE_ANALYZED custody
  event, including risk, RF, IF, integrity, findings and model notes.
- Adds one CASE_ANALYSIS_COMPLETED event with the case-level results summary.
- Existing database schema is retained; no database reset or migration is
  required by this update.
- The existing JavaScript UI structure and API routes are preserved. The
  analysis table and custody table display the results already returned by
  the existing API.

Important interpretation
------------------------
The Random Forest in this project is still a demonstration model trained on
heuristic-derived labels from the evidence being analyzed. Its NORMAL /
SUSPICIOUS output is a triage indicator, not independently validated malware
classification. It does not have a calibrated confidence score.
Isolation Forest detects statistical outliers relative to the current case;
an anomaly is not proof of maliciousness. With fewer than 10 files it will
show "Insufficient reference data" rather than a misleading result.

Quick verification
------------------
1. Acquire a case with several files of different formats.
2. Run AI Analysis.
3. Confirm the analysis table shows risk severity, risk score, Random Forest,
   Isolation Forest, and analysis time.
4. Open Chain of Custody. Confirm EVIDENCE_ANALYZED events show the per-file
   analysis details and CASE_ANALYSIS_COMPLETED shows the case summary.
5. Run custody integrity verification. The chain should remain valid.

No software change can guarantee that every file will be classified correctly.
Use the findings as forensic triage and verify suspicious indicators manually.
