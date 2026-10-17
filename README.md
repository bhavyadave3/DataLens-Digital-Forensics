# DataLens — Digital Forensics Platform

DataLens is a Python-based digital forensics platform designed to assist investigators with digital evidence management, forensic analysis, recovery, and evidence integrity verification.

## Features
- **Evidence Management** — Organize and manage digital evidence.
- **Forensic Analysis** — Analyze digital evidence using forensic tools.
- **File Recovery** — Scan supported files and disk images for recoverable data.
- **Chain of Custody** — Maintain evidence handling records.
- **Integrity Verification** — Verify evidence integrity using hashes.
- **Web Dashboard** — Access forensic features through a web-based interface.

## Tech Stack
- Python
- HTML, CSS, JavaScript
- SQLite
- HTTP server

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/bhavyadave3/DataLens-Digital-Forensics.git
   cd DataLens-Digital-Forensics
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   ```

   Windows PowerShell:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Start the application:
   ```bash
   python app.py
   ```

5. Open `http://127.0.0.1:8000` in your browser.

## Disclaimer
DataLens is intended for authorized digital forensic investigations and educational use. Recovery results and experimental machine-learning outputs should be independently validated before being used in forensic conclusions.

## Author
**Bhavya Dave**

[GitHub Repository](https://github.com/bhavyadave3/DataLens-Digital-Forensics)
