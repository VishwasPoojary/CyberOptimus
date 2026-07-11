# CyberOptimus

CyberOptimus is a cybersecurity web application built using Python and Flask. It provides multiple tools for website security scanning, password analysis, phishing detection, file analysis, scan history, and downloadable security reports.

## Features

### Website Security Scanner
- DNS health analysis
- SSL/TLS certificate inspection
- TLS version detection
- HTTP security header analysis
- Redirect tracking
- Cookie security analysis
- Server information detection
- Performance analysis
- Severity-based findings
- Security score and grade
- PDF report generation

### Password Security Analyzer
- Password strength score
- Entropy calculation
- Common-password detection
- Dictionary and pattern analysis
- Estimated attack method
- Offline crack-time estimates
- Risk factors and recommendations
- Secure password generator
- Copy-to-clipboard support
- Local analysis without storing passwords

### Phishing Detector
- Suspicious URL analysis
- Lookalike-domain detection
- Character-substitution detection
- DNS and SSL checks
- Risk score and threat level
- Security recommendations

### File Analyzer
- File type identification
- Hash generation
- Basic suspicious-file indicators
- File metadata analysis

### Additional Features
- Security dashboard
- Scan history
- Severity summaries
- Downloadable PDF reports
- Responsive dark-themed interface

## Tech Stack

- Python
- Flask
- HTML
- CSS
- JavaScript
- SQLite

## Project Structure

```text
CyberOptimus/
├── app/
│   ├── models/
│   ├── reports/
│   ├── repositories/
│   ├── routes/
│   ├── scanners/
│   ├── services/
│   ├── static/
│   ├── templates/
│   └── utils/
├── docs/
├── config.py
├── requirements.txt
├── run.py
└── README.md
