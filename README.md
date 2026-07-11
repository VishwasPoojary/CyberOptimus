# CyberOptimus

**Enterprise Cybersecurity Assessment Platform**

## Mission
A modern AI-powered cybersecurity platform that helps users analyze websites, detect phishing attempts, evaluate passwords, inspect files, and generate professional security reports through an intuitive dashboard.

## Features
- **Website Scanner**: Analyze HTTPS, headers, server info, and connection risks.
- **Phishing Detector**: Analyze URLs for phishing indicators and malicious intent.
- **Password Checker**: Evaluate password strength and check if it has been exposed in data breaches.
- **File Analyzer**: Extract metadata, hashes, and identify suspicious files.
- **Security Dashboard**: Real-time cyber risk monitoring center with detailed metrics and statistics.

## Clean Architecture
CyberOptimus has been meticulously designed using Clean Architecture principles to separate concerns into intuitive modules:
- **Scanners**: Dedicated modules for distinct analysis tools.
- **Utils**: Reusable networking and cryptography utilities.
- **Repositories**: Standardized database interactions using the repository pattern.
- **Reports**: Isolated logic for generating dashboard statistics and scores.

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/CyberOptimus.git
cd CyberOptimus

# Install dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the application
python run.py
```

## Contributing
We welcome contributions to CyberOptimus. Please submit pull requests to the `main` branch.

## License
MIT License
