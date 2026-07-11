# 🛡️ CyberOptimus

### Cybersecurity Assessment Platform

CyberOptimus is a modern cybersecurity web application built with **Python** and **Flask**. It helps users analyze website security, evaluate password strength, detect phishing attempts, inspect files, and generate professional security reports through an intuitive dashboard.

---

## ✨ Features

### 🌐 Website Security Scanner
- DNS Health Analysis
- SSL/TLS Certificate Validation
- TLS Version Detection
- HTTP Security Header Analysis
- Cookie Security Analysis
- Server Configuration Analysis
- Redirect Tracking
- Performance Analysis
- Security Score & Grade
- Severity-based Risk Assessment
- Professional PDF Report Generation

---

### 🔐 Password Security Analyzer
- Password Strength Score
- Entropy Calculation
- Common Password Detection
- Dictionary Attack Detection
- Attack Method Prediction
- Offline Crack Time Estimation
- Password Security Recommendations
- Secure Password Generator
- Password Privacy Protection (No Storage)

---

### 🎣 Phishing Detector
- URL Risk Analysis
- Suspicious Domain Detection
- Lookalike Domain Detection
- Homograph Attack Detection
- SSL & DNS Verification
- Threat Level Assessment
- Security Recommendations

---

### 📁 File Analyzer
- File Type Detection
- File Hash Generation
- Metadata Extraction
- Suspicious File Identification
- Security Risk Assessment

---

### 📊 Dashboard
- Professional Security Dashboard
- Risk Summary
- Severity Statistics
- Scan History
- Interactive Reports

---

## 🛠️ Tech Stack

**Backend**
- Python
- Flask

**Frontend**
- HTML5
- CSS3
- JavaScript

**Database**
- SQLite

**Libraries**
- Requests
- Cryptography
- BeautifulSoup
- dnspython
- ReportLab
- And other Python packages listed in `requirements.txt`

---

## 📂 Project Structure

```text
CyberOptimus/
│
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
│
├── docs/
├── requirements.txt
├── config.py
├── run.py
└── README.md
```

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/VishwasPoojary/CyberOptimus.git
cd CyberOptimus
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

#### Linux / Ubuntu

```bash
source venv/bin/activate
```

#### Windows

```cmd
venv\Scripts\activate
```

### 4. Install Required Packages

```bash
pip install -r requirements.txt
```

### 5. Run the Application

```bash
python3 run.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

---

## 🔒 Security & Privacy

CyberOptimus is designed with security in mind.

- Passwords are analyzed locally and are **never stored**.
- Generated passwords are **not saved**.
- Sensitive files such as `.env`, databases, and virtual environments are excluded from Git using `.gitignore`.
- This project is intended for **authorized security assessment and educational purposes only**.

---

## 📸 Screenshots

Add screenshots here after uploading them.

Example:

```markdown
![Dashboard](docs/screenshots/dashboard.png)

![Website Scanner](docs/screenshots/website_scanner.png)

![Password Analyzer](docs/screenshots/password_analyzer.png)

![Phishing Detector](docs/screenshots/phishing_detector.png)

![File Analyzer](docs/screenshots/file_analyzer.png)
```

---

## 🎯 Future Enhancements

- Threat Intelligence Integration
- VirusTotal Integration
- WHOIS & Domain Age Lookup
- Advanced Malware Analysis
- AI-powered Security Recommendations
- Scan History Export
- User Authentication
- Cloud Deployment

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👨‍💻 Author

**Vishwas Poojary**

GitHub: https://github.com/VishwasPoojary

---

⭐ If you found this project useful, consider giving it a **Star** on GitHub.
