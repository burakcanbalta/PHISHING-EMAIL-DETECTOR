# 🛡️ Phishing Email Detector

A real-time phishing email detection and alerting system designed for SOCs and security teams. Automatically analyze emails, detect phishing patterns, and send alerts with comprehensive reporting.

---

## 🚀 Quick Start

### 1. Requirements

```txt
requests==2.31.0
dnspython==2.4.2
```

### 2. Installation

```bash
# Install required packages
pip install requests dnspython
```

### 3. Usage Examples

```bash
# Analyze a suspicious email file
python phishing_detector.py --analyze-file suspicious_email.eml

# Add known phishing domain to threat intelligence database
python phishing_detector.py --add-threat "evil-phishing.com"

# Generate phishing detection report for last 48 hours (JSON)
python phishing_detector.py --report --hours 48 --format json
```

### 4. Integration with Email Gateway (Python API)

```python
from phishing_detector import PhishingDetector

detector = PhishingDetector()
result = detector.analyze_email(email_content)
if result['verdict'] in ['SUSPICIOUS', 'MALICIOUS']:
    quarantine_email(email_content)
```

---

## 🎯 Purpose

Detect and analyze phishing emails automatically, leveraging header, content, URL, and attachment analysis. Integrates with SOC alerting workflows to provide real-time notifications.

---

## 🔍 Features

* **Advanced Email Analysis**

  * Header Analysis: Detect spoofing and suspicious sender patterns
  * Content Analysis: Keyword and suspicious language scanning
  * URL Analysis: Reputation checks and VirusTotal integration
  * Attachment Analysis: File type detection, double-extension checks

* **Threat Intelligence**

  * Known Phishing Domains: Real-time database lookup
  * URL Reputation: VirusTotal API integration
  * Pattern Recognition: Suspicious TLDs, newly registered domains

* **Multi-Channel Alerting**

  * Email alerts via SMTP
  * Slack/Discord notifications
  * Comprehensive security event logging

* **Risk Scoring & Verdict**

  * Intelligent risk scoring
  * Three-tier verdict: CLEAN, SUSPICIOUS, MALICIOUS
  * Configurable sensitivity thresholds

---

## 🧩 CLI Reference

```bash
# Analyze email
python phishing_detector.py --analyze-file suspicious_email.eml

# Add a threat
python phishing_detector.py --add-threat "evil-phishing.com"

# Generate report
python phishing_detector.py --report --hours 48 --format json
```

---

## 🧪 Use Cases

### SOC Email Analysis

```bash
# Analyze suspicious email
python phishing_detector.py --analyze-file suspicious_email.eml
```

**Sample Output:**

```
Analysis Result: MALICIOUS
Risk Score: 9/10
Suspicious URLs: 3
Suspicious Attachments: 1
```

### Threat Intelligence Management

```bash
# Add known phishing domain
python phishing_detector.py --add-threat "evil-phishing.com"
```

### Reporting & Analytics

```bash
# Generate phishing detection report
python phishing_detector.py --report --hours 48 --format json
```

### Integration with Email Gateway

```python
# Quarantine emails flagged as suspicious or malicious
result = detector.analyze_email(email_content)
if result['verdict'] in ['SUSPICIOUS', 'MALICIOUS']:
    quarantine_email(email_content)
```

---

## 📊 Sample Output

### Email Analysis Result (JSON)

```json
{
  "verdict": "MALICIOUS",
  "risk_score": 9,
  "suspicious_urls": [
    {
      "url": "http://evil-phishing.com/login",
      "reputation_score": -3,
      "threat_type": "PHISHING"
    }
  ],
  "suspicious_attachments": [
    {
      "filename": "invoice.exe",
      "risk_score": 3,
      "suspicious_indicators": ["Executable file extension"]
    }
  ]
}
```

### Alert Message (Text)

```
🚨 Phishing Alert: MALICIOUS
Message ID: <12345@evil.com>
From: security@your-bank.com
Subject: URGENT: Your Account Will Be Suspended
Risk Score: 9/10
Suspicious Indicators:
- URLs: 1 malicious
- Attachments: 1 suspicious
- Authentication Failures: SPF, DKIM
Immediate investigation required!
```

---

## 🤝 Contributing

* Fork the repository
* Create a feature branch
* Commit changes and push
* Create a pull request
* Contribution areas: detection algorithms, alerting channels, reporting formats
