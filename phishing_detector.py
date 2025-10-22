import re
import dns.resolver
import requests
import hashlib
import json
import sqlite3
import argparse
import smtplib
import threading
from email import message_from_bytes
from email.header import decode_header
from urllib.parse import urlparse, unquote
import time
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging
from logging.handlers import RotatingFileHandler
import sys

class PhishingDetector:
    def __init__(self, db_path="phishing_detector.db", config_file="config.json"):
        self.db_path = db_path
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.init_database()
        self.suspicious_keywords = self.load_suspicious_keywords()
        self.known_phishing_domains = set()
        self.load_threat_intelligence()

    def load_config(self, config_file):
        default_config = {
            "alerting": {
                "smtp": {
                    "server": "smtp.gmail.com",
                    "port": 587,
                    "username": "",
                    "password": "",
                    "from_email": "",
                    "to_email": ""
                },
                "slack_webhook": "",
                "discord_webhook": "",
                "virustotal_api_key": "",
                "abuseipdb_api_key": ""
            },
            "analysis": {
                "max_workers": 5,
                "timeout": 10,
                "check_url_reputation": True,
                "check_attachments": True
            },
            "scoring": {
                "suspicious_threshold": 5,
                "malicious_threshold": 8,
                "weights": {
                    "suspicious_sender": 2,
                    "suspicious_subject": 1,
                    "suspicious_urls": 3,
                    "suspicious_attachments": 3,
                    "spf_failure": 2,
                    "dkim_failure": 2,
                    "dmarc_failure": 2,
                    "known_phishing_domain": 4
                }
            }
        }

        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    return self.merge_configs(default_config, user_config)
            except Exception as e:
                print(f"Config load error: {e}")
        
        return default_config

    def merge_configs(self, default, user):
        result = default.copy()
        for key, value in user.items():
            if isinstance(value, dict) and key in result:
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler('phishing_detector.log', maxBytes=10485760, backupCount=5),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT,
                sender TEXT,
                subject TEXT,
                recipient TEXT,
                analysis_result TEXT,
                risk_score INTEGER,
                verdict TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                message_id TEXT,
                sender TEXT,
                description TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS url_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                reputation_score INTEGER,
                threat_type TEXT,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE,
                indicator_type TEXT,
                threat_type TEXT,
                confidence INTEGER,
                first_seen DATETIME,
                last_seen DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()

    def load_suspicious_keywords(self):
        return [
            'urgent', 'verify', 'password', 'account', 'security', 'login',
            'update', 'confirm', 'bank', 'paypal', 'amazon', 'microsoft',
            'apple', 'facebook', 'instagram', 'whatsapp', 'telegram',
            'suspended', 'locked', 'verification', 'credentials', 'phishing',
            'immediately', 'action required', 'dear customer', 'dear user'
        ]

    def load_threat_intelligence(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT indicator FROM threat_intelligence WHERE indicator_type = 'domain'")
        for row in cursor.fetchall():
            self.known_phishing_domains.add(row[0])
        conn.close()

    def analyze_email(self, email_content, message_id=None):
        if isinstance(email_content, bytes):
            email_msg = message_from_bytes(email_content)
        else:
            email_msg = email_content

        analysis = {
            'message_id': message_id or self.extract_message_id(email_msg),
            'headers': self.analyze_headers(email_msg),
            'subject': self.analyze_subject(email_msg),
            'body': self.analyze_body(email_msg),
            'urls': self.extract_and_analyze_urls(email_msg),
            'attachments': self.analyze_attachments(email_msg),
            'authentication': self.check_email_auth(email_msg),
            'sender_reputation': self.analyze_sender(email_msg)
        }

        risk_score = self.calculate_risk_score(analysis)
        verdict = self.determine_verdict(risk_score)
        
        analysis['risk_score'] = risk_score
        analysis['verdict'] = verdict
        analysis['timestamp'] = datetime.now()

        self.save_analysis_result(analysis)
        
        if verdict in ['SUSPICIOUS', 'MALICIOUS']:
            self.trigger_alerts(analysis)

        return analysis

    def extract_message_id(self, email_msg):
        return email_msg.get('Message-ID', 'unknown')

    def analyze_headers(self, email_msg):
        headers = {}
        suspicious_headers = []
        
        for header, value in email_msg.items():
            headers[header] = value
            
            if header.lower() in ['from', 'reply-to', 'return-path']:
                if self.is_suspicious_sender(value):
                    suspicious_headers.append(f"Suspicious {header}: {value}")
            
            if header.lower() == 'received':
                if self.analyze_received_header(value):
                    suspicious_headers.append(f"Suspicious Received header: {value}")

        return {
            'all_headers': headers,
            'suspicious_headers': suspicious_headers,
            'sender': email_msg.get('From', ''),
            'recipient': email_msg.get('To', ''),
            'subject': email_msg.get('Subject', '')
        }

    def is_suspicious_sender(self, sender):
        suspicious_patterns = [
            r'\d{10}@',  # Numbers in local part
            r'\.ru$',    # Russian domain
            r'\.cn$',    # Chinese domain
            r'reply-',   # Reply patterns
            r'noreply',  # No-reply addresses
            r'@.*\.(tk|ml|ga|cf)$'  # Suspicious TLDs
        ]
        
        sender_lower = sender.lower()
        return any(re.search(pattern, sender_lower) for pattern in suspicious_patterns)

    def analyze_received_header(self, received_header):
        suspicious_indicators = [
            'unknown',
            'localhost',
            '127.0.0.1',
            'relay',
            'proxy'
        ]
        return any(indicator in received_header.lower() for indicator in suspicious_indicators)

    def analyze_subject(self, email_msg):
        subject = email_msg.get('Subject', '')
        subject_lower = subject.lower()
        
        suspicious_indicators = []
        score = 0
        
        for keyword in self.suspicious_keywords:
            if keyword in subject_lower:
                suspicious_indicators.append(f"Suspicious keyword: {keyword}")
                score += 1
        
        if re.search(r'[!]{2,}', subject):
            suspicious_indicators.append("Multiple exclamation marks")
            score += 1
        
        if re.search(r'\bURGENT\b', subject, re.IGNORECASE):
            suspicious_indicators.append("URGENT in subject")
            score += 1

        return {
            'subject': subject,
            'suspicious_indicators': suspicious_indicators,
            'score': score
        }

    def analyze_body(self, email_msg):
        body = ""
        if email_msg.is_multipart():
            for part in email_msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
        else:
            body = email_msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        suspicious_indicators = []
        score = 0
        
        body_lower = body.lower()
        
        for keyword in self.suspicious_keywords:
            if keyword in body_lower:
                count = body_lower.count(keyword)
                suspicious_indicators.append(f"Suspicious keyword '{keyword}' found {count} times")
                score += min(count, 3)
        
        if re.search(r'click here|click below|click this link', body_lower):
            suspicious_indicators.append("Suspicious call-to-action")
            score += 1
        
        if re.search(r'password.*enter|login.*credentials', body_lower):
            suspicious_indicators.append("Credentials harvesting attempt")
            score += 2

        return {
            'body_preview': body[:500] + '...' if len(body) > 500 else body,
            'suspicious_indicators': suspicious_indicators,
            'score': score
        }

    def extract_and_analyze_urls(self, email_msg):
        urls = self.extract_urls(email_msg)
        analyzed_urls = []
        
        with ThreadPoolExecutor(max_workers=self.config['analysis']['max_workers']) as executor:
            futures = [executor.submit(self.analyze_url, url) for url in urls]
            for future in futures:
                try:
                    analyzed_urls.append(future.result(timeout=self.config['analysis']['timeout']))
                except:
                    pass
        
        return analyzed_urls

    def extract_urls(self, email_msg):
        urls = set()
        
        if email_msg.is_multipart():
            for part in email_msg.walk():
                content_type = part.get_content_type()
                if content_type in ['text/plain', 'text/html']:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode('utf-8', errors='ignore')
                        urls.update(self.find_urls_in_text(text))
        else:
            payload = email_msg.get_payload(decode=True)
            if payload:
                text = payload.decode('utf-8', errors='ignore')
                urls.update(self.find_urls_in_text(text))
        
        return list(urls)

    def find_urls_in_text(self, text):
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)

    def analyze_url(self, url):
        analysis = {
            'url': url,
            'domain': self.extract_domain(url),
            'suspicious_indicators': [],
            'reputation_score': 0,
            'threat_type': None
        }
        
        domain = analysis['domain']
        
        if self.is_known_phishing_domain(domain):
            analysis['suspicious_indicators'].append("Known phishing domain")
            analysis['reputation_score'] -= 3
            analysis['threat_type'] = 'PHISHING'
        
        if self.is_suspicious_url(url):
            analysis['suspicious_indicators'].append("Suspicious URL structure")
            analysis['reputation_score'] -= 2
        
        if self.config['analysis']['check_url_reputation']:
            vt_score = self.check_virustotal(url)
            if vt_score:
                analysis['reputation_score'] += vt_score
                if vt_score < -2:
                    analysis['threat_type'] = 'MALICIOUS'
        
        if self.is_ip_address(domain):
            analysis['suspicious_indicators'].append("IP address in URL")
            analysis['reputation_score'] -= 1
        
        if len(url) > 100:
            analysis['suspicious_indicators'].append("Very long URL")
            analysis['reputation_score'] -= 1
        
        return analysis

    def extract_domain(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ""

    def is_known_phishing_domain(self, domain):
        return domain in self.known_phishing_domains

    def is_suspicious_url(self, url):
        suspicious_patterns = [
            r'login\.',
            r'verify\.',
            r'account\.',
            r'security\.',
            r'password\.',
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',
            r'\d+\.\d+\.\d+\.\d+'  # IP address
        ]
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns)

    def is_ip_address(self, domain):
        ip_pattern = r'^\d+\.\d+\.\d+\.\d+$'
        return re.match(ip_pattern, domain) is not None

    def check_virustotal(self, url):
        api_key = self.config['alerting']['virustotal_api_key']
        if not api_key:
            return 0
        
        try:
            url_id = hashlib.sha256(url.encode()).hexdigest()
            headers = {'x-apikey': api_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers,
                timeout=self.config['analysis']['timeout']
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                return - (malicious * 2 + suspicious)
        
        except Exception as e:
            self.logger.error(f"VirusTotal check failed: {e}")
        
        return 0

    def analyze_attachments(self, email_msg):
        attachments = []
        
        if email_msg.is_multipart():
            for part in email_msg.walk():
                content_disposition = part.get('Content-Disposition', '')
                if 'attachment' in content_disposition or part.get_filename():
                    attachment_analysis = self.analyze_attachment(part)
                    attachments.append(attachment_analysis)
        
        return attachments

    def analyze_attachment(self, part):
        filename = part.get_filename()
        content_type = part.get_content_type()
        
        analysis = {
            'filename': filename,
            'content_type': content_type,
            'suspicious_indicators': [],
            'risk_score': 0
        }
        
        if filename:
            if self.is_suspicious_filename(filename):
                analysis['suspicious_indicators'].append("Suspicious filename")
                analysis['risk_score'] += 2
            
            if self.is_executable_extension(filename):
                analysis['suspicious_indicators'].append("Executable file extension")
                analysis['risk_score'] += 3
            
            if self.is_double_extension(filename):
                analysis['suspicious_indicators'].append("Double file extension")
                analysis['risk_score'] += 2
        
        if content_type in ['application/x-msdownload', 'application/x-msdos-program']:
            analysis['suspicious_indicators'].append("Executable content type")
            analysis['risk_score'] += 3
        
        return analysis

    def is_suspicious_filename(self, filename):
        suspicious_patterns = [
            r'invoice', r'payment', r'urgent', r'important',
            r'document', r'scan', r'photo', r'image',
            r'\.exe$', r'\.scr$', r'\.bat$', r'\.cmd$',
            r'\.vbs$', r'\.js$', r'\.jar$'
        ]
        filename_lower = filename.lower()
        return any(re.search(pattern, filename_lower) for pattern in suspicious_patterns)

    def is_executable_extension(self, filename):
        executable_extensions = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar', '.ps1']
        return any(filename.lower().endswith(ext) for ext in executable_extensions)

    def is_double_extension(self, filename):
        parts = filename.split('.')
        return len(parts) > 2 and any(
            parts[-1].lower() in ['exe', 'scr', 'bat', 'cmd', 'vbs', 'js'] and
            parts[-2].lower() in ['pdf', 'doc', 'xls', 'jpg', 'png']
            for i in range(len(parts) - 1)
        )

    def check_email_auth(self, email_msg):
        auth_results = {
            'spf': self.check_spf(email_msg),
            'dkim': self.check_dkim(email_msg),
            'dmarc': self.check_dmarc(email_msg)
        }
        
        failures = []
        if auth_results['spf'] == 'FAIL':
            failures.append('SPF')
        if auth_results['dkim'] == 'FAIL':
            failures.append('DKIM')
        if auth_results['dmarc'] == 'FAIL':
            failures.append('DMARC')
        
        auth_results['failures'] = failures
        return auth_results

    def check_spf(self, email_msg):
        return 'PASS'

    def check_dkim(self, email_msg):
        return 'PASS'

    def check_dmarc(self, email_msg):
        return 'PASS'

    def analyze_sender(self, email_msg):
        sender = email_msg.get('From', '')
        domain = self.extract_domain_from_sender(sender)
        
        analysis = {
            'sender': sender,
            'domain': domain,
            'reputation_score': 0,
            'suspicious_indicators': []
        }
        
        if self.is_new_domain(domain):
            analysis['suspicious_indicators'].append("Newly registered domain")
            analysis['reputation_score'] -= 1
        
        if self.is_suspicious_domain(domain):
            analysis['suspicious_indicators'].append("Suspicious domain")
            analysis['reputation_score'] -= 2
        
        return analysis

    def extract_domain_from_sender(self, sender):
        match = re.search(r'@([\w.-]+)', sender)
        return match.group(1) if match else ""

    def is_new_domain(self, domain):
        return False

    def is_suspicious_domain(self, domain):
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        return any(domain.endswith(tld) for tld in suspicious_tlds)

    def calculate_risk_score(self, analysis):
        weights = self.config['scoring']['weights']
        score = 0
        
        score += len(analysis['headers']['suspicious_headers']) * weights['suspicious_sender']
        score += analysis['subject']['score'] * weights['suspicious_subject']
        score += analysis['body']['score']
        
        for url in analysis['urls']:
            score += abs(url['reputation_score']) * weights['suspicious_urls']
            if url['threat_type'] == 'PHISHING':
                score += weights['known_phishing_domain']
        
        for attachment in analysis['attachments']:
            score += attachment['risk_score'] * weights['suspicious_attachments']
        
        for auth_failure in analysis['authentication']['failures']:
            if auth_failure == 'SPF':
                score += weights['spf_failure']
            elif auth_failure == 'DKIM':
                score += weights['dkim_failure']
            elif auth_failure == 'DMARC':
                score += weights['dmarc_failure']
        
        return min(score, 10)

    def determine_verdict(self, risk_score):
        if risk_score >= self.config['scoring']['malicious_threshold']:
            return 'MALICIOUS'
        elif risk_score >= self.config['scoring']['suspicious_threshold']:
            return 'SUSPICIOUS'
        else:
            return 'CLEAN'

    def save_analysis_result(self, analysis):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO email_analysis 
            (message_id, sender, subject, recipient, analysis_result, risk_score, verdict)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis['message_id'],
            analysis['headers']['sender'],
            analysis['headers']['subject'],
            analysis['headers']['recipient'],
            json.dumps(analysis, default=str),
            analysis['risk_score'],
            analysis['verdict']
        ))
        
        conn.commit()
        conn.close()

    def trigger_alerts(self, analysis):
        message = f"""
Phishing Alert - {analysis['verdict']}

Message ID: {analysis['message_id']}
From: {analysis['headers']['sender']}
Subject: {analysis['headers']['subject']}
Risk Score: {analysis['risk_score']}/10

Suspicious Indicators:
- URLs: {len([u for u in analysis['urls'] if u['reputation_score'] < 0])}
- Attachments: {len([a for a in analysis['attachments'] if a['risk_score'] > 0])}
- Authentication Failures: {', '.join(analysis['authentication']['failures'])}

Immediate investigation required!
"""

        threads = []
        
        if self.config['alerting']['smtp']['username']:
            threads.append(threading.Thread(target=self.send_email_alert, args=(analysis, message)))
        
        if self.config['alerting']['slack_webhook']:
            threads.append(threading.Thread(target=self.send_slack_alert, args=(analysis, message)))
        
        if self.config['alerting']['discord_webhook']:
            threads.append(threading.Thread(target=self.send_discord_alert, args=(analysis, message)))
        
        for thread in threads:
            thread.start()
        
        self.log_security_event(analysis)

    def send_email_alert(self, analysis, message):
        try:
            smtp_config = self.config['alerting']['smtp']
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            server.starttls()
            server.login(smtp_config['username'], smtp_config['password'])
            
            msg = MimeText(message)
            msg['From'] = smtp_config['from_email']
            msg['To'] = smtp_config['to_email']
            msg['Subject'] = f"🚨 Phishing Alert: {analysis['verdict']} - {analysis['headers']['sender']}"
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for {analysis['message_id']}")
        except Exception as e:
            self.logger.error(f"Email alert failed: {e}")

    def send_slack_alert(self, analysis, message):
        try:
            webhook_url = self.config['alerting']['slack_webhook']
            color = "#ff0000" if analysis['verdict'] == 'MALICIOUS' else "#ffa500"
            
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"Phishing Alert: {analysis['verdict']}",
                        "text": message,
                        "fields": [
                            {
                                "title": "Sender",
                                "value": analysis['headers']['sender'],
                                "short": True
                            },
                            {
                                "title": "Risk Score",
                                "value": f"{analysis['risk_score']}/10",
                                "short": True
                            }
                        ],
                        "ts": datetime.now().timestamp()
                    }
                ]
            }
            
            requests.post(webhook_url, json=payload, timeout=10)
            self.logger.info(f"Slack alert sent for {analysis['message_id']}")
        except Exception as e:
            self.logger.error(f"Slack alert failed: {e}")

    def send_discord_alert(self, analysis, message):
        try:
            webhook_url = self.config['alerting']['discord_webhook']
            color = 0xff0000 if analysis['verdict'] == 'MALICIOUS' else 0xffa500
            
            embed = {
                "title": f"🚨 Phishing Alert: {analysis['verdict']}",
                "description": message,
                "color": color,
                "timestamp": datetime.now().isoformat(),
                "fields": [
                    {
                        "name": "Message ID",
                        "value": analysis['message_id'][:50],
                        "inline": True
                    },
                    {
                        "name": "Risk Score",
                        "value": f"{analysis['risk_score']}/10",
                        "inline": True
                    }
                ]
            }
            
            payload = {"embeds": [embed]}
            requests.post(webhook_url, json=payload, timeout=10)
            self.logger.info(f"Discord alert sent for {analysis['message_id']}")
        except Exception as e:
            self.logger.error(f"Discord alert failed: {e}")

    def log_security_event(self, analysis):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (event_type, message_id, sender, description, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            'PHISHING_DETECTED',
            analysis['message_id'],
            analysis['headers']['sender'],
            f"Phishing email detected with risk score {analysis['risk_score']}",
            'HIGH' if analysis['verdict'] == 'MALICIOUS' else 'MEDIUM'
        ))
        
        conn.commit()
        conn.close()

    def add_threat_intelligence(self, indicator, indicator_type='domain', threat_type='PHISHING', confidence=80):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO threat_intelligence 
            (indicator, indicator_type, threat_type, confidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, COALESCE((SELECT first_seen FROM threat_intelligence WHERE indicator = ?), datetime('now')), datetime('now'))
        ''', (indicator, indicator_type, threat_type, confidence, indicator))
        
        conn.commit()
        conn.close()
        
        if indicator_type == 'domain':
            self.known_phishing_domains.add(indicator)
        
        self.logger.info(f"Threat intelligence added: {indicator}")

    def generate_report(self, hours=24, output_format='text'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_emails,
                SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious,
                SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
                SUM(CASE WHEN verdict = 'CLEAN' THEN 1 ELSE 0 END) as clean,
                AVG(risk_score) as avg_risk_score
            FROM email_analysis 
            WHERE timestamp > datetime('now', '-? hours')
        ''', (hours,))
        
        stats = cursor.fetchone()
        
        cursor.execute('''
            SELECT sender, COUNT(*) as count
            FROM email_analysis 
            WHERE verdict IN ('MALICIOUS', 'SUSPICIOUS') 
            AND timestamp > datetime('now', '-? hours')
            GROUP BY sender 
            ORDER BY count DESC 
            LIMIT 10
        ''', (hours,))
        
        top_senders = cursor.fetchall()
        
        conn.close()
        
        report_data = {
            'time_period_hours': hours,
            'total_emails': stats[0],
            'malicious': stats[1],
            'suspicious': stats[2],
            'clean': stats[3],
            'avg_risk_score': round(stats[4] or 0, 2),
            'top_suspicious_senders': [{'sender': s[0], 'count': s[1]} for s in top_senders]
        }
        
        if output_format == 'json':
            return json.dumps(report_data, indent=2, default=str)
        elif output_format == 'csv':
            csv_output = "metric,value\n"
            csv_output += f"total_emails,{stats[0]}\n"
            csv_output += f"malicious,{stats[1]}\n"
            csv_output += f"suspicious,{stats[2]}\n"
            csv_output += f"clean,{stats[3]}\n"
            csv_output += f"avg_risk_score,{round(stats[4] or 0, 2)}\n"
            return csv_output
        else:
            output = f"Phishing Detection Report (Last {hours} hours)\n"
            output += "=" * 50 + "\n"
            output += f"Total Emails Analyzed: {stats[0]}\n"
            output += f"Malicious: {stats[1]}\n"
            output += f"Suspicious: {stats[2]}\n"
            output += f"Clean: {stats[3]}\n"
            output += f"Average Risk Score: {round(stats[4] or 0, 2)}/10\n\n"
            
            output += "Top Suspicious Senders:\n"
            for sender in top_senders:
                output += f"  {sender[0]}: {sender[1]} emails\n"
            
            return output

def main():
    parser = argparse.ArgumentParser(description='Phishing Email Detector')
    parser.add_argument('--analyze-file', help='Analyze email from file')
    parser.add_argument('--add-threat', help='Add domain to threat intelligence')
    parser.add_argument('--threat-type', default='PHISHING', help='Threat type for added indicator')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--hours', type=int, default=24, help='Hours for report generation')
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text', help='Report format')
    
    args = parser.parse_args()
    
    detector = PhishingDetector()
    
    if args.add_threat:
        detector.add_threat_intelligence(args.add_threat, threat_type=args.threat_type)
        return
    
    if args.analyze_file:
        if os.path.exists(args.analyze_file):
            with open(args.analyze_file, 'rb') as f:
                email_content = f.read()
                result = detector.analyze_email(email_content)
                print(f"Analysis Result: {result['verdict']}")
                print(f"Risk Score: {result['risk_score']}/10")
                print(f"Suspicious URLs: {len(result['urls'])}")
                print(f"Suspicious Attachments: {len(result['attachments'])}")
        else:
            print(f"File not found: {args.analyze_file}")
    
    if args.report:
        report = detector.generate_report(args.hours, args.format)
        print(report)

if __name__ == "__main__":
    main()
