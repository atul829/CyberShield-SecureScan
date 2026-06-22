# 🛡️ CyberShield - AI-Powered Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Groq](https://img.shields.io/badge/Groq-API-orange.svg)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📌 Overview

CyberShield is an AI-powered vulnerability scanner that combines **Nmap** with **Groq/DeepSeek/Ollama** AI to automatically detect, analyze, and prioritize security vulnerabilities.

## ✨ Features

- 🔍 **Automated Scanning** - Uses Nmap for comprehensive port/service discovery
- 🤖 **AI-Powered Analysis** - Leverages Groq/DeepSeek/Ollama for intelligent vulnerability assessment
- 📊 **OWASP/CWE/CAPEC Mapping** - Industry-standard vulnerability classification
- 📄 **Professional Reports** - HTML/JSON/CSV/XML/TXT output formats
- 🎯 **Multiple Scan Profiles** - Quick, Full, Discovery, and Custom scans
- 🔒 **Safe & Ethical** - Built with responsible disclosure in mind

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/atul829/CyberShield-SecureScan-v2.git
cd CyberShield-SecureScan-v2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Configuration
Create a .env file:

env
GROQ_API_KEY=your_groq_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
Usage
bash
# Basic scan
python vulnscanner.py -t 127.0.0.1

# With Groq AI
python vulnscanner.py -t 127.0.0.1 --provider groq --trust-ai-html -o html

# Public target
python vulnscanner.py -t juice-shop.herokuapp.com --provider groq -o html
📊 Sample Reports
Localhost Scan

Juice Shop Scan

🔐 Ethical Usage
⚠️ IMPORTANT: This tool is for authorized testing only. Always obtain explicit permission before scanning any system.

📝 License
MIT License - Free for personal and commercial use.

🤝 Contributing
Contributions welcome! Please open an issue or PR.

📬 Contact
Email: your-email@example.com

LinkedIn: Your Profile

Made with ❤️ by Atul
