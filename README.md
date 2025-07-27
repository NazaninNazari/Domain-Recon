# N0aziXss Domain Recon v3.1 🍓

## 🌟 Introduction
**N0aziXss Domain Recon** A powerful WHOIS and DNS reconnaissance tool for domain analysis, subdomain enumeration, and network intelligence.  

## Features ✨
- Improved error handling and stability
- Faster DNS resolution
- Better subdomain discovery
- Proxy support (SOCKS/HTTP)
- Cleaner output format

## Technical Specifications 🛠️
1. Badges: Shows license and Python version at a glance.  
2. Structured Commands: Clear code blocks and tables.  
3. Technical Depth: Code structure and dependency visibility.  
4. Legal Compliance: Explicit ethical guidelines.  
5. Contributor-Friendly: Clear steps for community involvement.

## Legal & Ethical Notice ⚠️
This tool is for authorized security testing and educational purposes only.  
Unauthorized use against domains without permission is illegal.

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com/NazaninNazari/Domain-Recon.git  
cd Domain-Recon-tools  

# install dependencies
pip install -r requirements.txt

# run the scanner
python domain_recon.py

# Usage
1.basic command
```bash
python domain_recon.py -d example.com  

2.sava result to JSON
```bash
python domain_recon.py -d example.com -o results.json  

3.raw JSON output
```bash
python domain_recon.py -d example.com --raw  

4.Use proxy server
```bash
python domain_recon.py -d example.com --proxies socks5://127.0.0.1:9050

5.Export to CSV
```bash
python domain_recon.py -d example.com --csv report.csv

7.Full scan with all options
```bash
python domain_recon.py -d example.com -o results.json --csv report.csv --proxies http://proxy:8080

# Sample Output
1. Badges: Shows license and Python version at a glance.  
2. Structured Commands: Clear code blocks and tables.  
3. Technical Depth: Code structure and dependency visibility.  
4. Legal Compliance: Explicit ethical guidelines.  
5. Contributor-Friendly: Clear steps for community involvement.  