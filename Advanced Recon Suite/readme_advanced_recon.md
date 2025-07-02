# Advanced Recon Suite

This is a Level 3 Cybersecurity Reconnaissance Automation tool that extends prior levels into a professional-grade toolkit with advanced features like live screenshots, WAF/CDN detection, vulnerability scanning, and polished HTML reporting.

---

## Features

The Advanced Recon Suite performs the following tasks:

1. **Subdomain Enumeration**

   - Via crt.sh API and Sublist3r.

2. **DNS Record Lookup**

   - A, NS, MX using dnspython.

3. **WHOIS Lookup**

   - Using `python-whois` and CLI fallback.

4. **HTTP Header Inspection**

   - Server details via requests.

5. **robots.txt & sitemap.xml Retrieval**

   - Basic crawl protection intel.

6. **GeoIP Lookup**

   - Using `ipinfo.io` for GeoIP lookup.

7. **Port Scanning + Banner Grabbing**

   - Port scanning using `nmap` and Banner Grabbing using `socket`.

8. **Technology Detection**

   - Fetch Email's using WhatWeb CLI.

9. **Email Harvesting**

   - Retrives Email using theHarvester.

10. **Shodan Intelligence**

- Retrives IP intelligence using the Shodan API.

11. **Live Screenshots**

- Using `gowitness` to capture live screenshots.

12. **WAF/CDN Detection**

- Using `wafw00f` and HTTP header analysis.

13. **Vulnerability Scanning (Optional)**

- Using Nikto and storing results in CSV.

14. **HTML Report Generation**

- Reports are summarized with Jinja2 templates.

---

## Setup Instructions

### Docker

Build and run inside Docker for full dependency support:

```bash
docker build -f advanced_docker -t advanced-recon 
docker run --rm -v $(pwd)/reports:/app/reports advanced-recon example.com --crtsh --dns --gowitness --nikto
```

### Manual Setup

#### Create & Activate a Virtual Environment
Using a virtual environment is recommended to avoid "externally managed environment" errors:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install system tools (Debian-based):

```bash
sudo apt install nmap nikto whatweb whois git chromium chromium-driver
```

Download gowitness binary:

```bash
sudo wget https://github.com/sensepost/gowitness/releases/download/2.5.0/gowitness-2.5.0-linux-amd64 -O /usr/local/bin/gowitness
sudo chmod +x /usr/local/bin/gowitness
```

---

##  Usage

```bash
python advanced_recon.py example.com --crtsh --dns --port_banner --whatweb --shodan --gowitness --nikto
```

All module flags are optional — you can choose what to run.

---

##  Output

- HTML Report: `reports/example.com_report.html`
- Screenshots: `reports/screenshots/example.com_<timestamp>/`
- Vulnerability CSV: `reports/vuln/summary.csv`

---

##  Deliverables

- `advanced_recon.py` — The main script
- `reports/` — Output folder (screenshots, HTML summary report)
- `README.md` — This documentation

---

