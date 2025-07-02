# Intermediate Recon Toolkit

This is a Level 2 Cybersecurity Reconnaissance Automation tool written in Python. It builds upon the Basic Recon Toolkit by introducing deeper scanning, structured reporting, and additional intelligence gathering.

---

## Features

The toolkit performs the following tasks:

1. **Domain Input**
   - Accepts a domain via CLI argument.

2. **Subdomain Enumeration**
   - Uses crt.sh and Sublist3r to enumerate subdomains.

3. **DNS Records**
   - Retrieves A, NS, MX records using `dnspython`.

4. **WHOIS Lookup**
   - Obtains WHOIS information using `python-whois` or CLI.

5. **HTTP Headers**
   - Fetches headers using the `requests` library.

6. **robots.txt & sitemap.xml**
   - Retrieves and displays these resources if available.

7. **GeoIP Lookup**
   - Uses IP geolocation via `ipinfo.io` API.

8. **Port Scanning**
   - Performs port scan on common ports using `nmap` module.

9. **Banner Grabbing**
   - Grabs open port service banners using `socket`.

10. **Technology Detection**
   - Uses WhatWeb CLI tool for tech stack detection.

11. **Email Harvesting**
   - Uses theHarvester CLI to extract email addresses.

12. **Shodan Lookup**
   - Retrieves IP intelligence using the Shodan API.

13. **Structured Reporting**
   - Outputs results into a structured JSON file.

---

## Setup Instructions


### Manual Setup

#### Create & Activate a Virtual Environment
Using a virtual environment is recommended to avoid "externally managed environment" errors:

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Python dependencies:
```bash
pip install -r requirements.txt
```

### Install system tools:
```bash
sudo apt install nmap whatweb theharvester whois
```
---

## Usage

```bash
python intermediate_recon.py example.com --crtsh --dns --port_banner --whatweb --harvest --shodan
```

You can use any combination of the following flags:
- `--crtsh`
- `--sublist3r`
- `--dns`
- `--geoip`
- `--port_banner`
- `--whatweb`
- `--harvest`
- `--shodan`

---

##  Output

- JSON Report: `reports/example.com_report.json``

---

##  Deliverables

- `intermediate_recon.py` — Python script
- `reports/` — Output file which contains JSON report
- `README.md` — This documentation

---

