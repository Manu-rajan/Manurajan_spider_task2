# Basic Recon Automation Tool

This is a Level 1 Cybersecurity Reconnaissance Automation script written in Python. It automates fundamental recon tasks to replace manual steps during information gathering.

---

## Features

The tool performs the following tasks:

1. **Domain Input**

   - Accepts a target domain from command-line arguments.

2. **Subdomain Enumeration**

   - Uses [crt.sh](https://crt.sh/) certificate transparency logs.
   - Uses [Sublist3r](https://github.com/aboul3la/Sublist3r) for passive enumeration.

3. **DNS Record Lookup**

   - Fetches A, NS, MX records using `dnspython`.

4. **WHOIS Information**

   - Retrieves WHOIS details using `python-whois` or CLI fallback.

5. **HTTP Headers**

   - Grabs headers using `requests` library.

6. **robots.txt & sitemap.xml**

   - Fetches content of `/robots.txt` and `/sitemap.xml`.

7. **GeoIP Lookup**

   - Gets IP geolocation data using `ipinfo.io`.

---

## Setup Instructions

### Python Dependencies

Install using pip:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, install manually:

```bash
pip install requests dnspython python-whois
```

### Install Sublist3r

```bash
sudo apt intsall sublist3r
```

---

## Usage

```bash
python basic_recon.py example.com
```

The tool will print information to the terminal.

---

## Sample Output

Example terminal output includes:

- Subdomains (from crt.sh & Sublist3r)
- A, NS, MX records
- WHOIS data
- Server headers
- robots.txt and sitemap.xml content
- GeoIP information

---

## Deliverables

- `basic_recon.py` – The Python tool script
-  Screenshots of the terminal 
- `README.md` – This file

---


