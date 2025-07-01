import argparse
import subprocess
import requests
import whois
import dns.resolver
import sublist3r
import nmap
import socket
import json
import shodan
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def get_args():
    parser = argparse.ArgumentParser(description="Basic Recon Automation Tool")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--crtsh", action="store_true", help="Use crt.sh for subdomain enumeration")
    parser.add_argument("--sublist3r", action="store_true", help="Use Sublist3r for subdomain enumeration")
    parser.add_argument("--dns", action="store_true", help="Get DNS records")
    parser.add_argument("--whois", action="store_true", help="Get WHOIS info")
    parser.add_argument("--http_headers", action="store_true", help="Get HTTP headers")
    parser.add_argument("--robots_site", action="store_true", help="Get robots.txt and site.xml files")
    parser.add_argument("--geoip", action="store_true", help="Get GeoIP info")
    parser.add_argument("--port_banner", action="store_true", help="Perform Nmap port scan and Grab service banners")
    parser.add_argument("--whatweb", action="store_true", help="Detect technologies with WhatWeb")
    parser.add_argument("--harvest", action="store_true", help="Harvest emails using theHarvester")
    parser.add_argument("--shodan", action="store_true", help="Query Shodan for IP")
    parser.add_argument("--gowitness", action="store_true", help="Live screenshots")
    parser.add_argument("--waf00f", action="store_true", help="Get Web Applicatin Firewalls")
    parser.add_argument("--cdn", action="store_true", help="Get CDN services")
    parser.add_argument("--nikto", action="store_true", help="Vulnerabilty Scanning")
    return parser.parse_args()

def enum_crtsh(domain):
    url = f"https://crt.sh/json?q={domain}"
    subdoms = []
    try:
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            for subd in data:
                subdoms.append(subd['name_value'])
    except Exception as e:
        print(f"crt.sh error: {e}")
    return list(set(subdoms))

def enum_sublist3r(domain):
    try:
        subdomains = sublist3r.main(domain, 40,f'{domain}_subdomains.txt', ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
        return subdomains
    except Exception as e:
        print(f"Sublist3r module failed: {e}")
        return []

def dns_records(domain):
    rec_types = ['A', 'NS', 'MX']
    records = {}
    for rtype in rec_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = []
            for ans in answers:
                records[rtype].append(ans.to_text())
        except:
            records[rtype] = []
    return records

def get_whois(domain):
    try:
        w=whois.whois(domain)
        result = {}
        for key, value in dict(w).items():
            result[key] = str(value)
        return result
    except:
        try:
            w=subprocess.check_output(['whois', domain], text=True)
            return w
        except Exception as e:
            return f"WHOIS error: {e}"

def http_headers(domain):
    try:
        res = requests.head(f"http://{domain}", timeout=5)
        return dict(res.headers)
    except Exception as e:
        return {"error": str(e)}


def fetch_url_content(domain, path):
    url = f"http://{domain}{path}"
    try:
        res = requests.get(url, timeout=5)
        return res.text
    except Exception as e:
        return {"error": str(e)}

def geoip_lookup(domain):
    try:
        res = requests.get(f"https://dns.google/resolve?name={domain}&type=A")
        ip = res.json()['Answer'][0]['data']
        geo = requests.get(f"https://ipinfo.io/{ip}/json")
        data = geo.json()
        data['ip']=ip
        return data
    except Exception as e:
        return {"error": str(e)}


def grab_banner(domain, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((domain, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except Exception as e:
        return {"error": str(e)}
    
def port_banner(domain):
    nm = nmap.PortScanner()
    try:
        nm.scan(domain, arguments="-p 1-1024 -T4")
    except Exception as e:
        print(f"Error running nmap: {e}")
        return {}

    scan_results = {}
    for host in nm.all_hosts():
        scan_results[host] = {}
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                scan_results[host][port] = {"state": state}
                if state == 'open':
                    banner = grab_banner(host, port)
                    scan_results[host][port]["banner"] = banner
    return scan_results


def what_web(domain):
    try:
        output = subprocess.check_output(["whatweb", domain], text=True)
        return output.strip()
    except Exception as e:
        return {"error": str(e)}
    
def harvest_emails(domain):
    try:
        result = subprocess.check_output(["theHarvester", "-d", domain, "-b", "bing", "-l", "50"], text=True)
        return result
    except Exception as e:
        return {"error": str(e)}

def shodan_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        api_key = "hFpHIPMwekn8q69UH27vTsBWYG4x18AK"
        api = shodan.Shodan(api_key)
        result = api.host(ip)
        return result
    except Exception as e:
        return {"error": str(e)}
    
def live_screenshot(domain, output_dir="screenshots"):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        full_output_dir = os.path.join("reports", output_dir, f"{domain}_{timestamp}")
        os.makedirs(full_output_dir, exist_ok=True)
        subprocess.run(["gowitness", "scan","file","-f", f"{domain}_subdomains.txt", "--screenshot-path", full_output_dir], check=True)
    except Exception as e:
        return {"error": str(e)}
    
    
def detect_waf(domain):
    try:
        result = subprocess.run(["wafw00f", domain], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return {"error": str(e)}
    

def detect_cdn(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=10)
        cdn_indicators = []
        cdn_keywords = ["cloudflare", "akamai", "fastly", "cdn", "edge", "incapsula", "sucuri"]

        for key, value in response.headers.items():
            key_lower = key.lower()
            value_lower = value.lower()
            for keyword in cdn_keywords:
                if keyword in key_lower or keyword in value_lower:
                    cdn_indicators.append(f"{key}: {value}")
                    break

        if cdn_indicators:
            return "\n".join(cdn_indicators)
        return "No CDN-related headers found."
    
    except Exception as e:
        return {"error": str(e)}

def nikto(domain, output_path="reports/vuln/summary.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        subprocess.run(["nikto", "-h", f"http://{domain}","-o", output_path,"-Format", "csv"], check=True)
        return output_path
    
    except Exception as e:
        return {"error": str(e)}
    
def generate_html_report(domain, report_data):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    html_content = template.render(domain=domain, report=report_data, generated_at=datetime.now())
    os.makedirs("reports", exist_ok=True)
    output_path = f"reports/{domain}_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\nHTML report saved to {output_path}")

def main():
    args = get_args()
    domain = args.domain
    report={}
    print(f"\nIntermediate Recon for {domain}\n\n")

    if args.crtsh:
        print("Enumerating subdomains via crt.sh....\n")
        report['crtsh'] = enum_crtsh(domain)

    if args.sublist3r:
        print("Enumerating subdomains via Sublist3r....\n")
        report['sublist3r'] = enum_sublist3r(domain)

    if args.dns:
        print("DNS records....\n")
        report['dns_records'] = dns_records(domain)

    if args.whois:
        print("WHOIS info....\n")
        report['whois'] = get_whois(domain)

    if args.http_headers:
        print("HTTP headers....\n")
        report['HTTP_headers'] = http_headers(domain)

    if args.robots_site:
        print("robots.txt and sitemap.xml info....\n")
        for i in ['/robots.txt','/sitemap.xml']:
            report[f'{i}_info'] = fetch_url_content(domain,i)

    if args.geoip:
        print("GeoIP lookup....\n")
        report['Geoip'] = geoip_lookup(domain)

    if args.port_banner:
        print("Fetching Ports and Banner....\n")
        report['Port_scan_and_Banner_grab'] = port_banner(domain)


    if args.whatweb:
        print("Fetching technologies with WhatWeb....\n")
        report['Whatweb_technology'] = what_web(domain)

    if args.harvest:
        print("Harvesting emails....\n")
        report['Emails'] = harvest_emails(domain)

    if args.shodan:
        print("Shodan Look up....\n")
        report['Shodan'] = shodan_lookup(domain)

    if args.gowitness:
        print("Capturing live screenshots of discovered subdomains ....\n")
        report['gowitness']=live_screenshot(domain)

    if args.wafw00f or args.cdn :
        print("Capturing Web Application Firewalls and CDN services....\n")
        security_section = {"waf": detect_waf(domain),"cdn": detect_cdn(domain)}
        report["security"] = security_section
   
    if args.nikto:
         print("Basic Vulnerability Scanning....\n")
         report['nikto']=nikto(domain)

 


    generate_html_report(domain, report)



main()