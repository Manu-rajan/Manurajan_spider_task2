
import argparse
import subprocess
import requests
import whois
import dns.resolver
import sublist3r

def get_args():
    parser = argparse.ArgumentParser(description="Basic Recon Automation Tool")
    parser.add_argument("domain", help="Target domain")
    return parser.parse_args()

def enum_crtsh(domain):
    url = f"https://crt.sh/json?q={domain}"
    try:
        res = requests.get(url)
        subdoms=[]
        if res.status_code == 200:
            data = res.json()
            for subd in data:
                subdoms.append(subd['name_value'])
        print(f"\nSubdomains found using crt.sh is stored in {domain}_crt.txt")
        f=open(rf'{domain}_crt.txt','w')
        for subd in list(set(subdoms)):
            f.write(subd+"\n")
        f.close()
        x=input("Do you want to view the content of the file [Y/n]")
        if x.lower()== 'y':
            print("\n")
            f=open(rf'{domain}_crt.txt','r')
            print(f.read())
            f.close()
        elif x.lower()== 'n':
            pass
        else:
            print("Invalid option")
        return subdoms

    except Exception as e:
        print(f"crt.sh error: {e}")
        return []

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
    print('For MX rec is stored as ["priority no","mail server"]\n')
    for rtype in rec_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = []
            for ans in answers:
                records[rtype].append(ans.to_text())
        except:
            records[rtype] = []
    for rtype, values in records.items():
        print(rtype, values)

def get_whois(domain):
    try:
        w=whois.whois(domain)
        for key, value in w.items():
            print(f"{key}: {value}")
    except:
        try:
            w=subprocess.check_output(['whois', domain], text=True)
            print(w)
        except Exception as e:
            return f"WHOIS error: {e}"

def http_headers(domain):
    try:
        res = requests.head(f"http://{domain}", timeout=5)
        for k, v in res.headers.items():
            print(f"{k}:{v}")
    except:
        print("Could not fetch HTTP headers")


def fetch_url_content(domain, path):
    url = f"http://{domain}{path}"
    try:
        res = requests.get(url, timeout=5)
        print(res.text)
    except:
        print("Not Found")

def geoip_lookup(domain):
    try:
        res = requests.get(f"https://dns.google/resolve?name={domain}&type=A")
        ip = res.json()['Answer'][0]['data']
        geo = requests.get(f"https://ipinfo.io/{ip}/json")
        data = geo.json()
        print(f"IP Address: {ip}")
        print("GeoIP Info:")
        for key, value in data.items():
            print(f"{key}: {value}")
    except:
        print("Could not perform GeoIP lookup.")


def main():
    args = get_args()
    domain = args.domain
    print(f"\nBasic Recon for {domain}\n\n")

    print("Enumerating subdomains via crt.sh....\n")
    crtsh = enum_crtsh(domain)


    print("\nEnumerating subdomains via Sublist3r....\n")
    sbs = enum_sublist3r(domain)
    
    print("\nDNS records....\n")
    dns_recs = dns_records(domain)

    print("\nWHOIS info....\n")
    get_whois(domain)

    print("\nHTTP headers....\n")
    http_headers(domain)

    print("\nFetching robots.txt and sitemap.xml ....\n")
    print("Robots.txt...\n")
    fetch_url_content(domain, '/robots.txt')
    print("\nSitemap.xml...\n")
    fetch_url_content(domain, '/sitemap.xml')

    print("\nGeoIP lookup....\n")
    geoip_lookup(domain)



main()
