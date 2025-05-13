import socket
import argparse
import re
import json
import tldextract
import dns.resolver
import requests
from colorama import Fore, init
from pyfiglet import Figlet
from ratelimit import limits, sleep_and_retry
from rich.console import Console
from rich.table import Table

# Initialize
init(autoreset=True)
console = Console()

# Banner
BANNER = Figlet(font='slant').renderText('Domain Recon')
console.print(Fore.CYAN + BANNER)
print(Fore.CYAN + "♦*"*27)
print(Fore.GREEN + "🍓Professional Domain Recon Tool - Secure & Ethical🍓")
print(Fore.CYAN + "♦*"*27 + "\n")

class WhoisClient:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.WhoisServers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'ir': 'whois.nic.ir',
        }
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3

    def GetWhoisServer(self, TLD):
        return self.WhoisServers.get(TLD, 'whois.iana.org')

    @sleep_and_retry
    @limits(calls=3, period=60)
    def Query(self, domain):
        domain = self.ValidateDomain(domain)
        TLD = tldextract.extract(domain).suffix
        WhoisServer = self.GetWhoisServer(TLD)
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((WhoisServer, 43))
                s.send(f"{domain}\r\n".encode())
                response = b''
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data
                parsed_data = self.ParseWhoisResponse(response.decode())
                # Adding subdomains and IPs with advanced methods
                parsed_data.update({
                    "Subdomains": self.FindSubdomains(domain),
                    "IP Addresses": self.GetIPs(domain)
                })
                return parsed_data
        except Exception as e:
            raise ValueError(f"{Fore.RED}WHOIS query failed: {str(e)}")

    def FindSubdomains(self, domain):
        # Discovering subdomains by combining different methods
        subdomains = set()
        
        # Method 1: Search Certificate Transparency Logs
        try:
            ct_logs = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if ct_logs.status_code == 200:
                for entry in ct_logs.json():
                    name = entry['name_value']
                    if name.startswith('*.'):
                        subdomains.add(name.replace('*.', ''))
                    else:
                        subdomains.add(name)
        except:
            pass
        
        # Method 2: DNS Brute-force with Dynamic Pattern
        try:
            answers = self.resolver.resolve(domain, 'NS')
            for ns in answers:
                try:
                    Xfr = dns.Query.xfr(str(ns), domain, timeout=5)
                    for record in Xfr:
                        if record.DataType == dns.RDataType.NS:
                            subdomains.add(str(record.name))
                except:
                    continue
        except:
            pass
        
        return list(subdomains)

    def GetIPs(self, domain):
        # Get all relevant DNS records
        ips = set()
        record_types = ['A', 'AAAA', 'CNAME', 'MX']
        
        for rt in record_types:
            try:
                answers = self.resolver.resolve(domain, rt)
                for RData in answers:
                    if rt == 'A':
                        ips.add(RData.address)
                    elif rt == 'AAAA':
                        ips.add(RData.address)
                    elif rt in ['CNAME', 'MX']:
                        ips.add(str(RData.target))
            except:
                continue
        
        return list(ips)

    def ValidateDomain(self, domain):
        pattern = r'^([a-z0-9-]+\.)+[a-z]{2,}$'
        if not re.match(pattern, domain.lower()):
            raise ValueError(f"{Fore.RED}Invalid domain format!")
        return domain.lower().strip()

    def ParseWhoisResponse(self, response):
        parsed = {}
        important_fields = {
            'domain name': 'Domain Name',
            'registrar': 'Registrar',
            'creation date': 'Creation Date',
            'expiry date': 'Expiry Date',
            'name server': 'Name Servers',
            'registrant': 'Registrant',
            'status': 'Status'
        }
        
        for line in response.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                if key in important_fields:
                    clean_key = important_fields[key]
                    if clean_key == 'Name Servers':
                        parsed.setdefault(clean_key, []).append(value.strip().lower())
                    else:
                        parsed[clean_key] = value.strip()
        return parsed

def PrintResults(data):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="white")

    # Show main fields
    main_fields = ['Domain Name', 'Registrar', 'Creation Date', 
                  'Expiry Date', 'Name Servers', 'Status']
    for field in main_fields:
        if field in data:
            value = data[field]
            table.add_row(field, "\n".join(value) if isinstance(value, list) else value)

    table.add_row("Subdomains", "\n".join(data.get('Subdomains', ['None found'])))
    table.add_row("IP/DNS Records", "\n".join(data.get('IP Addresses', ['None found'])))

    console.print(table)

def Main():
    parser = argparse.ArgumentParser(description='N0aziXss WHOIS Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Save result to JSON file')
    parser.add_argument('--raw', action='store_true', help='Show raw response')
    args = parser.parse_args()

    client = WhoisClient()
    try:
        result = client.Query(args.domain)
        if args.raw:
            console.print_json(json.dumps(result))
        else:
            PrintResults(result)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            console.print(f"\n[+] Results saved to {args.output}", style="green")
            
    except Exception as e:
        console.print(f"Error: {str(e)}", style="bold red")

if __name__ == "__main__":
    Main()