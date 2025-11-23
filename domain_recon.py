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
from datetime import datetime
import warnings
import urllib3

# Initialize
init(autoreset=True)
console = Console()
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Banner_One
PURPLE = '\033[0;35m' 
END = "\033[0m"

banner = f"""
  {END}
    ███╗   ██╗ █████╗ ███████╗██╗██╗  ██╗███████╗███████╗
    ████╗  ██║██╔══██╗╚══███╔╝██║╚██╗██╔╝██╔════╝██╔════╝
    ██╔██╗ ██║███████║  ███╔╝ ██║ ╚███╔╝ ███████╗███████╗
    ██║╚██╗██║██╔══██║ ███╔╝  ██║ ██╔██╗ ╚════██║╚════██║
    ██║ ╚████║██║  ██║███████╗██║██╔╝ ██╗███████║███████║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
                                                         
    ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗    
    ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║    
    ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║    
    ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║    
    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║    
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝    
                                                         
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗          
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║          
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║          
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║          
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║          
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ """

print(banner)

# Banner_Two
print(Fore.CYAN + "♦*"*28)
print(Fore.YELLOW + "🍓 Professional Domain Recon Tool - Secure & Ethical 🍓")
print(Fore.CYAN + "♦*"*28 + "\n")

class WhoisClient:
    def __init__(self, timeout=5, proxies=None):
        self.timeout = timeout
        self.proxies = proxies
        self.WhoisServers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'ir': 'whois.nic.ir',
        }
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 3
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        })
        if proxies:
            self.session.proxies.update(proxies)

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
                parsed_data.update({
                    "Subdomains": self.FindSubdomains(domain),
                    "IP Addresses": self.GetIPs(domain),
                    "TXT Records": self.GetTXTRecords(domain),
                })
                self.CheckExpiryWarning(parsed_data)
                return parsed_data
        except Exception as e:
            raise ValueError(f"{Fore.RED}WHOIS query failed: {str(e)}")

    def FindSubdomains(self, domain):
        subdomains = set()
        
        # Method 1: Certificate Transparency Logs (with improved error handling)
        try:
            response = self.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15,
                verify=False
            )
            if response.status_code == 200:
                for entry in response.json():
                    name = entry['name_value']
                    if name.startswith('*.'):
                        subdomains.add(name[2:])
                    else:
                        subdomains.add(name)
        except requests.exceptions.RequestException as e:
            if "SOCKSHTTPSConnectionPool" in str(e):
                # Retry without proxy if SOCKS fails
                try:
                    response = requests.get(
                        f"https://crt.sh/?q=%25.{domain}&output=json",
                        headers={'User-Agent': 'Mozilla/5.0'},
                        timeout=15,
                        verify=False
                    )
                    if response.status_code == 200:
                        for entry in response.json():
                            name = entry['name_value']
                            subdomains.add(name.replace('*.', ''))
                except:
                    pass
            else:
                pass
        
        # Method 2: Common Subdomain Brute-forcing
        common_subs = ['www', 'mail', 'ftp', 'admin', 'webmail', 'ns1', 'ns2']
        for sub in common_subs:
            try:
                self.resolver.resolve(f"{sub}.{domain}", 'A')
                subdomains.add(f"{sub}.{domain}")
            except:
                continue
        
        return sorted(subdomains) if subdomains else ["No subdomains found"]

    def GetIPs(self, domain):
        ips = set()
        record_types = ['A', 'AAAA', 'CNAME', 'MX']
        
        for rt in record_types:
            try:
                answers = self.resolver.resolve(domain, rt)
                for rdata in answers:
                    if rt in ['A', 'AAAA']:
                        ips.add(rdata.address)
                    elif rt == 'CNAME':
                        ips.add(str(rdata.target))
                    elif rt == 'MX':
                        ips.add(str(rdata.exchange))
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                continue
            except Exception:
                continue
        
        return sorted(ips) if ips else ["No IP records found"]

    def GetTXTRecords(self, domain):
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata).strip('"') for rdata in answers]
        except dns.resolver.NoAnswer:
            return ["No TXT records found"]
        except Exception:
            return ["TXT records unavailable"]

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

    def CheckExpiryWarning(self, data):
        if 'Expiry Date' in data:
            expiry_date = data['Expiry Date']
            try:
                expiry = datetime.strptime(expiry_date, '%Y-%m-%d')
                if (expiry - datetime.now()).days < 30:
                    data['Expiry Warning'] = "⚠️ Domain expires soon!"
            except ValueError:
                pass

def PrintResults(data):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="white")

    main_fields = [
        'Domain Name', 'Registrar', 'Creation Date',
        'Expiry Date', 'Name Servers', 'Status', 'Expiry Warning'
    ]
    for field in main_fields:
        if field in data:
            value = data[field]
            table.add_row(
                field,
                "\n".join(value) if isinstance(value, list) else str(value),
                style="bold red" if field == 'Expiry Warning' else None
            )

    table.add_row("Subdomains", "\n".join(data.get('Subdomains', ['Not found'])))
    table.add_row("IP/DNS Records", "\n".join(data.get('IP Addresses', ['Not found'])))
    table.add_row("TXT Records", "\n".join(data.get('TXT Records', ['Not found'])))

    console.print(table)

def Main():
    parser = argparse.ArgumentParser(description='N0aziXss WHOIS Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Save result to JSON file')
    parser.add_argument('--csv', help='Export results to CSV')
    parser.add_argument('--raw', action='store_true', help='Show raw response')
    parser.add_argument('--proxies', help='Proxy settings (e.g., http://proxy:port)')
    args = parser.parse_args()

    proxies = {'http': args.proxies, 'https': args.proxies} if args.proxies else None
    client = WhoisClient(proxies=proxies)

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
        
        if args.csv:
            import pandas as pd
            pd.DataFrame([result]).to_csv(args.csv, index=False)
            console.print(f"\n[+] CSV exported to {args.csv}", style="green")
            
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        exit(1)

if __name__ == "__main__":
    Main()