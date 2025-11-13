#!/usr/bin/env python3
import argparse
import asyncio
from collections import defaultdict
import aiohttp
import aiodns
import json
import re
import random
import string
import time
import sys
import subprocess
import textwrap
from termcolor import colored
from tqdm import tqdm
from tabulate import tabulate

BANNER = r"""
   _____ __  ______  ____  ____  ________ __ __________ 
  / ___// / / / __ )/ __ \/ __ \/ ____/ //_// ____/ __ \
  \__ \/ / / / __  / / / / / / / /   / ,<  / __/ / /_/ /
 ___/ / /_/ / /_/ / /_/ / /_/ / /___/ /| |/ /___/ _, _/ 
/____/\____/_____/_____/\____/\____/_/ |_/_____/_/ |_|  
                                            -By Amithabh D.K
"""

class Subdocker:
    def __init__(self, domain, wordlist=None, threads=100, output=None, verbose=False,
                 resolve_ips=False, json_output=False, dns_servers=None, timeout=30,
                 rate_limit=5, ports=None, http_probe=False, waf_detect=False,
                 screenshot=False, skip_passive=False, skip_bruteforce=False,
                 ip_file=None, nmap_scan=False):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.resolve_ips = resolve_ips
        self.json_output = json_output
        self.dns_servers = dns_servers or ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.ports = ports or [80, 443]
        self.http_probe = http_probe
        self.waf_detect = waf_detect
        self.screenshot = screenshot
        self.skip_passive = skip_passive
        self.skip_bruteforce = skip_bruteforce
        self.ip_file = ip_file
        self.nmap_scan = nmap_scan
        self.found = set()
        self.resolved = defaultdict(list)
        self.cnames = {}
        self.http_results = {}
        self.waf_detected = {}
        self.semaphore = asyncio.Semaphore(threads)
        self.rate_semaphore = asyncio.Semaphore(rate_limit)
        self.wildcard_ips = set()
        self.session = None
        self.resolver = None
        self.passive_sources = [
            self.crtsh_search,
            self.hackertarget_query,
            self.certspotter_query,
            self.threatminer_query,
            self.urlscan_query,
            self.anubis_query,
            self.virustotal_query,
            self.otx_query,
            self.bufferover_query,
            self.sublist3r_query,
            self.rapiddns_query,
            self.sonar_query,
            self.wayback_query,
            self.commoncrawl_query,
            self.threatcrowd_query
        ]
        self.start_time = time.time()
        self.progress = None

    async def init_resolver(self):
        self.resolver = aiodns.DNSResolver(nameservers=self.dns_servers, timeout=self.timeout)

    async def detect_wildcard(self):
        try:
            # Generate truly random subdomains
            for _ in range(3):
                rand_str = ''.join(random.choices(string.ascii_lowercase, k=10))
                random_sub = f"{rand_str}.{self.domain}"
                try:
                    result = await self.resolver.query(random_sub, 'A')
                    self.wildcard_ips.update(r.host for r in result)
                except aiodns.error.DNSError:
                    pass

            if self.wildcard_ips and self.verbose:
                print(
                    colored(f"[!] Wildcard DNS detected (*.{self.domain} -> {', '.join(self.wildcard_ips)}", "yellow"))
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Wildcard detection error: {str(e)}", "red"))

    async def fetch_url(self, url, headers=None, json_response=False):
        try:
            async with self.rate_semaphore:
                async with self.session.get(url, headers=headers, timeout=self.timeout, ssl=False) as response:
                    if response.status == 200:
                        if json_response:
                            return await response.json()
                        return await response.text()
                    elif response.status == 429:
                        if self.verbose:
                            print(colored(f"[-] Rate limited for {url}. Sleeping for 10s...", "yellow"))
                        await asyncio.sleep(10)
                    elif self.verbose:
                        print(colored(f"[-] HTTP {response.status} from {url}", "red"))
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Error fetching {url}: {str(e)}", "red"))
        return None

    async def query_dns(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain
        if full_domain in self.found:
            return False

        try:
            # Query A records
            result = await self.resolver.query(full_domain, 'A')
            ips = [r.host for r in result]

            # Skip wildcard matches
            if self.wildcard_ips and set(ips).issubset(self.wildcard_ips):
                return False

            self.found.add(full_domain)

            # Query CNAME records
            try:
                cname_result = await self.resolver.query(full_domain, 'CNAME')
                cnames = [r.host for r in cname_result]
                self.cnames[full_domain] = cnames
            except aiodns.error.DNSError:
                pass

            if self.resolve_ips or self.ip_file or self.nmap_scan:
                self.resolved[full_domain] = ips

            if self.verbose:
                display_text = colored(f"[+] Found: {full_domain}", "green")
                if self.resolve_ips or self.ip_file or self.nmap_scan:
                    display_text += colored(f" → {', '.join(ips)}", "cyan")
                if full_domain in self.cnames:
                    display_text += colored(f" (CNAME: {', '.join(self.cnames[full_domain])})", "magenta")
                print(display_text)

            return True
        except aiodns.error.DNSError:
            return False
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] DNS query error for {full_domain}: {str(e)}", "red"))
            return False

    async def process_subdomain(self, name):
        """Process and normalize subdomains from various sources"""
        name = name.strip().lower()
        name = re.sub(r'^\.+|\.+$', '', name)  # Remove  dots
        name = re.sub(r'\*\.?', '', name)  # Remove wildcards

        # Handle different formats
        if name == self.domain:
            return await self.query_dns("")
        elif name.endswith(f".{self.domain}"):
            sub = name[:-len(f".{self.domain}")]
            return await self.query_dns(sub)
        return False

    async def crtsh_search(self):
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        if self.verbose:
            print(colored(f"[*] Querying crt.sh", "blue"))

        data = await self.fetch_url(url)
        if not data:
            if self.verbose:
                print(colored("[-] No response from crt.sh", "red"))
            return

        try:
            entries = json.loads(data)
            for cert in entries:
                names = cert.get('name_value', '')
                if not names:
                    continue

                # Handle both string and list formats
                name_list = names.split('\n') if isinstance(names, str) else names
                for name in name_list:
                    await self.process_subdomain(name)
        except json.JSONDecodeError:
            if self.verbose:
                print(colored("[-] Error parsing crt.sh response", "red"))
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] crt.sh processing error: {str(e)}", "red"))

    async def hackertarget_query(self):
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        if self.verbose:
            print(colored(f"[*] Querying Hackertarget: {url}", "blue"))

        data = await self.fetch_url(url)
        if not data:
            if self.verbose:
                print(colored("[-] No response from Hackertarget", "red"))
            return

        # Handle both CSV and line formats
        for line in data.split('\n'):
            line = line.strip()
            if not line:
                continue

            if ',' in line:
                # CSV format: subdomain,ip
                full_domain = line.split(',')[0].strip()
            else:
                # Simple list format
                full_domain = line

            await self.process_subdomain(full_domain)

    async def certspotter_query(self):
        """Query CertSpotter with pagination support"""
        page = 1
        while True:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}" \
                  f"&include_subdomains=true&expand=dns_names&page={page}"
            if self.verbose:
                print(colored(f"[*] Querying CertSpotter (Page {page}): {url}", "blue"))

            data = await self.fetch_url(url, json_response=True)
            if not data:
                break

            try:
                certs = data
                if not certs:
                    break

                for cert in certs:
                    for name in cert.get('dns_names', []):
                        await self.process_subdomain(name)

                # Check if we should continue pagination
                if len(certs) < 100:  # Max per page is 100
                    break
                page += 1

            except Exception as e:
                if self.verbose:
                    print(colored(f"[-] CertSpotter processing error: {str(e)}", "red"))
                break

    async def threatminer_query(self):
        url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
        if self.verbose:
            print(colored(f"[*] Querying ThreatMiner: {url}", "blue"))

        data = await self.fetch_url(url)
        if not data:
            if self.verbose:
                print(colored("[-] No response from ThreatMiner", "red"))
            return

        try:
            result = json.loads(data)
            if 'results' in result:
                for item in result['results']:
                    await self.process_subdomain(item)
        except json.JSONDecodeError:
            if self.verbose:
                print(colored("[-] Error parsing ThreatMiner response", "red"))
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] ThreatMiner processing error: {str(e)}", "red"))

    async def urlscan_query(self):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
        if self.verbose:
            print(colored(f"[*] Querying urlscan.io: {url}", "blue"))

        data = await self.fetch_url(url, json_response=True)
        if not data:
            if self.verbose:
                print(colored("[-] No response from urlscan.io", "red"))
            return

        try:
            for item in data.get('results', []):
                domain = item.get('task', {}).get('domain')
                if domain:
                    await self.process_subdomain(domain)
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] urlscan.io processing error: {str(e)}", "red"))

    async def anubis_query(self):
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        if self.verbose:
            print(colored(f"[*] Querying AnubisDB: {url}", "blue"))

        data = await self.fetch_url(url, headers={'Accept': 'application/json'}, json_response=True)
        if not data:
            if self.verbose:
                print(colored("[-] No response from AnubisDB", "red"))
            return

        try:
            for subdomain in data:
                await self.process_subdomain(subdomain)
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] AnubisDB processing error: {str(e)}", "red"))

    async def virustotal_query(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=100"
        headers = {
            "x-apikey": "ad9ab96b90d5d3ad8ffbc0e29437517d3c30e5ec8c8c64b22585abcde7d68d54"}  # Replace with your API key

        if self.verbose:
            print(colored(f"[*] Querying VirusTotal: {url}", "blue"))

        data = await self.fetch_url(url, headers=headers, json_response=True)
        if not data:
            if self.verbose:
                print(colored("[-] No response from VirusTotal", "red"))
            return

        try:
            for item in data.get("data", []):
                subdomain = item.get("id", "").split('.')[0]
                await self.process_subdomain(subdomain)
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] VirusTotal processing error: {str(e)}", "red"))

    async def otx_query(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        if self.verbose:
            print(colored(f"[*] Querying AlienVault OTX: {url}", "blue"))

        data = await self.fetch_url(url, json_response=True)
        if not data:
            if self.verbose:
                print(colored("[-] No response from AlienVault OTX", "red"))
            return

        try:
            for item in data.get("passive_dns", []):
                hostname = item.get("hostname", "")
                if hostname:
                    await self.process_subdomain(hostname)
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] OTX processing error: {str(e)}", "red"))

    async def bufferover_query(self):
        url = f"https://dns.bufferover.run/dns?q={self.domain}"
        if self.verbose:
            print(colored(f"[*] Querying BufferOver: {url}", "blue"))

        data = await self.fetch_url(url, json_response=True)
        if not data:
            if self.verbose:
                print(colored("[-] No response from BufferOver", "red"))
            return

        try:
            # Process both FDNS_A and RDNS records
            for record_type in ["FDNS_A", "RDNS"]:
                records = data.get(record_type, [])
                for record in records:
                    # Handle CSV format: "ip,hostname" or "hostname,ip"
                    parts = record.split(',')
                    if len(parts) >= 2:
                        # Try both positions for hostname
                        for part in parts:
                            if part.endswith(f".{self.domain}"):
                                await self.process_subdomain(part)
                                break
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] BufferOver processing error: {str(e)}", "red"))

    async def sublist3r_query(self):
        url = f"https://api.sublist3r.com/search.php?domain={self.domain}"
        if self.verbose:
            print(colored(f"[*] Querying Sublist3r: {url}", "blue"))

        data = await self.fetch_url(url, json_response=True)
        if not data:
            if self.verbose:
                print(colored("[-] No response from Sublist3r", "red"))
            return

        try:
            for subdomain in data:
                await self.process_subdomain(subdomain)
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Sublist3r processing error: {str(e)}", "red"))

    # New open-source passive sources
    async def rapiddns_query(self):
        """Query RapidDNS.io subdomain database"""
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1#result"
        if self.verbose:
            print(colored(f"[*] Querying RapidDNS: {url}", "blue"))

        try:
            data = await self.fetch_url(url)
            if not data:
                return

            # Extract subdomains from HTML table
            pattern = re.compile(rf"([\w\-\.]+\.{re.escape(self.domain)})")
            matches = pattern.findall(data)
            for sub in set(matches):
                await self.process_subdomain(sub)

        except Exception as e:
            if self.verbose:
                print(colored(f"[-] RapidDNS error: {str(e)}", "red"))

    async def sonar_query(self):
        """Query Sonar (Project Sonar) database"""
        url = f"https://sonar.omnisint.io/subdomains/{self.domain}"
        if self.verbose:
            print(colored(f"[*] Querying Sonar: {url}", "blue"))

        try:
            data = await self.fetch_url(url, json_response=True)
            if not data:
                return

            for sub in data:
                await self.process_subdomain(sub)

        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Sonar error: {str(e)}", "red"))

    async def wayback_query(self):
        """Query Wayback Machine archives"""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey"
        if self.verbose:
            print(colored(f"[*] Querying Wayback Machine: {url}", "blue"))

        try:
            data = await self.fetch_url(url)
            if not data:
                return

            # Extract unique subdomains from URLs
            subs = set()
            for line in data.splitlines():
                url_parts = line.split('/')
                if len(url_parts) > 2:
                    host = url_parts[2]
                    if host.endswith(f".{self.domain}"):
                        subs.add(host)

            for sub in subs:
                await self.process_subdomain(sub)

        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Wayback Machine error: {str(e)}", "red"))

    async def commoncrawl_query(self):
        """Query Common Crawl index"""
        # First get the latest crawl index
        index_url = "https://index.commoncrawl.org/collinfo.json"
        if self.verbose:
            print(colored("[*] Getting Common Crawl index", "blue"))

        try:
            index_data = await self.fetch_url(index_url, json_response=True)
            if not index_data:
                return

            latest_index = index_data[0]['id']  # Get most recent crawl

            # Now search for subdomains
            search_url = f"https://index.commoncrawl.org/{latest_index}-index?url=*.{self.domain}&output=json"
            if self.verbose:
                print(colored(f"[*] Querying Common Crawl: {search_url}", "blue"))

            data = await self.fetch_url(search_url)
            if not data:
                return

            # Process line-delimited JSON
            for line in data.splitlines():
                try:
                    entry = json.loads(line)
                    url = entry.get('url')
                    if url:
                        host = url.split('/')[2]
                        if host.endswith(f".{self.domain}"):
                            await self.process_subdomain(host)
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Common Crawl error: {str(e)}", "red"))

    async def threatcrowd_query(self):
        """Query ThreatCrowd's crowdsourced DNS"""
        url = f"https://threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        if self.verbose:
            print(colored(f"[*] Querying ThreatCrowd: {url}", "blue"))

        try:
            data = await self.fetch_url(url, json_response=True)
            if not data:
                return

            # Extract subdomains from multiple fields
            sources = [
                data.get('subdomains', []),
                data.get('resolutions', [])
            ]

            for source in sources:
                for item in source:
                    if isinstance(item, str):
                        if item.endswith(f".{self.domain}"):
                            await self.process_subdomain(item)
                    elif isinstance(item, dict):
                        sub = item.get('ip_address') or item.get('domain')
                        if sub and sub.endswith(f".{self.domain}"):
                            await self.process_subdomain(sub)

        except Exception as e:
            if self.verbose:
                print(colored(f"[-] ThreatCrowd error: {str(e)}", "red"))

    async def bruteforce(self):
        if not self.wordlist or self.skip_bruteforce:
            return

        try:
            with open(self.wordlist) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(colored(f"[-] Error: Wordlist file '{self.wordlist}' not found", "red"))
            return

        # Initialize progress bar
        self.progress = tqdm(total=len(words), desc="Brute-forcing", unit="sub",
                             bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")

        tasks = []
        for word in words:
            # Use semaphore to control concurrency
            async with self.semaphore:
                task = asyncio.create_task(self.query_dns(word))
                task.add_done_callback(lambda _: self.progress.update(1))
                tasks.append(task)

        await asyncio.gather(*tasks)
        self.progress.close()

    # Port Scanning
    async def port_scan(self, ip, port):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2)
            writer.close()
            await writer.wait_closed()
            return port, "open"
        except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
            return port, "closed"
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] Port scan error on {ip}:{port}: {str(e)}", "red"))
            return port, "error"

    async def scan_ports(self, ip):
        tasks = [self.port_scan(ip, port) for port in self.ports]
        results = await asyncio.gather(*tasks)
        return {port: status for port, status in results if status == "open"}

    # HTTP Probing with Method Detection
    async def http_probe_url(self, subdomain, scheme="https"):
        url = f"{scheme}://{subdomain}"
        try:
            async with self.session.get(url, timeout=10, allow_redirects=True, ssl=False) as response:
                # Get allowed methods
                methods = []
                try:
                    async with self.session.options(url, timeout=5, ssl=False) as options_resp:
                        if 'Allow' in options_resp.headers:
                            methods = options_resp.headers['Allow'].split(', ')
                except:
                    methods = ["GET"]  # Default to GET if OPTIONS fails

                return {
                    "url": url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "server": response.headers.get('Server', ''),
                    "content_type": response.headers.get('Content-Type', ''),
                    "redirects": [str(r.url) for r in response.history],
                    "final_url": str(response.url),
                    "methods": methods  # Capture allowed HTTP methods
                }
        except Exception as e:
            if self.verbose:
                print(colored(f"[-] HTTP probe failed for {url}: {str(e)}", "red"))
            return None

    async def probe_subdomain(self, subdomain):
        results = {}
        for scheme in ["http", "https"]:
            result = await self.http_probe_url(subdomain, scheme)
            if result:
                results[scheme] = result
        return results if results else None

    # WAF Detection
    async def detect_waf(self, subdomain):
        url = f"https://{subdomain}/"
        try:
            async with self.session.get(url, headers={"User-Agent": "Mozilla/5.0"},
                                        timeout=10, ssl=False) as response:
                headers = dict(response.headers)
                server = headers.get('Server', '').lower()
                powered_by = headers.get('X-Powered-By', '').lower()

                # Common WAF indicators
                waf_indicators = [
                    "cloudflare", "akamai", "incapsula", "sucuri", "barracuda",
                    "f5", "fortinet", "imperva", "aws", "azurewaf", "cloudfront"
                ]

                for indicator in waf_indicators:
                    if indicator in server or indicator in powered_by:
                        return indicator
        except Exception:
            pass
        return None

    def save_ips_to_file(self):
        """Save all unique IP addresses to a file"""
        if not self.ip_file:
            return

        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)

        if not all_ips:
            print(colored("[-] No IP addresses to save", "red"))
            return

        with open(self.ip_file, 'w') as f:
            for ip in sorted(all_ips):
                f.write(f"{ip}\n")

        print(colored(f"[+] Saved {len(all_ips)} unique IP addresses to {self.ip_file}", "green"))

    def run_nmap_scan(self):
        """Run Nmap scan on collected IP addresses"""
        if not self.nmap_scan:
            return

        # Collect all unique IPs
        all_ips = set()
        for ips in self.resolved.values():
            all_ips.update(ips)

        if not all_ips:
            print(colored("[-] No IP addresses to scan with Nmap", "red"))
            return

        # Prepare IP list for Nmap
        ip_list = sorted(all_ips)

        # Generate output filename
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        output_file = f"nmap_scan_{self.domain}_{timestamp}.txt"

        # Build Nmap command
        nmap_cmd = [
            "nmap",
            "-sV",  # Service version detection
            "-O",  # OS detection
            "-T4",  # Aggressive timing template
            "-Pn",  # Skip host discovery
            "-v",  # Verbose output
            "-oN", output_file  # Output to file
        ]

        # Add ports if specified
        if self.ports:
            port_arg = ",".join(str(p) for p in self.ports)
            nmap_cmd.extend(["-p", port_arg])

        # Add IP addresses
        nmap_cmd.extend(ip_list)

        print(colored(f"[*] Starting Nmap scan on {len(ip_list)} IPs...", "blue"))
        print(colored(f"[*] Command: {' '.join(nmap_cmd)}", "cyan"))

        try:
            # Run Nmap
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                check=True
            )

            # Print Nmap output
            print(colored(f"\n[+] Nmap scan completed successfully!", "green"))
            print(colored(f"[+] Results saved to: {output_file}", "green"))

            if self.verbose:
                print("\nNmap Output:")
                print(result.stdout)

        except subprocess.CalledProcessError as e:
            print(colored(f"[-] Nmap scan failed with error: {e.stderr}", "red"))
        except FileNotFoundError:
            print(colored("[-] Nmap not found. Please install Nmap to use this feature.", "red"))

    def wrap_text(self, text, width):
        """Wrap text into multiple lines with a maximum width"""
        if not text:
            return ""
        return '\n'.join(textwrap.wrap(str(text), width=width))

    def generate_results_table(self):
        """Generate a table view of results with improved wrapping"""
        if not self.found:
            return [], []

        # Column width configuration
        COLUMN_WIDTHS = {
            "Subdomain": 30,
            "IPs": 20,
            "Methods": 25,
            "Server": 20,
            "CNAME": 30
        }

        table_data = []
        headers = ["Subdomain", "IPs", "Status", "Methods", "Server", "WAF", "CNAME"]

        for sub in sorted(self.found):
            # Get IP addresses
            ips = ', '.join(self.resolved[sub]) if sub in self.resolved else ""

            # Initialize HTTP-related variables
            http_status = ""
            http_methods = ""
            server_info = ""

            # Process HTTP results if available
            if self.http_probe and sub in self.http_results:
                statuses = []
                methods_set = set()
                servers_found = set()

                for scheme, res in self.http_results[sub].items():
                    if res:
                        # Collect status codes
                        statuses.append(f"{res['status']}")

                        # Collect HTTP methods
                        if 'methods' in res and res['methods']:
                            methods_set.update(res['methods'])

                        # Collect server information
                        if res.get('server'):
                            servers_found.add(res['server'])

                http_status = '/'.join(statuses) if statuses else ""
                http_methods = ', '.join(sorted(methods_set)) if methods_set else ""
                server_info = ', '.join(servers_found) if servers_found else ""

            # Get WAF info
            waf_info = self.waf_detected.get(sub, "")

            # Get CNAME info
            cname_info = ', '.join(self.cnames.get(sub, []))

            # Apply wrapping to potentially long fields
            wrapped_row = [
                self.wrap_text(sub, COLUMN_WIDTHS["Subdomain"]),
                self.wrap_text(ips, COLUMN_WIDTHS["IPs"]),
                http_status,
                self.wrap_text(http_methods, COLUMN_WIDTHS["Methods"]),
                self.wrap_text(server_info, COLUMN_WIDTHS["Server"]),
                waf_info,
                self.wrap_text(cname_info, COLUMN_WIDTHS["CNAME"])
            ]

            table_data.append(wrapped_row)

        return headers, table_data

    async def run(self):
        # Print banner at startup
        print(colored(BANNER, "cyan"))

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        await self.init_resolver()

        async with aiohttp.ClientSession(headers=headers) as self.session:
            if self.verbose:
                print(colored(f"[*] Starting scan for {self.domain}", "blue"))
                print(colored(f"[*] Wildcard detection in progress...", "blue"))

            await self.detect_wildcard()

            if self.verbose and not self.skip_passive:
                source_names = [src.__name__.replace('_', ' ') for src in self.passive_sources]
                print(colored(f"[*] Using passive sources: {', '.join(source_names)}", "blue"))
                if self.wordlist and not self.skip_bruteforce:
                    print(colored(f"[*] Brute-forcing with {self.wordlist} ({self.threads} threads)", "blue"))
                if self.resolve_ips or self.ip_file or self.nmap_scan:
                    print(colored("[*] IP resolution enabled", "blue"))
                if self.http_probe:
                    print(colored("[*] HTTP probing enabled", "blue"))
                if self.waf_detect:
                    print(colored("[*] WAF detection enabled", "blue"))
                if self.ip_file:
                    print(colored(f"[*] IP addresses will be saved to {self.ip_file}", "blue"))
                if self.nmap_scan:
                    print(colored("[*] Nmap scan will be performed on discovered IPs", "blue"))

            # Run passive sources
            if not self.skip_passive:
                passive_tasks = [source() for source in self.passive_sources]
                await asyncio.gather(*passive_tasks)

            # Run brute-force
            if self.wordlist and not self.skip_bruteforce:
                await self.bruteforce()

            # Run active checks
            if self.http_probe or self.waf_detect:
                if self.verbose:
                    print(colored("[*] Starting active checks...", "blue"))

                active_tasks = []
                for sub in self.found:
                    if self.http_probe:
                        active_tasks.append(self.probe_subdomain(sub))
                    if self.waf_detect:
                        active_tasks.append(self.detect_waf(sub))

                active_results = await asyncio.gather(*active_tasks)

                # Process results with proper index handling
                active_index = 0
                for sub in self.found:
                    if self.http_probe:
                        http_res = active_results[active_index]
                        active_index += 1
                        if http_res is not None:
                            self.http_results[sub] = http_res

                    if self.waf_detect:
                        waf_res = active_results[active_index]
                        active_index += 1
                        if waf_res is not None:
                            self.waf_detected[sub] = waf_res
                            if self.verbose:
                                print(colored(f"[+] WAF detected for {sub}: {waf_res}", "magenta"))

            # Save IPs to file if requested
            if self.ip_file:
                self.save_ips_to_file()

            # Output results
            if self.output:
                if self.json_output:
                    output_data = {
                        "domain": self.domain,
                        "subdomains": [],
                        "execution_time": round(time.time() - self.start_time, 2)
                    }

                    for sub in sorted(self.found):
                        sub_data = {"subdomain": sub}
                        if self.resolve_ips or self.ip_file or self.nmap_scan:
                            sub_data["ips"] = self.resolved[sub]
                        if sub in self.cnames:
                            sub_data["cnames"] = self.cnames[sub]
                        if self.http_probe and sub in self.http_results:
                            sub_data["http"] = self.http_results[sub]
                        if self.waf_detect and sub in self.waf_detected:
                            sub_data["waf"] = self.waf_detected[sub]
                        output_data["subdomains"].append(sub_data)

                    with open(self.output, 'w') as f:
                        json.dump(output_data, f, indent=2)
                else:
                    with open(self.output, 'w') as f:
                        for sub in sorted(self.found):
                            line = f"{sub}"
                            if self.resolve_ips or self.ip_file or self.nmap_scan:
                                line += f" [IP: {', '.join(self.resolved[sub])}]"
                            if sub in self.cnames:
                                line += f" [CNAME: {', '.join(self.cnames[sub])}]"
                            if self.http_probe and sub in self.http_results:
                                statuses = []
                                for scheme, res in self.http_results[sub].items():
                                    statuses.append(f"{scheme.upper()}:{res['status']}")
                                line += f" [HTTP: {' '.join(statuses)}]"
                            if self.waf_detect and sub in self.waf_detected:
                                line += f" [WAF: {self.waf_detected[sub]}]"
                            f.write(f"{line}\n")

                print(colored(f"\n[+] Results saved to {self.output}", "green"))

            # Generate and display results table
            headers, table_data = self.generate_results_table()
            print(colored(
                f"\n[+] Found {len(self.found)} unique subdomains in {round(time.time() - self.start_time, 2)} seconds",
                "green"))

            if table_data:
                print("\n" + tabulate(table_data, headers=headers, tablefmt="grid"))
            else:
                print(colored("[-] No subdomains found", "red"))

            # Run Nmap scan if requested
            if self.nmap_scan:
                self.run_nmap_scan()


def main():
    parser = argparse.ArgumentParser(description='Subdocker - Subdomain Discovery Tool')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Wordlist for brute-forcing')
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help='Concurrency level (default: 100)')
    parser.add_argument('-o', '--output', help='Output file to save results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--ip', action='store_true', help='Resolve subdomains to IP addresses')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--dns-servers', nargs='+', default=["1.1.1.1", "8.8.8.8"],
                        help='Custom DNS servers (space separated) default(1.1.1.1 , 8.8.8.8')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for requests in seconds')
    parser.add_argument('--rate-limit', type=int, default=5, help='Max requests per second for passive sources')
    parser.add_argument('--ports', nargs='+', type=int, default=[80, 443],
                        help='Ports to scan for open services')
    parser.add_argument('--http', action='store_true', help='Perform HTTP probing on discovered subdomains')
    parser.add_argument('--waf', action='store_true', help='Detect Web Application Firewalls')
    parser.add_argument('--skip-passive', action='store_true', help='Skip passive enumeration')
    parser.add_argument('--skip-bruteforce', action='store_true', help='Skip brute-force enumeration')
    parser.add_argument('-W', '--ip-file', help='Save IP addresses to a file')
    parser.add_argument('--nmap', action='store_true', help='Run Nmap scan on discovered IP addresses')

    args = parser.parse_args()

    if not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', args.domain, re.IGNORECASE):
        print(colored("Error: Invalid domain format", "red"))
        return

    tool = Subdocker(
        domain=args.domain,
        wordlist=args.wordlist,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose,
        resolve_ips=args.ip,
        json_output=args.json,
        dns_servers=args.dns_servers,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        ports=args.ports,
        http_probe=args.http,
        waf_detect=args.waf,
        skip_passive=args.skip_passive,
        skip_bruteforce=args.skip_bruteforce,
        ip_file=args.ip_file,
        nmap_scan=args.nmap
    )

    # Windows compatibility
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(tool.run())
    except KeyboardInterrupt:
        print(colored("\n[!] Scan interrupted by user", "red"))
        sys.exit(1)

if __name__ == '__main__':
    main()