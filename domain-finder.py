#!/usr/bin/env python3
"""
Company Domain Discovery Tool
Discovers all domains potentially owned by a company using multiple techniques
Author: elementalsouls
Date: 2025-06-10
"""

import os
import argparse
import requests
import json
import socket
import time
import threading
import re
import ssl
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional, Tuple
from datetime import datetime
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Rich library for better output formatting
try:
    from rich import print as rprint
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    def rprint(text):
        print(text)

# Initialize console
console = Console() if RICH_AVAILABLE else None

# ========== Configuration ==========

# API Keys from environment variables
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', '')
WHOISXML_API_KEY = os.getenv('WHOISXML_API_KEY', '')

# Common TLDs to check for company variations
COMMON_TLDS = [
    '.com', '.net', '.org', '.io', '.co', '.us', '.biz', '.info',
    '.tech', '.online', '.site', '.app', '.dev', '.ai', '.ml'
]

# Country-specific TLDs for international companies
COUNTRY_TLDS = [
    '.uk', '.de', '.fr', '.jp', '.au', '.ca', '.in', '.cn', '.br', '.ru'
]

# ========== Data Structures ==========

@dataclass
class DomainInfo:
    domain: str
    discovery_method: str
    confidence_score: int  # 1-100
    ip_address: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    organization: Optional[str] = None
    asn: Optional[str] = None
    is_active: bool = True
    ssl_info: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)

class CompanyDomainFinder:
    def __init__(self, company_name: str, primary_domain: str = None):
        self.company_name = company_name
        self.primary_domain = primary_domain
        self.discovered_domains = {}
        self.discovery_stats = {}
        
    def log_discovery(self, domain: str, method: str, confidence: int = 50, **kwargs):
        """Log a discovered domain with metadata"""
        if domain not in self.discovered_domains:
            self.discovered_domains[domain] = DomainInfo(
                domain=domain,
                discovery_method=method,
                confidence_score=confidence,
                **kwargs
            )
            
            # Update stats
            self.discovery_stats[method] = self.discovery_stats.get(method, 0) + 1
        else:
            # Update existing entry if this method has higher confidence
            existing = self.discovered_domains[domain]
            if confidence > existing.confidence_score:
                existing.confidence_score = confidence
                existing.discovery_method = f"{existing.discovery_method}, {method}"

    # ========== Certificate Transparency Methods ==========
    
    def discover_via_certificate_transparency(self):
        """Discover domains via Certificate Transparency logs"""
        rprint(f"[blue]🔍 Certificate Transparency Discovery[/blue]")
        
        # Search patterns for crt.sh
        search_patterns = [
            self.company_name.replace(' ', '%20'),
            self.company_name.replace(' ', ''),
            self.company_name.replace(' ', '-'),
        ]
        
        if self.primary_domain:
            search_patterns.append(self.primary_domain.split('.')[0])
        
        for pattern in search_patterns:
            self._search_crtsh_by_organization(pattern)
            self._search_crtsh_by_common_name(pattern)
            time.sleep(1)  # Rate limiting
    
    def _search_crtsh_by_organization(self, org_name):
        """Search crt.sh by organization name"""
        try:
            url = f"https://crt.sh/?O={org_name}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.ok and response.text.strip():
                certificates = response.json()
                rprint(f"  📜 Found {len(certificates)} certificates for org: {org_name}")
                
                for cert in certificates:
                    self._extract_domains_from_cert(cert, "cert_transparency_org", 85)
                    
        except Exception as e:
            rprint(f"  ❌ crt.sh org search failed for {org_name}: {e}")
    
    def _search_crtsh_by_common_name(self, name_pattern):
        """Search crt.sh by common name pattern"""
        try:
            url = f"https://crt.sh/?CN=%25{name_pattern}%25&output=json"
            response = requests.get(url, timeout=30)
            
            if response.ok and response.text.strip():
                certificates = response.json()
                rprint(f"  📜 Found {len(certificates)} certificates for CN: {name_pattern}")
                
                for cert in certificates:
                    self._extract_domains_from_cert(cert, "cert_transparency_cn", 70)
                    
        except Exception as e:
            rprint(f"  ❌ crt.sh CN search failed for {name_pattern}: {e}")
    
    def _extract_domains_from_cert(self, cert, method, confidence):
        """Extract domains from certificate data"""
        domains_to_check = []
        
        # Common name
        if cert.get('common_name'):
            domains_to_check.append(cert['common_name'])
        
        # Subject Alternative Names
        if cert.get('name_value'):
            domains_to_check.extend(cert['name_value'].split('\n'))
        
        for domain in domains_to_check:
            domain = domain.strip().lower()
            
            # Clean domain (remove wildcards, etc.)
            if domain.startswith('*.'):
                domain = domain[2:]
            
            if self._is_valid_domain(domain) and self._is_company_related(domain):
                self.log_discovery(domain, method, confidence)

    # ========== DNS Infrastructure Analysis ==========
    
    def discover_via_dns_infrastructure(self):
        """Discover domains sharing DNS infrastructure"""
        if not self.primary_domain:
            rprint("[yellow]⚠️  No primary domain provided for DNS infrastructure analysis[/yellow]")
            return
            
        rprint(f"[blue]🔍 DNS Infrastructure Analysis[/blue]")
        
        try:
            # Get nameservers for primary domain
            ns_records = dns.resolver.resolve(self.primary_domain, 'NS')
            nameservers = [str(ns).rstrip('.') for ns in ns_records]
            
            rprint(f"  📡 Primary domain nameservers: {', '.join(nameservers)}")
            
            # This would require reverse NS lookup capability
            # For now, we'll note the nameservers for manual investigation
            for ns in nameservers:
                rprint(f"    💡 Manual check recommended: Find other domains using {ns}")
                
        except Exception as e:
            rprint(f"  ❌ DNS infrastructure analysis failed: {e}")

    # ========== IP Range Analysis ==========
    
    def discover_via_ip_analysis(self):
        """Discover domains in same IP ranges"""
        if not self.primary_domain:
            rprint("[yellow]⚠️  No primary domain provided for IP analysis[/yellow]")
            return
            
        rprint(f"[blue]🔍 IP Range Analysis[/blue]")
        
        try:
            # Get IP of primary domain
            primary_ip = socket.gethostbyname(self.primary_domain)
            rprint(f"  🎯 Primary domain IP: {primary_ip}")
            
            # Analyze IP range (simplified approach)
            self._analyze_ip_range(primary_ip)
            
            # Get ASN information
            self._get_asn_info(primary_ip)
            
        except Exception as e:
            rprint(f"  ❌ IP analysis failed: {e}")
    
    def _analyze_ip_range(self, ip_address):
        """Analyze IP range for related domains"""
        ip_parts = ip_address.split('.')
        base_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        
        rprint(f"  🔍 Scanning IP range: {base_range}.x")
        
        # Sample a few IPs in the range (don't scan entire range)
        sample_ips = [f"{base_range}.{i}" for i in [1, 2, 10, 50, 100, 200, 254]]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._reverse_dns_lookup, ip): ip for ip in sample_ips}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    hostname = future.result()
                    if hostname and self._is_company_related(hostname):
                        self.log_discovery(hostname, "ip_range_analysis", 60, ip_address=ip)
                except:
                    continue
    
    def _reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except:
            return None
    
    def _get_asn_info(self, ip_address):
        """Get ASN information for IP"""
        # This would typically use a service like Hurricane Electric BGP toolkit
        # For demonstration, we'll show the concept
        rprint(f"  💡 ASN lookup recommended for {ip_address}")

    # ========== Brand Name Variations ==========
    
    def discover_via_brand_variations(self):
        """Discover domains using company name variations"""
        rprint(f"[blue]🔍 Brand Name Variations Discovery[/blue]")
        
        variations = self._generate_company_variations()
        rprint(f"  🔤 Generated {len(variations)} company name variations")
        
        # Check variations against common TLDs
        all_tlds = COMMON_TLDS + COUNTRY_TLDS
        
        domains_to_check = []
        for variation in variations:
            for tld in all_tlds:
                domains_to_check.append(f"{variation}{tld}")
        
        rprint(f"  🌐 Checking {len(domains_to_check)} domain combinations")
        
        # Check domains in batches
        batch_size = 50
        for i in range(0, len(domains_to_check), batch_size):
            batch = domains_to_check[i:i + batch_size]
            self._check_domain_batch(batch, "brand_variation")
            time.sleep(2)  # Rate limiting
    
    def _generate_company_variations(self):
        """Generate variations of company name"""
        variations = set()
        
        # Original name variations
        clean_name = re.sub(r'[^a-zA-Z0-9]', '', self.company_name.lower())
        variations.add(clean_name)
        
        # Space replacements
        variations.add(self.company_name.lower().replace(' ', ''))
        variations.add(self.company_name.lower().replace(' ', '-'))
        variations.add(self.company_name.lower().replace(' ', '_'))
        
        # Abbreviations
        words = self.company_name.split()
        if len(words) > 1:
            # First letters
            abbreviation = ''.join(word[0].lower() for word in words)
            variations.add(abbreviation)
            
            # First word only
            variations.add(words[0].lower())
            
            # Last word only
            variations.add(words[-1].lower())
        
        # Remove common suffixes
        suffixes = ['inc', 'corp', 'ltd', 'llc', 'company', 'co', 'corporation']
        for suffix in suffixes:
            for var in list(variations):
                if var.endswith(suffix):
                    variations.add(var[:-len(suffix)].rstrip())
        
        # Add numerical variations
        for var in list(variations):
            for num in ['1', '2', '123', '2024', '2025']:
                variations.add(f"{var}{num}")
                variations.add(f"{num}{var}")
        
        return sorted(list(variations))[:100]  # Limit to prevent abuse
    
    def _check_domain_batch(self, domains, method):
        """Check a batch of domains for existence"""
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_domain_exists, domain): domain for domain in domains}
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    if future.result():
                        self.log_discovery(domain, method, 75)
                except:
                    continue
    
    def _check_domain_exists(self, domain):
        """Check if domain exists and is resolvable"""
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False

    # ========== Third-party API Integration ==========
    
    def discover_via_virustotal(self):
        """Discover domains via VirusTotal API"""
        if not VIRUSTOTAL_API_KEY:
            rprint("[yellow]⚠️  VirusTotal API key not configured[/yellow]")
            return
            
        rprint(f"[blue]🔍 VirusTotal Domain Discovery[/blue]")
        
        if self.primary_domain:
            self._virustotal_domain_analysis(self.primary_domain)
    
    def _virustotal_domain_analysis(self, domain):
        """Analyze domain using VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': VIRUSTOTAL_API_KEY, 'domain': domain}
            
            response = requests.get(url, params=params, timeout=15)
            if response.ok:
                data = response.json()
                
                # Extract related domains
                if data.get('response_code') == 1:
                    # Subdomains
                    for subdomain in data.get('subdomains', []):
                        if self._is_company_related(subdomain):
                            self.log_discovery(subdomain, "virustotal_subdomains", 80)
                    
                    # Detected URLs
                    for url_data in data.get('detected_urls', [])[:50]:
                        url_str = url_data.get('url', '')
                        if url_str:
                            try:
                                parsed = urlparse(url_str)
                                if parsed.hostname and self._is_company_related(parsed.hostname):
                                    self.log_discovery(parsed.hostname, "virustotal_urls", 70)
                            except:
                                continue
                                
        except Exception as e:
            rprint(f"  ❌ VirusTotal analysis failed: {e}")
    
    def discover_via_shodan(self):
        """Discover domains via Shodan API"""
        if not SHODAN_API_KEY:
            rprint("[yellow]⚠️  Shodan API key not configured[/yellow]")
            return
            
        rprint(f"[blue]🔍 Shodan Domain Discovery[/blue]")
        
        # Search for company name in Shodan
        search_queries = [
            f'org:"{self.company_name}"',
            f'ssl:"{self.company_name}"',
        ]
        
        if self.primary_domain:
            search_queries.append(f'hostname:{self.primary_domain}')
        
        for query in search_queries:
            self._shodan_search(query)
            time.sleep(2)  # Rate limiting
    
    def _shodan_search(self, query):
        """Search Shodan for domains"""
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}"
            response = requests.get(url, timeout=15)
            
            if response.ok:
                data = response.json()
                for result in data.get('matches', []):
                    # Extract hostnames
                    hostnames = result.get('hostnames', [])
                    for hostname in hostnames:
                        if self._is_company_related(hostname):
                            self.log_discovery(hostname, "shodan_search", 85)
                            
        except Exception as e:
            rprint(f"  ❌ Shodan search failed for query '{query}': {e}")

    # ========== Validation and Filtering ==========
    
    def _is_valid_domain(self, domain):
        """Check if string is a valid domain"""
        if not domain or len(domain) > 253:
            return False
        
        # Basic domain regex
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(domain_pattern, domain) is not None
    
    def _is_company_related(self, domain):
        """Check if domain is likely related to the company"""
        domain_lower = domain.lower()
        company_lower = self.company_name.lower()
        
        # Remove common words from company name for better matching
        company_clean = re.sub(r'\b(inc|corp|ltd|llc|company|co|corporation)\b', '', company_lower)
        company_words = [word for word in company_clean.split() if len(word) > 2]
        
        # Check if any significant company word appears in domain
        for word in company_words:
            if word in domain_lower:
                return True
        
        # Check if primary domain components appear
        if self.primary_domain:
            primary_parts = self.primary_domain.split('.')[0].lower()
            if primary_parts in domain_lower:
                return True
        
        return False

    # ========== Enhanced Domain Information Gathering ==========
    
    def enrich_domain_info(self):
        """Enrich discovered domains with additional information"""
        rprint(f"[blue]🔍 Enriching Domain Information[/blue]")
        
        domains_to_enrich = list(self.discovered_domains.keys())[:50]  # Limit to prevent abuse
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._enrich_single_domain, domain): domain 
                      for domain in domains_to_enrich}
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    future.result()
                except Exception as e:
                    rprint(f"  ❌ Failed to enrich {domain}: {e}")
    
    def _enrich_single_domain(self, domain):
        """Enrich information for a single domain"""
        domain_info = self.discovered_domains[domain]
        
        try:
            # Get IP address
            if not domain_info.ip_address:
                domain_info.ip_address = socket.gethostbyname(domain)
            
            # Get nameservers
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                domain_info.nameservers = [str(ns).rstrip('.') for ns in ns_records]
            except:
                pass
            
            # Get SSL certificate info
            self._get_ssl_info(domain, domain_info)
            
        except Exception as e:
            domain_info.is_active = False
    
    def _get_ssl_info(self, domain, domain_info):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    domain_info.ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                    }
                    
                    # Extract organization from certificate
                    subject = domain_info.ssl_info.get('subject', {})
                    domain_info.organization = subject.get('organizationName', '')
                    
        except:
            pass

    # ========== Main Discovery Process ==========
    
    def discover_all_domains(self):
        """Run all discovery methods"""
        start_time = time.time()
        
        if console:
            console.print(Panel.fit(
                f"[bold cyan]🏢 COMPANY DOMAIN DISCOVERY[/bold cyan]\n"
                f"[yellow]Company: {self.company_name}[/yellow]\n"
                f"[yellow]Primary Domain: {self.primary_domain or 'Not specified'}[/yellow]",
                style="blue"
            ))
        
        # Run discovery methods
        self.discover_via_certificate_transparency()
        self.discover_via_brand_variations()
        self.discover_via_dns_infrastructure()
        self.discover_via_ip_analysis()
        self.discover_via_virustotal()
        self.discover_via_shodan()
        
        # Enrich domain information
        if self.discovered_domains:
            self.enrich_domain_info()
        
        elapsed_time = time.time() - start_time
        rprint(f"\n[green]✅ Discovery completed in {elapsed_time:.2f} seconds[/green]")
        
        return self.discovered_domains

    # ========== Results Display and Export ==========
    
    def display_results(self):
        """Display discovery results"""
        if not self.discovered_domains:
            rprint("[yellow]⚠️  No company domains discovered[/yellow]")
            return
        
        # Summary statistics
        total_domains = len(self.discovered_domains)
        active_domains = sum(1 for d in self.discovered_domains.values() if d.is_active)
        
        if console:
            # Create summary table
            summary_table = Table(title="Discovery Summary")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Count", style="green")
            
            summary_table.add_row("Total Domains Found", str(total_domains))
            summary_table.add_row("Active Domains", str(active_domains))
            summary_table.add_row("Discovery Methods Used", str(len(self.discovery_stats)))
            
            console.print(summary_table)
            print()
            
            # Method statistics
            method_table = Table(title="Discovery Methods")
            method_table.add_column("Method", style="cyan")
            method_table.add_column("Domains Found", style="green")
            
            for method, count in sorted(self.discovery_stats.items()):
                method_table.add_row(method.replace('_', ' ').title(), str(count))
            
            console.print(method_table)
            print()
        
        # Domain details
        self._display_domain_details()
    
    def _display_domain_details(self):
        """Display detailed domain information"""
        if console:
            # Sort domains by confidence score
            sorted_domains = sorted(
                self.discovered_domains.items(),
                key=lambda x: x[1].confidence_score,
                reverse=True
            )
            
            details_table = Table(title="Discovered Domains")
            details_table.add_column("Domain", style="cyan")
            details_table.add_column("Method", style="yellow")
            details_table.add_column("Confidence", style="green")
            details_table.add_column("IP Address", style="blue")
            details_table.add_column("Status", style="magenta")
            
            for domain, info in sorted_domains:
                status = "🟢 Active" if info.is_active else "🔴 Inactive"
                details_table.add_row(
                    domain,
                    info.discovery_method[:20] + "..." if len(info.discovery_method) > 20 else info.discovery_method,
                    f"{info.confidence_score}%",
                    info.ip_address or "Unknown",
                    status
                )
            
            console.print(details_table)
        else:
            # Fallback text display
            rprint(f"\n{'='*80}")
            rprint(f"DISCOVERED DOMAINS ({len(self.discovered_domains)} total)")
            rprint(f"{'='*80}")
            
            for domain, info in self.discovered_domains.items():
                status = "Active" if info.is_active else "Inactive"
                rprint(f"{domain:40} | {info.discovery_method:20} | {info.confidence_score:3d}% | {status}")
    
    def export_results(self, filename):
        """Export results to JSON file"""
        export_data = {
            'company_name': self.company_name,
            'primary_domain': self.primary_domain,
            'discovery_timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_domains': len(self.discovered_domains),
                'active_domains': sum(1 for d in self.discovered_domains.values() if d.is_active),
                'discovery_methods': self.discovery_stats
            },
            'domains': {}
        }
        
        for domain, info in self.discovered_domains.items():
            export_data['domains'][domain] = {
                'discovery_method': info.discovery_method,
                'confidence_score': info.confidence_score,
                'ip_address': info.ip_address,
                'nameservers': info.nameservers,
                'organization': info.organization,
                'is_active': info.is_active,
                'ssl_info': info.ssl_info,
                'metadata': info.metadata
            }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        rprint(f"[green]✅ Results exported to: {filename}[/green]")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Company Domain Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python company_domain_finder.py "Acme Corporation" --primary-domain acme.com
  python company_domain_finder.py "Microsoft" --output microsoft_domains.json
  python company_domain_finder.py "Google Inc" --primary-domain google.com --verbose

Environment Variables:
  SHODAN_API_KEY        - Shodan API key for enhanced discovery
  VIRUSTOTAL_API_KEY    - VirusTotal API key for domain analysis
  SECURITYTRAILS_API_KEY - SecurityTrails API key for DNS history
  WHOISXML_API_KEY      - WhoisXML API key for WHOIS data
        """
    )
    
    parser.add_argument('company_name', help='Company name to search for')
    parser.add_argument('--primary-domain', help='Known primary domain of the company')
    parser.add_argument('--output', '-o', help='Export results to JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=300, help='Discovery timeout in seconds')
    
    args = parser.parse_args()
    
    # Display banner
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          COMPANY DOMAIN FINDER                              ║
║                         Author: elementalsouls                              ║
║                         Date: 2025-06-10 15:17:24                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    rprint(banner)
    
    try:
        # Initialize finder
        finder = CompanyDomainFinder(args.company_name, args.primary_domain)
        
        # Check API keys
        if args.verbose:
            rprint(f"[blue]🔑 API Key Status:[/blue]")
            rprint(f"  Shodan: {'✅' if SHODAN_API_KEY else '❌'}")
            rprint(f"  VirusTotal: {'✅' if VIRUSTOTAL_API_KEY else '❌'}")
            rprint(f"  SecurityTrails: {'✅' if SECURITYTRAILS_API_KEY else '❌'}")
            rprint(f"  WhoisXML: {'✅' if WHOISXML_API_KEY else '❌'}")
            print()
        
        # Run discovery
        discovered_domains = finder.discover_all_domains()
        
        # Display results
        finder.display_results()
        
        # Export if requested
        if args.output:
            finder.export_results(args.output)
        
        # Final summary
        rprint(f"\n[bold green]🎯 Discovery Complete![/bold green]")
        rprint(f"[green]Found {len(discovered_domains)} potential company domains[/green]")
        
        if not SHODAN_API_KEY and not VIRUSTOTAL_API_KEY:
            rprint(f"\n[yellow]💡 Tip: Set API keys for enhanced discovery capabilities[/yellow]")
    
    except KeyboardInterrupt:
        rprint(f"\n[yellow]⚠️  Discovery interrupted by user[/yellow]")
    except Exception as e:
        rprint(f"\n[red]❌ Discovery failed: {e}[/red]")
        if args.verbose:
            import traceback
            rprint(traceback.format_exc())

if __name__ == "__main__":
    main()
