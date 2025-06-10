#!/usr/bin/env python3
"""
Complete Enhanced Domain Discovery Tool - Fixed Version
Author: elementalsouls
Date: 2025-06-10 17:43:33
"""

import os
import argparse
import requests
import json
import csv
import socket
import time
import ipaddress
import re
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional
import warnings
warnings.filterwarnings("ignore")

# Enhanced imports for real data retrieval
try:
    import whois  # pip install python-whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver  # pip install dnspython
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from rich import print as rprint
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    def rprint(text): print(text)

console = Console() if RICH_AVAILABLE else None

@dataclass
class DomainInfo:
    domain: str
    discovery_method: str
    confidence_score: int
    ip_address: Optional[str] = None
    is_active: bool = True
    organization: Optional[str] = None
    registrar: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    related_keywords: List[str] = field(default_factory=list)
    ssl_info: Dict = field(default_factory=dict)
    whois_data: Dict = field(default_factory=dict)

class CompleteFixedDomainFinder:
    def __init__(self, company_name: str, primary_domain: str = None):
        self.company_name = company_name
        self.primary_domain = primary_domain
        self.discovered_domains = {}
        self.company_keywords = self._extract_company_keywords()
        self.excluded_patterns = self._get_exclusion_patterns()
        self.whoisxml_api_key = os.getenv('WHOISXML_API_KEY', '')
        self.securitytrails_api_key = os.getenv('SECURITYTRAILS_API_KEY', '')
        self.shodan_api_key = os.getenv('SHODAN_API_KEY', '')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        
    def _extract_company_keywords(self):
        """Extract meaningful keywords from company name"""
        # Clean company name and extract keywords
        company_clean = re.sub(r'\b(inc|corp|ltd|llc|company|co|corporation|group|hospital|healthcare|medical|health)\b', '', self.company_name.lower())
        
        keywords = []
        words = company_clean.split()
        
        for word in words:
            word = word.strip()
            if len(word) >= 3:  # Only meaningful words
                keywords.append(word)
        
        # Add variations
        if len(keywords) >= 2:
            # Combine words
            keywords.append(''.join(keywords))
            keywords.append(''.join(keywords[:2]))  # First two words
        
        # Add specific patterns for healthcare companies
        if any(term in self.company_name.lower() for term in ['hospital', 'medical', 'health', 'clinic']):
            for keyword in list(keywords):
                keywords.extend([
                    keyword + 'hospital',
                    keyword + 'healthcare',
                    keyword + 'medical',
                    keyword + 'health'
                ])
        
        rprint(f"[blue]🎯 Company keywords extracted: {keywords}[/blue]")
        return keywords
    
    def _get_exclusion_patterns(self):
        """Get patterns to exclude (cloud providers, CDNs, etc.)"""
        return [
            # Cloud providers
            'amazonaws.com', 'amazonaws.cn', 'cloudflare.com', 'azure.com', 'googleapi',
            'google.com', 'googleapis.com', 'gstatic.com', 'doubleclick.net',
            
            # CDNs and services
            'akamaihd.net', 'cloudfront.net', 'fastly.com', 'jsdelivr.net',
            'bootstrapcdn.com', 'cdnjs.cloudflare.com',
            
            # Common third-party services
            'facebook.com', 'twitter.com', 'linkedin.com', 'youtube.com',
            'instagram.com', 'whatsapp.com', 'schema.org', 'w3.org',
            'wikipedia.org', 'goo.gl', 'g.page',
            
            # Generic domains
            'localhost', 'example.com', 'test.com', 'internal', '.local',
            
            # Just numbers/letters (invalid domains)
            r'^[a-z]\d*$', r'^\d+$', r'^[a-z]{1,2}$'
        ]
    
    def _is_excluded_domain(self, domain):
        """Check if domain should be excluded"""
        domain_lower = domain.lower()
        
        for pattern in self.excluded_patterns:
            if pattern.startswith('^') and pattern.endswith('$'):
                # Regex pattern
                if re.match(pattern, domain_lower):
                    return True
            else:
                # Substring pattern
                if pattern in domain_lower:
                    return True
        
        return False
    
    def _is_company_related(self, domain):
        """Smart check if domain is actually related to the company"""
        domain_lower = domain.lower()
        
        # First, check exclusions
        if self._is_excluded_domain(domain):
            return False
        
        # Check if any company keyword appears in domain
        for keyword in self.company_keywords:
            if keyword in domain_lower:
                return True
        
        # Check if primary domain root appears
        if self.primary_domain:
            primary_root = self.primary_domain.split('.')[0].lower()
            if primary_root in domain_lower and len(primary_root) > 3:
                return True
        
        return False
    
    # ========== Enhanced WHOIS Data Retrieval ==========
    
    def _get_enhanced_whois_info(self, domain):
        """Get real WHOIS information using multiple methods"""
        whois_data = {
            'registrar': 'Unknown',
            'organization': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'registrant_email': 'Unknown',
            'admin_email': 'Unknown'
        }
        
        try:
            # Method 1: Try python-whois library
            if WHOIS_AVAILABLE:
                rprint(f"    🔍 Performing WHOIS lookup for {domain}")
                w = whois.whois(domain)
                
                if w:
                    # Extract registrar
                    if hasattr(w, 'registrar') and w.registrar:
                        if isinstance(w.registrar, list):
                            whois_data['registrar'] = w.registrar[0] if w.registrar[0] else 'Unknown'
                        else:
                            whois_data['registrar'] = str(w.registrar)
                    
                    # Extract organization
                    if hasattr(w, 'org') and w.org:
                        if isinstance(w.org, list):
                            whois_data['organization'] = w.org[0] if w.org[0] else 'Unknown'
                        else:
                            whois_data['organization'] = str(w.org)
                    
                    # Try alternate organization fields
                    if whois_data['organization'] == 'Unknown':
                        for attr in ['organization', 'name', 'registrant_name']:
                            if hasattr(w, attr) and getattr(w, attr):
                                val = getattr(w, attr)
                                if isinstance(val, list):
                                    whois_data['organization'] = val[0] if val[0] else 'Unknown'
                                else:
                                    whois_data['organization'] = str(val)
                                break
                    
                    # Extract dates
                    if hasattr(w, 'creation_date') and w.creation_date:
                        if isinstance(w.creation_date, list):
                            whois_data['creation_date'] = str(w.creation_date[0]) if w.creation_date[0] else 'Unknown'
                        else:
                            whois_data['creation_date'] = str(w.creation_date)
                    
                    if hasattr(w, 'expiration_date') and w.expiration_date:
                        if isinstance(w.expiration_date, list):
                            whois_data['expiration_date'] = str(w.expiration_date[0]) if w.expiration_date[0] else 'Unknown'
                        else:
                            whois_data['expiration_date'] = str(w.expiration_date)
                    
                    # Extract emails
                    if hasattr(w, 'emails') and w.emails:
                        emails = w.emails if isinstance(w.emails, list) else [w.emails]
                        if emails:
                            whois_data['registrant_email'] = emails[0]
                            if len(emails) > 1:
                                whois_data['admin_email'] = emails[1]
                
                rprint(f"      ✅ WHOIS data retrieved for {domain}")
                
        except Exception as e:
            rprint(f"      ❌ WHOIS lookup failed for {domain}: {e}")
            
            # Method 2: Try WhoisXML API if available
            if self.whoisxml_api_key:
                try:
                    whois_data = self._get_whoisxml_data(domain)
                except Exception as e:
                    rprint(f"      ❌ WhoisXML API failed: {e}")
        
        return whois_data
    
    def _get_whoisxml_data(self, domain):
        """Get WHOIS data from WhoisXML API"""
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            'apiKey': self.whoisxml_api_key,
            'domainName': domain,
            'outputFormat': 'JSON'
        }
        
        response = requests.get(url, params=params, timeout=10)
        if response.ok:
            data = response.json()
            whois_record = data.get('WhoisRecord', {})
            
            return {
                'registrar': whois_record.get('registrarName', 'Unknown'),
                'organization': whois_record.get('registrant', {}).get('organization', 'Unknown'),
                'creation_date': whois_record.get('createdDate', 'Unknown'),
                'expiration_date': whois_record.get('expiresDate', 'Unknown'),
                'registrant_email': whois_record.get('registrant', {}).get('email', 'Unknown'),
                'admin_email': whois_record.get('administrativeContact', {}).get('email', 'Unknown')
            }
        
        return {
            'registrar': 'API_Error',
            'organization': 'API_Error',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'registrant_email': 'Unknown',
            'admin_email': 'Unknown'
        }
    
    # ========== Enhanced DNS Data Retrieval ==========
    
    def _get_enhanced_dns_info(self, domain):
        """Get comprehensive DNS information"""
        dns_info = {
            'nameservers': [],
            'mx_records': [],
            'txt_records': [],
            'a_records': [],
            'aaaa_records': []
        }
        
        if not DNS_AVAILABLE:
            rprint(f"      ⚠️  DNS resolver not available for {domain}")
            return dns_info
        
        try:
            # Get nameservers
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_info['nameservers'] = [str(ns).rstrip('.') for ns in ns_records]
                rprint(f"      📡 Found {len(dns_info['nameservers'])} nameservers for {domain}")
            except Exception as e:
                rprint(f"      ❌ NS lookup failed for {domain}: {e}")
            
            # Get MX records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [f"{mx.priority} {str(mx.exchange).rstrip('.')}" for mx in mx_records]
            except:
                pass
            
            # Get TXT records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(txt).strip('"') for txt in txt_records]
            except:
                pass
            
            # Get A records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(a) for a in a_records]
            except:
                pass
            
            # Get AAAA records (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                dns_info['aaaa_records'] = [str(aaaa) for aaaa in aaaa_records]
            except:
                pass
                
        except Exception as e:
            rprint(f"      ❌ DNS lookup failed for {domain}: {e}")
        
        return dns_info
    
    # ========== FIXED Certificate Transparency Discovery ==========
    
    def discover_via_smart_certificate_transparency(self):
        """Smart CT discovery with improved timeout handling"""
        rprint(f"[blue]🔍 Smart Certificate Transparency Discovery[/blue]")
        
        # Search by company keywords, not certificate issuers
        search_patterns = []
        
        # Use company keywords for search
        for keyword in self.company_keywords[:3]:  # Limit to top 3 keywords
            search_patterns.append(keyword)
        
        # Also search around primary domain if provided
        if self.primary_domain:
            domain_root = self.primary_domain.split('.')[0]
            search_patterns.append(domain_root)
        
        for pattern in search_patterns:
            self._search_crt_by_domain_pattern_fixed(pattern)
            time.sleep(2)  # Increased rate limiting
    
    def _search_crt_by_domain_pattern_fixed(self, pattern):
        """FIXED: Search crt.sh with better timeout and retry handling"""
        try:
            url = f"https://crt.sh/?q=%25{pattern}%25&output=json"
            
            # Multiple timeout attempts with exponential backoff
            timeouts = [10, 20, 35, 50]  # Progressive timeouts
            
            for i, timeout in enumerate(timeouts):
                try:
                    rprint(f"    ⏱️  Attempting CT search for '{pattern}' (timeout: {timeout}s, attempt {i+1}/{len(timeouts)})")
                    
                    # Use session for better connection handling
                    session = requests.Session()
                    session.headers.update({
                        'User-Agent': 'Mozilla/5.0 (compatible; DomainFinder/2.0)',
                        'Accept': 'application/json',
                        'Connection': 'close'
                    })
                    
                    response = session.get(url, timeout=timeout)
                    
                    if response.ok and response.text.strip():
                        try:
                            certificates = response.json()
                            rprint(f"  📜 Found {len(certificates)} certificates for pattern: {pattern}")
                            
                            relevant_domains = set()
                            for cert in certificates[:150]:  # Increased limit
                                domains = self._extract_domains_from_cert(cert)
                                for domain in domains:
                                    if self._is_company_related(domain):
                                        relevant_domains.add(domain)
                            
                            rprint(f"    ✅ {len(relevant_domains)} relevant domains found")
                            for domain in relevant_domains:
                                self._add_domain(domain, "smart_cert_transparency", 85)
                            
                            session.close()
                            return  # Success, exit function
                            
                        except json.JSONDecodeError:
                            rprint(f"    ❌ Invalid JSON response from crt.sh")
                            session.close()
                            break
                    else:
                        rprint(f"    ⚠️  Empty response from crt.sh (attempt {i+1})")
                        session.close()
                        if i < len(timeouts) - 1:  # Not last attempt
                            time.sleep(2 ** i)  # Exponential backoff
                            continue
                        
                except requests.exceptions.Timeout:
                    rprint(f"    ⏱️  Timeout at {timeout}s (attempt {i+1})")
                    if i < len(timeouts) - 1:  # Not last attempt
                        time.sleep(2 ** i)  # Exponential backoff
                        continue
                except requests.exceptions.ConnectionError:
                    rprint(f"    ❌ Connection error (attempt {i+1})")
                    if i < len(timeouts) - 1:
                        time.sleep(2 ** i)
                        continue
                except Exception as e:
                    rprint(f"    ❌ Request failed: {e}")
                    break
                    
            rprint(f"  ❌ All CT attempts failed for pattern: {pattern}")
            
        except Exception as e:
            rprint(f"  ❌ CT search failed for {pattern}: {e}")
    
    def _extract_domains_from_cert(self, cert):
        """Extract domains from certificate"""
        domains = set()
        
        # Common name
        if cert.get('common_name'):
            domain = cert['common_name'].strip().lower()
            if domain.startswith('*.'):
                domain = domain[2:]
            if domain and self._is_valid_domain(domain):
                domains.add(domain)
        
        # Subject Alternative Names
        if cert.get('name_value'):
            for name in cert['name_value'].split('\n'):
                domain = name.strip().lower()
                if domain.startswith('*.'):
                    domain = domain[2:]
                if domain and self._is_valid_domain(domain):
                    domains.add(domain)
        
        return domains
    
    # ========== Enhanced WHOIS and Registration Discovery ==========
    
    def discover_via_whois_analysis(self):
        """Discover domains through WHOIS analysis"""
        rprint(f"[blue]🔍 WHOIS Analysis Discovery[/blue]")
        
        if not self.primary_domain:
            rprint("[yellow]⚠️  No primary domain for WHOIS analysis[/yellow]")
            return
        
        # Get WHOIS info for primary domain
        whois_info = self._get_basic_whois_info(self.primary_domain)
        
        if whois_info:
            registrar = whois_info.get('registrar', '')
            if registrar:
                rprint(f"  🏢 Primary domain registrar: {registrar}")
                # In a real implementation, you'd query reverse WHOIS APIs here
        
        # Check domain variations
        self._check_domain_variations()
    
    def _get_basic_whois_info(self, domain):
        """Get basic WHOIS info"""
        try:
            rprint(f"  🔍 Checking WHOIS for {domain}")
            if WHOIS_AVAILABLE:
                w = whois.whois(domain)
                if w and hasattr(w, 'registrar'):
                    return {
                        'registrar': str(w.registrar) if w.registrar else 'Unknown',
                        'organization': str(w.org) if hasattr(w, 'org') and w.org else 'Unknown'
                    }
            return {'registrar': 'Unknown', 'organization': 'Unknown'}
        except Exception as e:
            rprint(f"  ❌ WHOIS lookup failed: {e}")
            return {}
    
    def _check_domain_variations(self):
        """Check common domain variations"""
        if not self.company_keywords:
            return
        
        rprint(f"  🔍 Checking domain variations")
        
        # Common TLDs to check
        tlds = ['.com', '.org', '.net', '.in', '.co.in', '.info', '.biz', '.co', '.io']
        
        # Generate variations
        variations = []
        for keyword in self.company_keywords[:3]:  # Increased limit
            for tld in tlds:
                variations.append(f"{keyword}{tld}")
        
        # Check variations in batches
        found_count = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_domain_exists, domain): domain 
                      for domain in variations[:30]}  # Increased limit
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    if future.result():
                        self._add_domain(domain, "domain_variation", 75)
                        found_count += 1
                except:
                    continue
        
        rprint(f"    ✅ Found {found_count} active domain variations")
    
    def _check_domain_exists(self, domain):
        """Check if domain exists"""
        try:
            socket.gethostbyname(domain)
            return True
        except:
            return False
    
    # ========== Website Content Analysis ==========
    
    def discover_via_website_analysis(self):
        """Analyze website content for related domains"""
        rprint(f"[blue]🔍 Website Content Analysis[/blue]")
        
        if not self.primary_domain:
            rprint("[yellow]⚠️  No primary domain for website analysis[/yellow]")
            return
        
        try:
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                try:
                    response = requests.get(f"{protocol}://{self.primary_domain}", 
                                          timeout=15, verify=False,
                                          headers={'User-Agent': 'Mozilla/5.0 (compatible; DomainFinder/2.0)'})
                    
                    if response.ok:
                        content = response.text
                        domains = self._extract_domains_from_content(content)
                        
                        relevant_domains = []
                        for domain in domains:
                            if self._is_company_related(domain):
                                relevant_domains.append(domain)
                                self._add_domain(domain, "website_content", 80)
                        
                        rprint(f"  ✅ Found {len(relevant_domains)} relevant domains in website content")
                        return  # Success, exit
                        
                except:
                    continue
                    
            rprint(f"  ❌ Failed to fetch website content for {self.primary_domain}")
                
        except Exception as e:
            rprint(f"  ❌ Website analysis failed: {e}")
    
    def _extract_domains_from_content(self, content):
        """Extract domains from website content"""
        # Find all URLs and extract domains
        url_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        found_urls = re.findall(url_pattern, content.lower())
        
        # Also find domain-like patterns without protocol
        domain_pattern = r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
        found_domains = re.findall(domain_pattern, content.lower())
        
        all_domains = set(found_urls + found_domains)
        
        # Filter out invalid domains
        valid_domains = []
        for domain in all_domains:
            if self._is_valid_domain(domain) and not self._is_excluded_domain(domain):
                valid_domains.append(domain)
        
        return valid_domains[:100]  # Increased limit
    
    # ========== Infrastructure Correlation (Focused) ==========
    
    def discover_via_focused_infrastructure(self):
        """Focused infrastructure analysis"""
        rprint(f"[blue]🔍 Focused Infrastructure Analysis[/blue]")
        
        if not self.primary_domain:
            rprint("[yellow]⚠️  No primary domain for infrastructure analysis[/yellow]")
            return
        
        try:
            # Get primary domain IP
            primary_ip = socket.gethostbyname(self.primary_domain)
            rprint(f"  🎯 Primary domain IP: {primary_ip}")
            
            # Check a small range around the primary IP
            self._check_nearby_ips(primary_ip)
            
            # Get nameservers
            self._analyze_nameservers()
            
        except Exception as e:
            rprint(f"  ❌ Infrastructure analysis failed: {e}")
    
    def _check_nearby_ips(self, primary_ip):
        """Check IPs near the primary domain IP"""
        try:
            ip_obj = ipaddress.IPv4Address(primary_ip)
            
            # Check just a few nearby IPs
            nearby_ips = []
            for offset in [-5, -2, -1, 1, 2, 5, 10, 20, 50]:  # Expanded range
                try:
                    nearby_ip = str(ip_obj + offset)
                    nearby_ips.append(nearby_ip)
                except:
                    continue
            
            found_count = 0
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = {executor.submit(self._reverse_dns_lookup, ip): ip 
                          for ip in nearby_ips}
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        hostname = future.result()
                        if hostname and self._is_company_related(hostname):
                            self._add_domain(hostname, "infrastructure_correlation", 70)
                            found_count += 1
                    except:
                        continue
            
            if found_count > 0:
                rprint(f"    ✅ Found {found_count} domains in nearby IP space")
            else:
                rprint(f"    ℹ️  No related domains found in nearby IP space")
                
        except Exception as e:
            rprint(f"    ❌ IP range analysis failed: {e}")
    
    def _reverse_dns_lookup(self, ip):
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def _analyze_nameservers(self):
        """Analyze nameserver patterns"""
        try:
            if DNS_AVAILABLE:
                ns_records = dns.resolver.resolve(self.primary_domain, 'NS')
                nameservers = [str(ns).rstrip('.') for ns in ns_records]
                
                rprint(f"  📡 Nameservers: {', '.join(nameservers)}")
                
                # Check if nameservers are custom (might indicate other company domains)
                custom_ns = []
                for ns in nameservers:
                    for keyword in self.company_keywords:
                        if keyword in ns.lower():
                            custom_ns.append(ns)
                
                if custom_ns:
                    rprint(f"    🎯 Custom nameservers found: {custom_ns}")
                    # In practice, you'd do reverse NS lookups here
            else:
                rprint(f"  ⚠️  DNS resolver not available for nameserver analysis")
            
        except Exception as e:
            rprint(f"    ❌ Nameserver analysis failed: {e}")
    
    # ========== Third-party API Integration ==========
    
    def discover_via_virustotal(self):
        """Discover domains via VirusTotal API"""
        if not self.virustotal_api_key:
            rprint("[yellow]⚠️  VirusTotal API key not configured[/yellow]")
            return
            
        rprint(f"[blue]🔍 VirusTotal Domain Discovery[/blue]")
        
        if self.primary_domain:
            self._virustotal_domain_analysis(self.primary_domain)
    
    def _virustotal_domain_analysis(self, domain):
        """Analyze domain using VirusTotal"""
        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': self.virustotal_api_key, 'domain': domain}
            
            response = requests.get(url, params=params, timeout=15)
            if response.ok:
                data = response.json()
                
                # Extract related domains
                if data.get('response_code') == 1:
                    # Subdomains
                    for subdomain in data.get('subdomains', []):
                        if self._is_company_related(subdomain):
                            self._add_domain(subdomain, "virustotal_subdomains", 80)
                    
                    # Detected URLs
                    for url_data in data.get('detected_urls', [])[:100]:
                        url_str = url_data.get('url', '')
                        if url_str:
                            try:
                                from urllib.parse import urlparse
                                parsed = urlparse(url_str)
                                if parsed.hostname and self._is_company_related(parsed.hostname):
                                    self._add_domain(parsed.hostname, "virustotal_urls", 70)
                            except:
                                continue
                                
        except Exception as e:
            rprint(f"  ❌ VirusTotal analysis failed: {e}")
    
    def discover_via_shodan(self):
        """Discover domains via Shodan API"""
        if not self.shodan_api_key:
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
            url = f"https://api.shodan.io/shodan/host/search?key={self.shodan_api_key}&query={query}"
            response = requests.get(url, timeout=15)
            
            if response.ok:
                data = response.json()
                for result in data.get('matches', []):
                    # Extract hostnames
                    hostnames = result.get('hostnames', [])
                    for hostname in hostnames:
                        if self._is_company_related(hostname):
                            self._add_domain(hostname, "shodan_search", 85)
                            
        except Exception as e:
            rprint(f"  ❌ Shodan search failed for query '{query}': {e}")
    
    # ========== Enhanced Domain Enrichment ==========
    
    def enrich_domain_info(self):
        """Enhanced domain enrichment with real WHOIS and DNS data"""
        rprint(f"[blue]🔍 Enhanced Domain Information Enrichment[/blue]")
        
        if not WHOIS_AVAILABLE:
            rprint("[yellow]⚠️  python-whois not installed. Install with: pip install python-whois[/yellow]")
        
        if not DNS_AVAILABLE:
            rprint("[yellow]⚠️  dnspython not installed. Install with: pip install dnspython[/yellow]")
        
        domains_to_enrich = list(self.discovered_domains.keys())
        
        # Limit enrichment to prevent overwhelming and rate limiting
        if len(domains_to_enrich) > 50:
            rprint(f"  ⚠️  Limiting enrichment to top 50 domains (WHOIS rate limiting)")
            domains_to_enrich = domains_to_enrich[:50]
        
        enriched_count = 0
        with ThreadPoolExecutor(max_workers=3) as executor:  # Reduced for WHOIS rate limiting
            futures = {executor.submit(self._enrich_single_domain_enhanced, domain): domain 
                      for domain in domains_to_enrich}
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    if future.result():
                        enriched_count += 1
                    time.sleep(1.5)  # Increased rate limiting for WHOIS
                except Exception as e:
                    rprint(f"      ❌ Enrichment failed for {domain}: {e}")
        
        rprint(f"  ✅ Enhanced enrichment completed for {enriched_count}/{len(domains_to_enrich)} domains")
    
    def _enrich_single_domain_enhanced(self, domain):
        """Enhanced enrichment for a single domain"""
        domain_info = self.discovered_domains[domain]
        
        try:
            # Get IP address and check if active
            ip_address = socket.gethostbyname(domain)
            domain_info.ip_address = ip_address
            domain_info.is_active = True
            
            # Get enhanced DNS information
            dns_info = self._get_enhanced_dns_info(domain)
            domain_info.nameservers = dns_info['nameservers']
            
            # Get WHOIS information (with rate limiting)
            whois_data = self._get_enhanced_whois_info(domain)
            domain_info.organization = whois_data['organization']
            domain_info.registrar = whois_data['registrar']
            domain_info.whois_data = whois_data
            
            # Test HTTP/HTTPS connectivity
            try:
                response = requests.head(f"https://{domain}", timeout=8, verify=False)
                if response.status_code < 400:
                    domain_info.ssl_info['https_available'] = True
            except:
                try:
                    response = requests.head(f"http://{domain}", timeout=8)
                    if response.status_code < 400:
                        domain_info.ssl_info['http_available'] = True
                except:
                    pass
            
            return True
            
        except socket.gaierror:
            # Domain doesn't resolve
            domain_info.is_active = False
            domain_info.ip_address = "No DNS Record"
            return False
        except Exception as e:
            domain_info.is_active = False
            domain_info.ip_address = "Resolution Failed"
            return False
    
    # ========== FIXED CSV Export ==========
    
    def export_to_csv(self, filename):
        """FIXED: Export results to enhanced CSV file with proper timestamp"""
        rprint(f"[blue]📊 Exporting enhanced results to CSV: {filename}[/blue]")
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # Define CSV columns
                fieldnames = [
                    'Domain',
                    'Discovery_Method',
                    'Confidence_Score',
                    'IP_Address',
                    'Status',
                    'Organization',
                    'Registrar',
                    'Matched_Keywords',
                    'Nameservers',
                    'HTTPS_Available',
                    'HTTP_Available',
                    'Creation_Date',
                    'Expiration_Date',
                    'Registrant_Email',
                    'Discovery_Timestamp'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Get current timestamp in proper format
                current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                
                # Sort domains by confidence score
                sorted_domains = sorted(
                    self.discovered_domains.items(),
                    key=lambda x: x[1].confidence_score,
                    reverse=True
                )
                
                # Write domain data
                for domain, info in sorted_domains:
                    # Find matching keywords
                    matched_keywords = []
                    for keyword in self.company_keywords:
                        if keyword in domain.lower():
                            matched_keywords.append(keyword)
                    
                    # Format nameservers (limit to first 2 for readability)
                    ns_display = ', '.join(info.nameservers[:2]) if info.nameservers else 'Unknown'
                    if len(info.nameservers) > 2:
                        ns_display += f" (+{len(info.nameservers)-2} more)"
                    
                    # Prepare row data
                    row_data = {
                        'Domain': domain,
                        'Discovery_Method': info.discovery_method,
                        'Confidence_Score': info.confidence_score,
                        'IP_Address': info.ip_address or 'Unknown',
                        'Status': 'Active' if info.is_active else 'Inactive',
                        'Organization': info.organization or 'Unknown',
                        'Registrar': info.registrar or 'Unknown',
                        'Matched_Keywords': ', '.join(matched_keywords) if matched_keywords else 'None',
                        'Nameservers': ns_display,
                        'HTTPS_Available': 'Yes' if info.ssl_info.get('https_available') else 'No',
                        'HTTP_Available': 'Yes' if info.ssl_info.get('http_available') else 'No',
                        'Creation_Date': str(info.whois_data.get('creation_date', 'Unknown'))[:19],  # Truncate long dates
                        'Expiration_Date': str(info.whois_data.get('expiration_date', 'Unknown'))[:19],
                        'Registrant_Email': info.whois_data.get('registrant_email', 'Unknown'),
                        'Discovery_Timestamp': current_time
                    }
                    
                    writer.writerow(row_data)
                
                rprint(f"  ✅ Successfully exported {len(sorted_domains)} domains to enhanced CSV")
                
        except Exception as e:
            rprint(f"  ❌ Enhanced CSV export failed: {e}")
    
    def export_summary_csv(self, filename):
        """Export summary statistics to CSV"""
        summary_filename = filename.replace('.csv', '_summary.csv')
        rprint(f"[blue]📈 Exporting summary to CSV: {summary_filename}[/blue]")
        
        try:
            with open(summary_filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Metric', 'Value']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Calculate summary statistics
                total_domains = len(self.discovered_domains)
                active_domains = sum(1 for d in self.discovered_domains.values() if d.is_active)
                inactive_domains = total_domains - active_domains
                whois_retrieved = sum(1 for d in self.discovered_domains.values() if d.organization != 'Unknown')
                
                # Method breakdown
                methods = {}
                for domain_info in self.discovered_domains.values():
                    method = domain_info.discovery_method
                    methods[method] = methods.get(method, 0) + 1
                
                # Get current timestamp
                current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                
                # Write summary data
                summary_data = [
                    {'Metric': 'Company_Name', 'Value': self.company_name},
                    {'Metric': 'Primary_Domain', 'Value': self.primary_domain or 'Not_Specified'},
                    {'Metric': 'Discovery_Timestamp', 'Value': current_time},
                    {'Metric': 'Total_Domains_Found', 'Value': total_domains},
                    {'Metric': 'Active_Domains', 'Value': active_domains},
                    {'Metric': 'Inactive_Domains', 'Value': inactive_domains},
                    {'Metric': 'WHOIS_Data_Retrieved', 'Value': whois_retrieved},
                    {'Metric': 'Success_Rate', 'Value': f"{(active_domains/total_domains*100):.1f}%" if total_domains > 0 else "0%"},
                    {'Metric': 'Company_Keywords', 'Value': ', '.join(self.company_keywords[:5])},
                ]
                
                # Add method statistics
                for method, count in methods.items():
                    summary_data.append({
                        'Metric': f'Method_{method.replace("_", " ").title().replace(" ", "_")}',
                        'Value': count
                    })
                
                for row in summary_data:
                    writer.writerow(row)
                
                rprint(f"  ✅ Successfully exported summary statistics to CSV")
                
        except Exception as e:
            rprint(f"  ❌ Summary CSV export failed: {e}")
    
    # ========== Utility Methods ==========
    
    def _is_valid_domain(self, domain):
        """Check if string is a valid domain"""
        if not domain or len(domain) > 253 or len(domain) < 4:
            return False
        
        # Skip IP addresses
        try:
            ipaddress.ip_address(domain)
            return False
        except:
            pass
        
        # Basic domain regex
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
        return re.match(domain_pattern, domain) is not None
    
    def _add_domain(self, domain, method, confidence):
        """Add discovered domain"""
        if domain not in self.discovered_domains:
            self.discovered_domains[domain] = DomainInfo(
                domain=domain,
                discovery_method=method,
                confidence_score=confidence
            )
        else:
            # Update if higher confidence
            existing = self.discovered_domains[domain]
            if confidence > existing.confidence_score:
                existing.confidence_score = confidence
                existing.discovery_method = method
    
    # ========== Main Discovery Process ==========
    
    def discover_all_domains(self):
        """Run all discovery methods"""
        start_time = time.time()
        
        if console:
            console.print(Panel.fit(
                f"[bold cyan]🏢 COMPLETE FIXED DOMAIN DISCOVERY[/bold cyan]\n"
                f"[yellow]Company: {self.company_name}[/yellow]\n"
                f"[yellow]Primary Domain: {self.primary_domain or 'Not specified'}[/yellow]\n"
                f"[yellow]WHOIS Available: {'✅' if WHOIS_AVAILABLE else '❌ (pip install python-whois)'}[/yellow]\n"
                f"[yellow]DNS Available: {'✅' if DNS_AVAILABLE else '❌ (pip install dnspython)'}[/yellow]\n"
                f"[yellow]VirusTotal API: {'✅' if self.virustotal_api_key else '❌'}[/yellow]\n"
                f"[yellow]Shodan API: {'✅' if self.shodan_api_key else '❌'}[/yellow]",
                style="blue"
            ))
        
        # Run all discovery methods
        self.discover_via_smart_certificate_transparency()
        self.discover_via_whois_analysis()
        self.discover_via_website_analysis()
        self.discover_via_focused_infrastructure()
        
        # Optional API-based discovery
        if self.virustotal_api_key:
            self.discover_via_virustotal()
        
        if self.shodan_api_key:
            self.discover_via_shodan()
        
        # Enhanced enrichment with real data
        if self.discovered_domains:
            self.enrich_domain_info()
        
        elapsed_time = time.time() - start_time
        rprint(f"\n[green]✅ Complete fixed discovery finished in {elapsed_time:.2f} seconds[/green]")
        
        return self.discovered_domains
    
    def display_results(self):
        """Display enhanced results with proper alignment"""
        if not self.discovered_domains:
            rprint("[yellow]⚠️  No company domains discovered[/yellow]")
            return
        
        total_domains = len(self.discovered_domains)
        active_domains = sum(1 for d in self.discovered_domains.values() if d.is_active)
        whois_retrieved = sum(1 for d in self.discovered_domains.values() if d.organization != 'Unknown')
        
        if console:
            # Summary table
            summary_table = Table(title="Complete Fixed Discovery Summary")
            summary_table.add_column("Metric", style="cyan")
            summary_table.add_column("Count", style="green")
            
            summary_table.add_row("Total Relevant Domains", str(total_domains))
            summary_table.add_row("Active Domains", str(active_domains))
            summary_table.add_row("Inactive/Unresolved", str(total_domains - active_domains))
            summary_table.add_row("WHOIS Data Retrieved", str(whois_retrieved))
            summary_table.add_row("Nameservers Retrieved", str(sum(1 for d in self.discovered_domains.values() if d.nameservers)))
            
            # Method breakdown
            methods = {}
            for domain_info in self.discovered_domains.values():
                method = domain_info.discovery_method
                methods[method] = methods.get(method, 0) + 1
            
            for method, count in methods.items():
                summary_table.add_row(f"  {method.replace('_', ' ').title()}", str(count))
            
            console.print(summary_table)
            print()
            
            # Domain details with FIXED emoji alignment
            details_table = Table(title="Complete Fixed Domain Details")
            details_table.add_column("Domain", style="cyan", width=40)
            details_table.add_column("Method", style="yellow", width=20)
            details_table.add_column("Confidence", style="green", width=10)
            details_table.add_column("IP Address", style="blue", width=15)
            details_table.add_column("Status", style="magenta", width=12)
            details_table.add_column("Organization", style="white", width=20)
            
            # Sort by confidence, then by active status
            sorted_domains = sorted(
                self.discovered_domains.items(),
                key=lambda x: (x[1].confidence_score, x[1].is_active),
                reverse=True
            )
            
            for domain, info in sorted_domains[:25]:  # Show top 25
                # Status with proper alignment using Rich Text objects
                if info.is_active:
                    status_text = Text()
                    status_text.append("●", style="green")
                    status_text.append(" Active", style="green")
                    ip_display = info.ip_address or "Unknown"
                else:
                    status_text = Text()
                    status_text.append("●", style="red")
                    status_text.append(" Inactive", style="red")
                    ip_display = info.ip_address or "No DNS"
                
                # Truncate long fields
                domain_display = domain[:37] + "..." if len(domain) > 40 else domain
                method_display = info.discovery_method.replace('_', ' ')[:17]
                org_display = (info.organization or "Unknown")[:17] + "..." if len(info.organization or "Unknown") > 20 else (info.organization or "Unknown")
                
                details_table.add_row(
                    domain_display,
                    method_display,
                    f"{info.confidence_score}%",
                    ip_display,
                    status_text,
                    org_display
                )
            
            console.print(details_table)
        else:
            # Fallback text display with fixed alignment
            rprint(f"\n{'='*150}")
            rprint(f"COMPLETE FIXED DISCOVERY RESULTS ({total_domains} total, {active_domains} active)")
            rprint(f"{'='*150}")
            rprint(f"{'Domain':<45} | {'Method':<20} | {'Conf':<4} | {'IP Address':<15} | {'Status':<10} | {'Organization':<20}")
            rprint(f"{'-'*150}")
            
            for domain, info in self.discovered_domains.items():
                # Use consistent text-based status indicators
                status = "● Active  " if info.is_active else "● Inactive"
                ip_addr = (info.ip_address or "Unknown")[:15]
                org = (info.organization or "Unknown")[:20]
                
                rprint(f"{domain[:44]:<45} | {info.discovery_method[:19]:<20} | {info.confidence_score:3d}% | {ip_addr:<15} | {status:<10} | {org}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Complete Fixed Company Domain Discovery Tool - All Issues Resolved',
        epilog="""
Examples:
  python complete_fixed_domain_finder.py "CK Birla Hospital" --primary-domain ckbhospital.com --csv results.csv
  
Required Dependencies:
  pip install python-whois dnspython rich requests
  
Optional API Keys (set as environment variables):
  export WHOISXML_API_KEY="your_api_key"
  export SECURITYTRAILS_API_KEY="your_api_key"
  export SHODAN_API_KEY="your_api_key"
  export VIRUSTOTAL_API_KEY="your_api_key"
        """
    )
    
    parser.add_argument('company_name', help='Company name to search for')
    parser.add_argument('--primary-domain', help='Known primary domain of the company')
    parser.add_argument('--csv', help='Export results to CSV file')
    parser.add_argument('--json', '--output', '-o', help='Export results to JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        # Initialize complete fixed finder
        finder = CompleteFixedDomainFinder(args.company_name, args.primary_domain)
        
        # Run discovery
        discovered_domains = finder.discover_all_domains()
        
        # Display results
        finder.display_results()
        
        # Export to CSV if requested
        if args.csv:
            finder.export_to_csv(args.csv)
            finder.export_summary_csv(args.csv)
        
        # Export to JSON if requested
        if args.json:
            with open(args.json, 'w') as f:
                export_data = {
                    'company_name': args.company_name,
                    'primary_domain': args.primary_domain,
                    'discovery_timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                    'company_keywords': finder.company_keywords,
                    'summary': {
                        'total_domains': len(discovered_domains),
                        'active_domains': sum(1 for d in discovered_domains.values() if d.is_active),
                        'whois_data_retrieved': sum(1 for d in discovered_domains.values() if d.organization != 'Unknown'),
                        'nameservers_retrieved': sum(1 for d in discovered_domains.values() if d.nameservers)
                    },
                    'discovered_domains': {
                        domain: {
                            'discovery_method': info.discovery_method,
                            'confidence_score': info.confidence_score,
                            'ip_address': info.ip_address,
                            'is_active': info.is_active,
                            'organization': info.organization,
                            'registrar': info.registrar,
                            'nameservers': info.nameservers,
                            'whois_data': info.whois_data,
                            'ssl_info': info.ssl_info
                        }
                        for domain, info in discovered_domains.items()
                    }
                }
                json.dump(export_data, f, indent=2, default=str)
            rprint(f"[green]✅ Results exported to JSON: {args.json}[/green]")
        
        rprint(f"\n[bold green]🎯 Complete Fixed Discovery Finished![/bold green]")
        rprint(f"[green]Found {len(discovered_domains)} relevant company domains[/green]")
        rprint(f"[green]Active: {sum(1 for d in discovered_domains.values() if d.is_active)} | Inactive: {sum(1 for d in discovered_domains.values() if not d.is_active)}[/green]")
        
        # Show dependency status
        if not WHOIS_AVAILABLE:
            rprint(f"[yellow]💡 Install python-whois for real WHOIS data: pip install python-whois[/yellow]")
        if not DNS_AVAILABLE:
            rprint(f"[yellow]💡 Install dnspython for DNS data: pip install dnspython[/yellow]")
        
        # Show API status
        api_count = sum([
            bool(finder.whoisxml_api_key),
            bool(finder.securitytrails_api_key), 
            bool(finder.shodan_api_key),
            bool(finder.virustotal_api_key)
        ])
        rprint(f"[blue]🔑 API Keys configured: {api_count}/4[/blue]")
        
        if len(discovered_domains) == 0:
            rprint(f"\n[yellow]💡 Tips to improve results:[/yellow]")
            rprint(f"[yellow]  - Ensure the company name is spelled correctly[/yellow]")
            rprint(f"[yellow]  - Try variations of the company name[/yellow]")
            rprint(f"[yellow]  - Check if the primary domain is accessible[/yellow]")
            rprint(f"[yellow]  - Configure API keys for enhanced discovery[/yellow]")
            rprint(f"[yellow]  - Try running during off-peak hours for better CT performance[/yellow]")
        
    except KeyboardInterrupt:
        rprint(f"\n[yellow]⚠️  Discovery interrupted by user[/yellow]")
    except Exception as e:
        rprint(f"\n[red]❌ Discovery failed: {e}[/red]")

if __name__ == "__main__":
    main()
