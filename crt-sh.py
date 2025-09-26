#!/usr/bin/env python3
"""
CRT.sh Certificate Scraper

A comprehensive tool for extracting SSL certificate data from Certificate Transparency logs
via crt.sh. Supports both JSON API and web scraping methods with enhanced reliability.

Author: Your Name
License: MIT
Repository: https://github.com/yourusername/crtsh-scraper
"""

import argparse
import json
import random
import sys
import time
from typing import Set, Optional
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class Colors:
    """Color constants for better terminal output."""
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    WARNING = Fore.YELLOW
    INFO = Fore.CYAN
    HEADER = Fore.MAGENTA
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL

class CRTSHScraper:
    """Main scraper class for crt.sh certificate data extraction."""
    
    def __init__(self, domain: str, verbose: bool = False):
        """
        Initialize the scraper.
        
        Args:
            domain: Target domain to search for certificates
            verbose: Enable verbose logging
        """
        self.domain = self._clean_domain(domain)
        self.verbose = verbose
        self.session = requests.Session()
        self._setup_session()
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize the domain input."""
        domain = domain.strip()
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.split('/')[0]  # Remove any path
        return domain.lower()
    
    def _setup_session(self) -> None:
        """Configure the requests session with appropriate headers."""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        })
    
    def _log(self, message: str, level: str = "INFO") -> None:
        """Log messages with appropriate colors."""
        color_map = {
            "SUCCESS": Colors.SUCCESS,
            "ERROR": Colors.ERROR,
            "WARNING": Colors.WARNING,
            "INFO": Colors.INFO
        }
        
        if self.verbose or level in ["SUCCESS", "ERROR"]:
            color = color_map.get(level, Colors.INFO)
            print(f"{color}[{level}]{Colors.RESET} {message}")
    
    def get_json_data(self) -> Set[str]:
        """
        Retrieve certificate data using crt.sh JSON API.
        
        Returns:
            Set of unique certificate identities
        """
        encoded_domain = quote(self.domain)
        json_url = f"https://crt.sh/?q={encoded_domain}&output=json"
        
        self._log(f"Attempting JSON API: {json_url}")
        
        try:
            response = self.session.get(json_url, timeout=30)
            response.raise_for_status()
            
            if response.status_code == 200 and response.content:
                data = response.json()
                identities = set()
                
                for cert in data:
                    # Extract common name
                    if cert.get('common_name'):
                        identities.add(cert['common_name'])
                    
                    # Extract name value (contains Subject Alternative Names)
                    if cert.get('name_value'):
                        names = cert['name_value'].replace('\n', ',').split(',')
                        for name in names:
                            clean_name = name.strip()
                            if clean_name and clean_name != '-':
                                identities.add(clean_name)
                
                self._log(f"JSON API successful: {len(identities)} identities found", "SUCCESS")
                return identities
            
            self._log("No JSON data received", "WARNING")
            return set()
            
        except requests.exceptions.RequestException as e:
            self._log(f"JSON API request failed: {e}", "ERROR")
            return set()
        except json.JSONDecodeError as e:
            self._log(f"Failed to parse JSON response: {e}", "ERROR")
            return set()
        except Exception as e:
            self._log(f"JSON API error: {e}", "ERROR")
            return set()
    
    def get_html_data(self) -> Set[str]:
        """
        Retrieve certificate data using web scraping.
        
        Returns:
            Set of unique certificate identities
        """
        encoded_domain = quote(self.domain)
        url = f"https://crt.sh/?q={encoded_domain}"
        
        self._log(f"Attempting web scraping: {url}")
        
        try:
            # Be respectful with delays
            time.sleep(random.uniform(1, 3))
            
            response = self.session.get(url, timeout=30, allow_redirects=True)
            response.raise_for_status()
            
            if "No certificates found" in response.text:
                self._log("No certificates found for this domain", "WARNING")
                return set()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            table = soup.find('table')
            
            if not table:
                self._log("No certificate table found", "WARNING")
                return set()
            
            rows = table.find_all('tr')
            if len(rows) <= 1:
                self._log("No certificate data in table", "WARNING")
                return set()
            
            # Parse table headers
            header_row = rows[0]
            headers = [th.get_text(strip=True) for th in header_row.find_all(['th', 'td'])]
            
            self._log(f"Table headers: {headers}")
            
            # Find the matching identities column
            identities_col_idx = self._find_identities_column(headers)
            
            if identities_col_idx is None:
                self._log("Could not find matching identities column", "ERROR")
                return set()
            
            self._log(f"Using column '{headers[identities_col_idx]}' at index {identities_col_idx}")
            
            # Extract identities
            identities = set()
            for row in rows[1:]:  # Skip header
                cells = row.find_all(['td', 'th'])
                if len(cells) > identities_col_idx:
                    identity = cells[identities_col_idx].get_text(strip=True)
                    if identity and identity not in ['-', '', 'N/A']:
                        # Handle multiple identities in one cell
                        names = identity.replace('\n', ',').split(',')
                        for name in names:
                            clean_name = name.strip()
                            if clean_name and clean_name not in ['-', 'N/A']:
                                identities.add(clean_name)
            
            self._log(f"Web scraping successful: {len(identities)} identities found", "SUCCESS")
            return identities
            
        except requests.exceptions.RequestException as e:
            self._log(f"Web scraping request failed: {e}", "ERROR")
            return set()
        except Exception as e:
            self._log(f"Web scraping error: {e}", "ERROR")
            return set()
    
    def _find_identities_column(self, headers: list) -> Optional[int]:
        """Find the column index containing certificate identities."""
        # Primary keywords for matching identities column
        primary_keywords = ['matching identities', 'common name', 'identity']
        
        for i, header in enumerate(headers):
            header_lower = header.lower()
            if any(keyword in header_lower for keyword in primary_keywords):
                return i
        
        # Fallback keywords
        fallback_keywords = ['name', 'domain', 'subject', 'cn']
        for i, header in enumerate(headers):
            header_lower = header.lower()
            if any(keyword in header_lower for keyword in fallback_keywords):
                return i
        
        return None
    
    def scrape(self) -> Set[str]:
        """
        Main scraping method that tries multiple approaches.
        
        Returns:
            Set of unique certificate identities
        """
        print(f"{Colors.HEADER}{Colors.BOLD}🔍 CRT.sh Certificate Scraper{Colors.RESET}")
        print(f"{Colors.HEADER}{'=' * 50}{Colors.RESET}")
        print(f"{Colors.INFO}Target Domain: {Colors.BOLD}{self.domain}{Colors.RESET}")
        print()
        
        # Try JSON API first
        identities = self.get_json_data()
        if identities:
            return identities
        
        self._log("JSON API failed, trying web scraping...", "WARNING")
        
        # Fallback to web scraping
        identities = self.get_html_data()
        if identities:
            return identities
        
        self._log("All methods failed", "ERROR")
        return set()
    
    def filter_subdomains(self, identities: Set[str]) -> Set[str]:
        """Filter identities to only include subdomains of the target domain."""
        return {identity for identity in identities if self.domain in identity.lower()}
    
    def save_results(self, identities: Set[str], filename: Optional[str] = None) -> bool:
        """
        Save results to a file.
        
        Args:
            identities: Set of certificate identities to save
            filename: Optional custom filename
            
        Returns:
            True if successful, False otherwise
        """
        if not filename:
            filename = f"crtsh_{self.domain.replace('.', '_')}_results.txt"
        
        try:
            sorted_identities = sorted(identities, key=str.lower)
            subdomains = self.filter_subdomains(identities)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"CRT.sh Certificate Analysis Report\n")
                f.write(f"{'=' * 40}\n\n")
                f.write(f"Target Domain: {self.domain}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Unique Identities: {len(identities)}\n")
                f.write(f"Subdomains Found: {len(subdomains)}\n\n")
                
                f.write("All Certificate Identities:\n")
                f.write("-" * 30 + "\n")
                for i, identity in enumerate(sorted_identities, 1):
                    f.write(f"{i:3d}. {identity}\n")
                
                if subdomains and len(subdomains) != len(identities):
                    f.write(f"\n\nSubdomains of '{self.domain}' only:\n")
                    f.write("-" * 35 + "\n")
                    for i, subdomain in enumerate(sorted(subdomains, key=str.lower), 1):
                        f.write(f"{i:3d}. {subdomain}\n")
            
            return True
            
        except Exception as e:
            self._log(f"Failed to save results: {e}", "ERROR")
            return False

def display_results(domain: str, identities: Set[str]) -> None:
    """Display the results in a formatted manner."""
    if not identities:
        print(f"\n{Colors.ERROR}❌ No certificate identities found for '{domain}'{Colors.RESET}")
        print(f"\n{Colors.WARNING}Possible reasons:{Colors.RESET}")
        print("  • Domain has no SSL certificates in CT logs")
        print("  • Domain is very new or not publicly accessible")
        print("  • Temporary issues with crt.sh")
        print("  • Domain might be misspelled")
        print(f"\n{Colors.INFO}💡 Try checking manually: https://crt.sh/?q={domain}{Colors.RESET}")
        return
    
    sorted_identities = sorted(identities, key=str.lower)
    subdomains = [identity for identity in sorted_identities if domain in identity.lower()]
    
    print(f"\n{Colors.SUCCESS}{Colors.BOLD}✅ SUCCESS!{Colors.RESET}")
    print(f"{Colors.SUCCESS}Found {len(identities)} unique certificate identities{Colors.RESET}")
    print(f"{Colors.HEADER}{'=' * 60}{Colors.RESET}")
    
    # Display all identities
    for i, identity in enumerate(sorted_identities, 1):
        color = Colors.SUCCESS if domain in identity.lower() else Colors.INFO
        print(f"{color}{i:3d}. {identity}{Colors.RESET}")
    
    print(f"{Colors.HEADER}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.INFO}📊 Total unique identities: {Colors.BOLD}{len(identities)}{Colors.RESET}")
    
    # Show subdomain summary if applicable
    if subdomains and len(subdomains) != len(identities):
        print(f"{Colors.INFO}🎯 Subdomains of '{domain}': {Colors.BOLD}{len(subdomains)}{Colors.RESET}")
        print(f"\n{Colors.WARNING}Subdomains only:{Colors.RESET}")
        print(f"{Colors.WARNING}{'-' * 20}{Colors.RESET}")
        for i, subdomain in enumerate(subdomains, 1):
            print(f"{Colors.SUCCESS}{i:3d}. {subdomain}{Colors.RESET}")

def main():
    """Main entry point of the application."""
    parser = argparse.ArgumentParser(
        description="🔍 CRT.sh Certificate Scraper - Extract SSL certificate data from Certificate Transparency logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crtsh_scraper.py -d google.com
  python crtsh_scraper.py -d example.org -v
  python crtsh_scraper.py -d test.com -o results.txt
  python crtsh_scraper.py -d domain.com -v -s
        """
    )
    
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Target domain to search for certificates (e.g., google.com)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output for debugging'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file to save results (default: auto-generated filename)'
    )
    
    parser.add_argument(
        '-s', '--save',
        action='store_true',
        help='Automatically save results to file without prompting'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='CRT.sh Certificate Scraper v2.0'
    )
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    # Create scraper instance
    scraper = CRTSHScraper(args.domain, args.verbose)
    
    try:
        # Perform the scraping
        identities = scraper.scrape()
        
        # Display results
        display_results(scraper.domain, identities)
        
        # Handle file saving
        if identities and (args.save or args.output):
            if scraper.save_results(identities, args.output):
                filename = args.output or f"crtsh_{scraper.domain.replace('.', '_')}_results.txt"
                print(f"\n{Colors.SUCCESS}💾 Results saved to: {Colors.BOLD}{filename}{Colors.RESET}")
            else:
                print(f"\n{Colors.ERROR}❌ Failed to save results{Colors.RESET}")
        elif identities and not args.save:
            # Ask user if they want to save
            try:
                save_choice = input(f"\n{Colors.INFO}💾 Save results to file? (y/N): {Colors.RESET}").strip().lower()
                if save_choice in ['y', 'yes']:
                    if scraper.save_results(identities):
                        filename = f"crtsh_{scraper.domain.replace('.', '_')}_results.txt"
                        print(f"{Colors.SUCCESS}✅ Results saved to: {Colors.BOLD}{filename}{Colors.RESET}")
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Colors.WARNING}⚠️  Save cancelled by user{Colors.RESET}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}⚠️  Operation cancelled by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.ERROR}❌ Unexpected error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
