# Company Domain Discovery Tool

A comprehensive Python tool for discovering all domains potentially owned by a company using multiple reconnaissance techniques including Certificate Transparency, DNS analysis, brand variations, and threat intelligence APIs.

## Features

- **Certificate Transparency Discovery**: Searches public SSL certificate logs
- **Brand Name Variations**: Generates and tests company name variations
- **DNS Infrastructure Analysis**: Analyzes shared nameservers and IP ranges  
- **API Integrations**: Shodan, VirusTotal, HackerTarget, URLScan.io
- **Multi-threaded Operations**: Concurrent DNS lookups and API queries
- **Rich Output**: Colored terminal output with progress indicators
- **Comprehensive Reporting**: JSON export with detailed metadata
- **Rate Limiting**: Respects API quotas and prevents abuse

┌─────────────────────────────────────────────────────────────────────────┐
│                    Company-Domain-Finder                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────┐   │
│  │ Input Layer │    │ Config Layer│    │ API Keys    │    │ Helper  │   │
│  │             │    │             │    │             │    │ Imports │   │
│  │ - Company   │    │ - Keywords  │    │ - WHOISXML  │    │         │   │
│  │   Name      │    │ - Exclusion │    │ - Security  │    │ - whois │   │
│  │ - Primary   │    │   Patterns  │    │   Trails    │    │ - dns   │   │
│  │   Domain    │    │             │    │ - Shodan    │    │ - rich  │   │
│  └─────────────┘    └─────────────┘    │ - VirusTotal│    └─────────┘   │
│                                        └─────────────┘                  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    Discovery Methods                              │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │  │
│  │  │ Certificate     │  │ WHOIS Analysis  │  │ Website Content │    │  │
│  │  │ Transparency    │  │                 │  │ Analysis        │    │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘    │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │  │
│  │  │ Infrastructure  │  │ VirusTotal      │  │ Shodan          │    │  │
│  │  │ Correlation     │  │ Integration     │  │ Integration     │    │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘    │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Data Processing                              │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │  │
│  │  │ Domain          │  │ Validation      │  │ Enrichment      │    │  │
│  │  │ Collection      │  │ - Is Valid      │  │ - Enhanced WHOIS│    │  │
│  │  │ - DomainInfo    │  │ - Is Excluded   │  │ - Enhanced DNS  │    │  │
│  │  │   Data Class    │  │ - Is Related    │  │ - IP/Status     │    │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘    │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                       Output Methods                              │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │  │
│  │  │ Rich Console    │  │ CSV Export      │  │ JSON Export     │    │  │
│  │  │ Display         │  │ - Standard      │  │                 │    │  │
│  │  │ - Tables        │  │ - Summary       │  │                 │    │  │
│  │  │ - Panels        │  │                 │  │                 │    │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘    │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Main Process Flow                            │  │
│  │                                                                   │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  │  │
│  │  │ Initialize  │→ │ Run         │→ │ Enrich      │→ │ Display/ │  │  │
│  │  │ Parameters  │  │ Discovery   │  │ Domains     │  │ Export   │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘  │  │
│  │                                                                   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                       External Dependencies                             │
├─────────────────────────────────────┬───────────────────────────────────┤
│                                     │                                   │
│  ┌─────────────────────────────┐    │    ┌─────────────────────────┐    │
│  │ Local Services              │    │    │ Remote APIs             │    │
│  │                             │    │    │                         │    │
│  │ - DNS Resolver              │    │    │ - crt.sh                │    │
│  │ - Socket/Network            │    │    │ - WHOISXML API          │    │
│  │ - WHOIS Client              │    │    │ - VirusTotal API        │    │
│  │                             │    │    │ - SecurityTrails API    │    │
│  │                             │    │    │ - Shodan API            │    │
│  └─────────────────────────────┘    │    └─────────────────────────┘    │
│                                     │                                   │
└─────────────────────────────────────┴───────────────────────────────────┘


### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup
```bash
# Clone or download the script
git clone https://github.com/elementalsouls/company-domain-finder.git
cd company-domain-finder

# Install dependencies
pip install -r requirements.txt

# Make script executable (optional)
chmod +x domain-finder.py
```

### API Keys Configuration
Set your API keys as environment variables:

```bash
# Required for enhanced discovery
export SHODAN_API_KEY="your_shodan_api_key_here"
export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"

# Optional for additional sources
export OTX_API_KEY="your_otx_api_key_here"
export MISP_API_URL="https://your-misp-instance.com/"
export MISP_API_KEY="your_misp_api_key_here"
```

**Note**: The script includes default API keys for demonstration purposes. Replace them with your own keys for production use.

## Usage

### Basic Usage

```bash
# Basic domain discovery
python domain-finder.py example.com

# With company name for comprehensive discovery
python domain-finder.py example.com --company-name "Example Corporation"

# Export results to file
python domain-finder.py example.com --output example_report.json

# Limit number of subdomains discovered
python domain-finder.py example.com --max-subdomains 100

# Skip DNS brute force (faster execution)
python domain-finder.py example.com --no-bruteforce

# Verbose output with detailed information
python domain-finder.py example.com --verbose
```

### Advanced Usage

```bash
# Complete analysis with all options
python domain-finder.py target-company.com \
  --company-name "Target Company Inc" \
  --output complete_analysis.json \
  --max-subdomains 200 \
  --verbose

# Quick analysis without brute force
python domain-finder.py fastcompany.com \
  --no-bruteforce \
  --max-subdomains 50 \
  --output quick_scan.json

# API connectivity test
python domain-finder.py test.com --test-apis
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `domain` | Target domain to analyze (required) |
| `--company-name` | Company name for comprehensive domain discovery |
| `--output`, `-o` | Export report to JSON file |
| `--max-subdomains` | Maximum number of subdomains to discover |
| `--no-bruteforce` | Skip DNS brute force subdomain discovery |
| `--test-apis` | Test connectivity to all threat intelligence APIs |
| `--verbose`, `-v` | Enable verbose output with detailed information |

## Discovery Methods

### 1. Certificate Transparency
- Searches crt.sh for SSL certificates
- Extracts domains from certificate Subject Alternative Names
- Discovers subdomains and related domains

### 2. Brand Variations
- Generates company name variations (abbreviations, numbers, etc.)
- Tests variations against common TLDs (.com, .net, .org, etc.)
- Includes country-specific TLDs for international companies

### 3. API Integrations

#### VirusTotal
- Domain reputation analysis
- Subdomain extraction from scan results
- Related URL analysis

#### HackerTarget
- Passive DNS subdomain discovery
- Host search functionality

#### URLScan.io
- Domain scanning results
- Related domain discovery

#### Shodan
- Network service discovery
- SSL certificate analysis
- Infrastructure mapping

### 4. DNS Analysis
- Brute force subdomain discovery using common wordlists
- Nameserver analysis
- IP range correlation

## Output

### Console Output
The tool provides rich, colored console output including:
- Progress indicators for each discovery method
- Summary statistics per method
- Threat correlation results with risk scoring
- Detailed domain information tables

### JSON Report
When using `--output`, the tool generates a comprehensive JSON report containing:

```json
{
  "company_name": "Example Corporation",
  "primary_domain": "example.com",
  "discovery_timestamp": "2025-06-10T15:57:34Z",
  "summary": {
    "total_domains": 45,
    "active_domains": 42,
    "discovery_methods": {
      "cert_transparency": 15,
      "brand_variation": 12,
      "virustotal": 8,
      "dns_bruteforce": 10
    }
  },
  "domains": {
    "subdomain.example.com": {
      "discovery_method": "cert_transparency",
      "confidence_score": 85,
      "ip_address": "192.168.1.100",
      "is_active": true,
      "threat_indicators": []
    }
  }
}
```

## API Keys

### Getting API Keys

1. **Shodan**: Register at [shodan.io](https://www.shodan.io/)
2. **VirusTotal**: Register at [virustotal.com](https://www.virustotal.com/)
3. **OTX**: Register at [otx.alienvault.com](https://otx.alienvault.com/)
4. **MISP**: Contact your organization's MISP administrator

### Free Tier Limitations
- **VirusTotal**: 1,000 requests/day
- **Shodan**: 1 result per search, 1,000 queries/month
- **OTX**: Rate limited but generally generous
- **URLScan.io**: Rate limited, no registration required
- **HackerTarget**: Rate limited, no registration required

## Examples

### Example 1: Basic Company Analysis
```bash
python domain-finder.py microsoft.com --company-name "Microsoft Corporation"
```

### Example 2: Quick Subdomain Discovery
```bash
python domain-finder.py github.com --no-bruteforce --max-subdomains 50
```

### Example 3: Complete Analysis with Export
```bash
python domain-finder.py spotify.com \
  --company-name "Spotify Technology S.A." \
  --output spotify_analysis.json \
  --verbose
```

### Example 4: Testing API Connectivity
```bash
python domain-finder.py test.com --test-apis
```

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ENHANCED CYBER THREAT INTELLIGENCE TOOL                  ║
║                              Target: example.com                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

🕷️  COMPREHENSIVE SUBDOMAIN DISCOVERY: example.com
🔍 Certificate Transparency (crt.sh): example.com
  ✅ Found 15 subdomains from certificates
🔍 VirusTotal API: example.com  
  ✅ Found 8 subdomains from VirusTotal
🔍 HackerTarget API: example.com
  ✅ Found 5 subdomains from HackerTarget

📊 Discovery Summary:
  🔍 cert_transparency: 15 subdomains
  🔍 virustotal: 8 subdomains
  🔍 hackertarget: 5 subdomains

✅ Total unique subdomains discovered: 23

🎯 ANALYSIS RESULTS
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
║ Metric                     ║ Count                      ║
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Total Assets               │ 24                         │
│ Subdomains Discovered      │ 23                         │
│ Threat Indicators          │ 2                          │
│ Active Correlations        │ 1                          │
└────────────────────────────┴────────────────────────────┘

🎯 Discovery Complete!
Found 24 potential company domains
```

## Troubleshooting

### Common Issues

1. **DNS Resolution Errors**
   ```bash
   # Check your DNS settings
   nslookup example.com
   ```

2. **API Rate Limiting**
   - Increase delays between requests
   - Use `--no-bruteforce` to reduce API calls
   - Check your API key quotas

3. **SSL Certificate Errors**
   ```python
   # The script handles SSL errors automatically
   # Check your network connectivity if issues persist
   ```

4. **No Results Found**
   - Verify the target domain exists
   - Check if company name spelling is correct
   - Try with `--verbose` for debugging information


## Security Considerations

- **Rate Limiting**: Built-in delays prevent API abuse
- **SSL Verification**: Configurable SSL certificate verification
- **API Key Security**: Use environment variables, never hardcode keys
- **Responsible Use**: Only scan domains you own or have permission to test

## Legal Disclaimer

This tool is intended for legitimate security research, authorized penetration testing, and educational purposes only. Users are responsible for:

- Obtaining proper authorization before scanning any domains
- Complying with applicable laws and regulations
- Respecting API terms of service and rate limits
- Using the tool ethically and responsibly

The authors are not responsible for any misuse of this tool.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add appropriate tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

**elementalsouls**
- GitHub: [@elementalsouls](https://github.com/elementalsouls)
- Date: 2025-06-10

## Acknowledgments

- Certificate Transparency project and crt.sh
- VirusTotal, Shodan, HackerTarget, URLScan.io for their APIs
- Rich library for beautiful terminal output
- DNS Python library for DNS operations
- The cybersecurity community for continuous improvements and feedback
