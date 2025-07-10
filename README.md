# IP Threat Intelligence (IPTI)

A comprehensive Python tool for checking IP addresses against multiple threat intelligence platforms to determine if they are malicious or safe. This tool provides advanced threat assessment through multi-platform analysis, geographic risk evaluation, port scanning, and DNS analysis.

## 🚀 Features

### Core Capabilities
- **Multi-Platform Threat Intelligence**: Checks IP addresses against 4 major threat intelligence platforms:
  - AbuseIPDB - Community-driven IP reputation database
  - VirusTotal - Comprehensive malware and threat detection
  - ThreatBook IO - Advanced threat intelligence platform
  - AlienVault OTX - Open threat exchange with global threat data

### Advanced Analysis Modules
- **Geographic Risk Assessment**: Evaluates risk based on IP location using configurable high-risk country lists
- **Provider Risk Assessment**: Analyzes hosting provider risk using configurable high-risk provider lists
- **Privacy/Proxy Detection**: Identifies VPN, Tor, proxy, and relay usage
- **Port Analysis**: Examines open ports and services using Shodan data with intelligent categorization
- **PTR Record Analysis**: Evaluates DNS PTR records for suspicious patterns and risk assessment
- **Comprehensive Scoring**: Weighted scoring system combining all factors for accurate threat assessment

### Usage Modes
- **Command-line tool** for batch processing and automation
- **Python library** for integration into your own applications
- **Flexible input methods**: Individual IPs, multiple IPs, or batch file processing
- **Multiple output formats**: Colored terminal output, JSON, and text files

### Configuration & Customization
- **Configurable thresholds** for all risk factors
- **Customizable risk lists** for countries and providers
- **Adjustable scoring weights** for different assessment components
- **Caching system** for improved performance and reduced API calls

## 📋 Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Command-Line Tool](#command-line-tool)
  - [Library Usage](#library-usage)
- [Assessment Logic](#assessment-logic)
- [Output Formats](#output-formats)
- [API Requirements](#api-requirements)
- [Error Handling](#error-handling)
- [Performance & Caching](#performance--caching)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- Valid API keys for the required services

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bayufedra/ipti
   cd ipti
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv iptivenv
   source iptivenv/bin/activate  # On Windows: iptivenv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

### API Keys Setup

Create a `.env` file in the project root with your API keys:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
THREATBOOK_API_KEY=your_threatbook_api_key_here
ALIENVAULT_API_KEY=your_alienvault_api_key_here
IPINFO_API_KEY=your_ipinfo_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
```

### Getting API Keys

| Service | URL | Description |
|---------|-----|-------------|
| **AbuseIPDB** | [abuseipdb.com](https://www.abuseipdb.com/) | Community-driven IP reputation database |
| **VirusTotal** | [virustotal.com](https://www.virustotal.com/) | Comprehensive malware and threat detection |
| **ThreatBook IO** | [threatbook.io](https://www.threatbook.io/) | Advanced threat intelligence platform |
| **AlienVault OTX** | [otx.alienvault.com](https://otx.alienvault.com/) | Open threat exchange with global threat data |
| **IPInfo** | [ipinfo.io](https://ipinfo.io/) | IP geolocation and metadata service |
| **Shodan** | [shodan.io](https://shodan.io/) | Internet-wide port scanning and service detection |

### Risk Assessment Configuration

The tool includes configurable risk assessment based on geographic location and hosting providers. You can modify these settings in `config.py`:

#### High-Risk Countries
```python
HIGH_RISK_COUNTRY = [
    "CN",  # China (context-dependent)
    "RU",  # Russia (context-dependent)
    "IN",  # India (context-dependent)
    "TR",  # Turkey (context-dependent)
    "IR",  # Iran (context-dependent)
    "PK",  # Pakistan (context-dependent)
    "BD",  # Bangladesh (context-dependent)
    "NP",  # Nepal (context-dependent)
    "AF",  # Afghanistan (context-dependent)
    "SO",  # Somalia (context-dependent)
    "YE"   # Yemen (context-dependent)
]
```

#### High-Risk Providers
```python
HIGH_RISK_PROVIDER = [
    "Cloudflare",
    "OVH",
    "DigitalOcean",
    "Linode",
    "Vultr",
    "Hetzner",
]
```

**Note**: These lists are context-dependent and should be customized based on your specific security requirements. Consider the legitimate use cases for each country/provider before flagging them as high-risk.

## 🎯 Usage

### Command-Line Tool

#### Basic Usage

Check a single IP address:
```bash
python main.py --ip 192.168.1.1
```

Check multiple IP addresses:
```bash
python main.py --ip 192.168.1.1 10.0.0.1 8.8.8.8
```

Check IPs from a file:
```bash
python main.py --list ips.txt
```

#### Advanced Usage

Save results to a file:
```bash
python main.py --ip 8.8.8.8 --output-file report.txt --output-format text
```

JSON output for programmatic use:
```bash
python main.py --ip 1.1.1.1 --output-file report.json --output-format json
```

Custom thresholds:
```bash
python main.py --ip 10.0.0.1 192.168.1.100 --max-age 60 --max-score 50 --max-user 5 --safe-ratio 0.8
```

Summary-only output for multiple IPs:
```bash
python main.py --list suspicious_ips.txt --summary-only --output-file summary.txt
```

#### Command-Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--ip` | `-i` | One or more IP addresses to check (space-separated) | - |
| `--list` | `-l` | Path to file containing IP addresses (one per line) | - |
| `--max-age` | `-a` | Maximum age in days for threat data | 30 |
| `--max-user` | `-u` | Minimum number of distinct users who reported the IP | 3 |
| `--max-score` | `-s` | Confidence percentage threshold for AbuseIPDB | 30 |
| `--safe-ratio` | `-r` | Minimum ratio of platforms that must consider IP safe | 0.75 |
| `--output-file` | `-o` | Path to save the output report | - |
| `--output-format` | `-f` | Output format: `text` or `json` | text |
| `--summary-only` | `-S` | Show only summary report (for multiple IPs) | False |

### Library Usage

#### Basic Library Usage

```python
from ipti import IPTI

# Check a single IP
ipti = IPTI("192.168.1.1")
result = ipti.ipti_check()
print(f"IP {result['ip']} is safe: {result['is_safe']}")
```

#### Batch Processing

```python
from ipti import IPTI

IP_LIST = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]

for ip in IP_LIST:
    ipti = IPTI(ip)
    result = ipti.ipti_check()
    print(f"IP {result['ip']} is safe: {result['is_safe']}")
```

#### Custom Configuration

```python
from ipti import IPTI

# Custom thresholds
ipti = IPTI(
    ip="192.168.1.1",
    max_age_in_days=60,
    score_threshold=50,
    user_threshold=5,
    safe_ratio=0.8
)

result = ipti.ipti_check()
print(result)
```

#### Advanced Result Analysis

```python
from ipti import IPTI

ipti = IPTI("8.8.8.8")
result = ipti.ipti_check()

print(f"IP Address: {result['ip']}")
print(f"Overall Assessment: {'SAFE' if result['is_safe'] else 'MALICIOUS'}")
print(f"Safe Ratio: {result['safe_ratio']:.2f}")
print(f"Platforms Checked: {result['platforms']['platforms_considered']}")

# Check individual platform results
for platform, is_malicious in result['platforms']['malicious_report'].items():
    status = "MALICIOUS" if is_malicious else "SAFE"
    print(f"{platform}: {status}")

# Server information
server_info = result['server_info']
print(f"Country: {server_info['country']}")
print(f"ISP: {server_info['isp']}")
print(f"Risk Level: {server_info['risk_assessment']['overall_risk_level']}")

# Privacy information
privacy = server_info['privacy']
print(f"Proxy: {privacy['proxy']}")
print(f"VPN: {privacy['vpn']}")
print(f"Tor: {privacy['tor']}")
print(f"Relay: {privacy['relay']}")

# Port analysis
ports_data = result['ports']
print(f"Open Ports: {ports_data['ports_count']}")
print(f"Port Risk Level: {ports_data['risk_analysis']['risk_level']}")

# PTR information
ptr_data = result['ptr']
print(f"PTR Record: {ptr_data['ptr']}")
print(f"PTR Risk: {ptr_data['ptr_risk']}")
```

## 🧠 Assessment Logic

The tool uses a comprehensive multi-factor assessment system to determine if an IP is safe or malicious.

### Current Scoring System (Enhanced)
Uses the following weight distribution:

#### 1. Platform Threat Intelligence (50% weight)
Each platform returns a boolean indicating if the IP is considered malicious:
- **AbuseIPDB**: Based on abuse confidence score and user count thresholds
- **VirusTotal**: Based on malicious/suspicious detection counts and reputation score
- **ThreatBook IO**: Based on threat judgments and recency
- **AlienVault OTX**: Based on threat pulse count and recency

#### 2. PTR Record Analysis (15% weight)
Evaluates DNS PTR records for suspicious patterns:
- **Normal/Branded**: 1.0 score (low risk)
- **Cloud Provider (Neutral)**: 0.8 score
- **DNS Timeout/Error**: 0.5-0.6 score (medium risk)
- **Suspicious/Dynamic**: 0.4 score
- **Unusual PTR**: 0.3 score (high risk)
- **No PTR**: 0.2 score (very high risk)

#### 3. Port Analysis (15% weight)
Evaluates open ports and services:
- **Port Risk Scoring**: Each port assessed for risk level
- **Service Categorization**: Web, database, mail, remote access, file services
- **Multiple High-Risk Services**: 
  - 15% penalty for 2+ high-risk services
  - 30% penalty for 4+ high-risk services
- **Database + Web Services**: 20% penalty for exposed databases with web services

#### 4. Server Information Analysis (20% weight)
Combines multiple risk factors:
- **Geographic Risk**: 40% penalty for high-risk countries
- **Provider Risk**: 30% penalty for high-risk hosting providers
- **Privacy/Proxy Detection**: 
  - Proxy: 15% penalty
  - VPN: 10% penalty
  - Tor: 25% penalty
  - Relay: 20% penalty

### Comprehensive Safe Ratio Calculation

**Current System:**
```
comprehensive_safe_ratio = (platform_ratio × 0.5) + (ptr_ratio × 0.15) + (port_ratio × 0.15) + (server_ratio × 0.2)
```

### Final Assessment
- **SAFE**: `comprehensive_safe_ratio ≥ SAFE_RATIO` (default: 0.75)
- **MALICIOUS**: `comprehensive_safe_ratio < SAFE_RATIO`

**Risk Levels:**
- **Low Risk**: score ≥ 0.85
- **Medium Risk**: score ≥ 0.7
- **High Risk**: score ≥ 0.5
- **Very High Risk**: score ≥ 0.3
- **Critical Risk**: score < 0.3

## 📊 Output Formats

### Text Format
Provides colored terminal output with detailed information about each assessment component:

```
=== IP Threat Intelligence Report ===
IP Address: 8.8.8.8
Check Date: 2024-01-15 10:30:00

=== Server Information ===
Country: United States
City: New York
Organization: Cloudflare Inc
ISP: Cloudflare Inc
Privacy Information:
  Proxy: True
  VPN: True
  Tor: False
  Relay: False

=== Risk Assessment ===
Geographic Risk: Low - IP is located in US, which is not flagged as high-risk
Provider Risk: Low - IP is not hosted by any flagged high-risk provider
Overall Risk Level: Low

=== PTR Information ===
PTR Record: dns.google
PTR Risk Assessment: Normal / Branded

=== Port Analysis ===
Total Open Ports: 0
Port Risk Level: Low
Average Risk Score: 0.000

=== Platform Results ===
  AbuseIPDB: ✓ SAFE
  VirusTotal: ✓ SAFE
  Threatbook IO: ✓ SAFE
  Alienvault OTX: ✓ SAFE

=== Risk Breakdown ===
Platform Safe Ratio: 1.00
Server Safe Ratio: 1.00
Port Safe Ratio: 1.00
Comprehensive Safe Ratio: 1.00

=== Overall Assessment ===
✓ IP is considered SAFE
```

### JSON Format
Returns structured JSON data for programmatic use:

```json
{
  "ip": "8.8.8.8",
  "check_date": "2024-01-15 10:30:00",
  "platforms": {
    "malicious_report": {
      "abuseipdb": false,
      "virustotal": false,
      "threatbook": false,
      "alienvault": false
    },
    "max_age_in_days": 30,
    "score_threshold": 30,
    "user_threshold": 3,
    "platforms_considered": 4,
    "platforms_flagged_as_safe": 4,
    "platforms_safe_ratio": 1.0,
    "is_safe": true
  },
  "ports": {
    "ports": [],
    "ports_count": 0,
    "server_safe_ratio": 1.0,
    "port_categories": {},
    "risk_analysis": {
      "risk_level": "Low",
      "reason": "No open ports found"
    }
  },
  "server_info": {
    "country": "US",
    "city": "Mountain View",
    "org": "Google LLC",
    "isp": "Google LLC",
    "server_safe_ratio": 1.0,
    "privacy": {
      "proxy": false,
      "vpn": false,
      "tor": false,
      "relay": false
    },
    "risk_assessment": {
      "geographic": {"risk_level": "Low"},
      "provider": {"risk_level": "Low"},
      "overall_risk_level": "Low"
    }
  },
  "ptr": {
    "ptr": "dns.google",
    "ptr_risk": "Normal / Branded"
  },
  "is_safe": true,
  "safe_ratio": 1.0,
  "risk_breakdown": {
    "platform_safe_ratio": 1.0,
    "server_safe_ratio": 1.0,
    "port_safe_ratio": 1.0,
    "comprehensive_safe_ratio": 1.0
  }
}
```

## 🔧 API Requirements

### Rate Limits
Each API service has different rate limits:
- **AbuseIPDB**: 1000 requests/day (free tier)
- **VirusTotal**: 4 requests/minute (free tier)
- **ThreatBook IO**: Varies by plan
- **AlienVault OTX**: 100 requests/minute (free tier)
- **IPInfo**: 50,000 requests/month (free tier)
- **Shodan**: 1 request/second (free tier)

### Error Handling
The tool includes comprehensive error handling:
- **API Rate Limits**: Graceful handling with informative error messages
- **Network Issues**: Timeout handling and retry logic
- **Missing API Keys**: Clear error messages with setup instructions
- **Invalid IPs**: Validation and error reporting
- **Partial Failures**: Continues processing other IPs if one fails

## ⚡ Performance & Caching

### Port Data Caching
The tool includes an intelligent caching system for port data:
- **Cache TTL**: 1 hour (configurable)
- **Memory-based**: Fast access for repeated queries
- **Automatic cleanup**: Expired entries are automatically removed
- **Cache statistics**: Monitor cache performance

### Performance Optimizations
- **Parallel processing**: Multiple API calls where possible
- **Connection pooling**: Efficient HTTP connection reuse
- **Timeout handling**: Prevents hanging requests
- **Error recovery**: Graceful degradation on API failures

## 📝 Input File Format

When using the `--list` option, provide a text file with one IP address per line:

```
192.168.1.1
10.0.0.1
8.8.8.8
1.1.1.1
```

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and security research purposes. Always ensure you have proper authorization before scanning IP addresses that you don't own or control. The authors are not responsible for any misuse of this tool.

### Legal Considerations
- **Authorized Use Only**: Only scan IP addresses you own or have explicit permission to test
- **Rate Limiting**: Respect API rate limits to avoid service disruption
- **Data Privacy**: Be mindful of privacy implications when analyzing IP data
- **Compliance**: Ensure compliance with local laws and regulations

## 🔗 Related Projects

- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [VirusTotal API](https://developers.virustotal.com/)
- [ThreatBook IO API](https://developers.threatbook.io/)
- [AlienVault OTX API](https://otx.alienvault.com/api/)
- [IPInfo API](https://ipinfo.io/developers)
- [Shodan API](https://developer.shodan.io/)

## 📞 Support

If you encounter any issues or have questions:
1. Check the [Issues](https://github.com/bayufedra/ipti/issues) page
2. Review the configuration and API key setup
3. Ensure all dependencies are properly installed
4. Check API rate limits and service status

## 📞 Contact

### Get in Touch
Have questions, suggestions, or need help? I'd love to hear from you!

### Connect With Me
<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/bayufedra)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://x.com/bayufedraa)
[![Instagram](https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/bayufedraa)
[![Email](https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:bayufedra@gmail.com)

</div>

### Support Options
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/bayufedra/ipti/issues)
- **💡 Feature Requests**: [GitHub Discussions](https://github.com/bayufedra/ipti/discussions)
- **📖 Documentation**: Check the sections above for detailed usage

---

<div align="center">

**Made with ❤️ for the security community**

*Empowering security professionals with powerful IP threat intelligence tools*

</div> 
