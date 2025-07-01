# IP Threat Intelligence Tool (IPTI)

A comprehensive Python tool for checking IP addresses against multiple threat intelligence platforms to determine if they are malicious or safe. This tool can be used both as a command-line utility and as a Python library.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Command-Line Tool Usage](#1-command-line-tool-usage)
  - [Library Usage](#2-library-usage)
- [Input File Format](#input-file-format)
- [Output Formats](#output-formats)
- [How It Works](#how-it-works)
- [IP Assessment Logic & Decision Process](#ip-assessment-logic--decision-process)
- [Dependencies](#dependencies)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features

- **Multi-Platform Threat Intelligence**: Checks IP addresses against 4 major threat intelligence platforms:
  - AbuseIPDB
  - VirusTotal
  - ThreatBook IO
  - AlienVault OTX

- **Dual Usage Modes**:
  - **Command-line tool** for batch processing and automation
  - **Python library** for integration into your own applications

- **Flexible Input Methods**: 
  - Check individual IP addresses via command line
  - Process multiple IPs from a text file
  - Batch processing capabilities

- **Configurable Thresholds**:
  - Maximum age for threat data
  - Score thresholds for different platforms
  - User count thresholds
  - Safe ratio threshold for overall assessment

- **Multiple Output Formats**:
  - Colored terminal output with detailed reports
  - JSON format for programmatic use
  - Text file output
  - Summary reports for multiple IPs

## Installation

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

## Configuration

### API Keys Setup

Create a `.env` file in the project root with your API keys:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
THREATBOOK_API_KEY=your_threatbook_api_key_here
ALIENVAULT_API_KEY=your_alienvault_api_key_here
```

### Getting API Keys

- **AbuseIPDB**: Sign up at [abuseipdb.com](https://www.abuseipdb.com/) and get your API key
- **VirusTotal**: Sign up at [virustotal.com](https://www.virustotal.com/) and get your API key
- **ThreatBook IO**: Sign up at [threatbook.io](https://www.threatbook.io/) and get your API key
- **AlienVault OTX**: Sign up at [otx.alienvault.com](https://otx.alienvault.com/) and get your API key

## Usage

### 1. Command-Line Tool Usage

#### Basic Usage

Check a single IP address:
```bash
python main.py --ip 192.168.1.1
```

Check multiple IP addresses:
```bash
python main.py --ip 192.168.1.1 10.0.0.1 8.8.8.8
```

#### Advanced Usage

Check IPs from a file:
```bash
python main.py --list ips.txt
```

Save results to a file:
```bash
python main.py --ip 8.8.8.8 --output-file report.txt --output-format text
```

JSON output:
```bash
python main.py --ip 1.1.1.1 --output-file report.json --output-format json
```

#### Configuration Options

- `--max-age, -a`: Maximum age in days for threat data (default: 30)
- `--max-user, -u`: Maximum number of users threshold (default: 3)
- `--max-score, -s`: Maximum score threshold (default: 30)
- `--safe-ratio, -r`: Safe ratio threshold (default: 0.75)
- `--summary-only, -S`: Show only summary report (for multiple IPs)

#### Examples

```bash
# Check with custom thresholds
python main.py --ip 10.0.0.1 192.168.1.100 --max-age 60 --max-score 50 --max-user 5 --safe-ratio 0.8

# Process file with summary only
python main.py --list suspicious_ips.txt --summary-only --output-file summary.txt

# JSON output for integration
python main.py --ip 8.8.8.8 1.1.1.1 --output-format json --output-file results.json
```

### 2. Library Usage

You can also use IPTI as a Python library in your own applications:

#### Basic Library Usage

```python
from ipti import IPTI

# Check a single IP
ipti = IPTI("192.168.1.1")
result = ipti.is_malicious()
print(f"IP {result['ip']} is safe: {result['is_safe']}")
```

#### Batch Processing with Library

```python
from ipti import IPTI

IP_LIST = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]

for ip in IP_LIST:
    ipti = IPTI(ip)
    result = ipti.is_malicious()
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

result = ipti.is_malicious()
print(result)
```

#### Detailed Result Analysis

```python
from ipti import IPTI

ipti = IPTI("8.8.8.8")
result = ipti.is_malicious()

print(f"IP Address: {result['ip']}")
print(f"Overall Assessment: {'SAFE' if result['is_safe'] else 'MALICIOUS'}")
print(f"Safe Ratio: {result['safe_ratio']:.2f}")
print(f"Platforms Checked: {result['platforms_considered']}")

# Check individual platform results
for platform, is_malicious in result['malicious_report'].items():
    status = "MALICIOUS" if is_malicious else "SAFE"
    print(f"{platform}: {status}")
```

## Input File Format

When using the `--list` option, provide a text file with one IP address per line:

```
192.168.1.1
10.0.0.1
8.8.8.8
1.1.1.1
```

## Output Formats

### Text Format
The tool provides colored terminal output with detailed information about each platform's assessment and an overall verdict.

### JSON Format
Returns structured JSON data with all assessment details for programmatic use:

```json
{
  "ip": "8.8.8.8",
  "max_age_in_days": 30,
  "score_threshold": 30,
  "user_threshold": 3,
  "check_date": "2024-01-15 10:30:00",
  "malicious_report": {
    "abuseipdb": false,
    "virustotal": false,
    "threatbook": false,
    "alienvault": false
  },
  "is_safe": true,
  "safe_ratio": 1.0,
  "platforms_considered": 4,
  "platforms_flagged_as_safe": 4
}
```
## How It Works

1. **Platform Checks**: The tool queries each threat intelligence platform's API
2. **Threshold Evaluation**: Compares results against configurable thresholds
3. **Safe Ratio Calculation**: Determines overall safety based on the ratio of platforms that flag the IP as safe
4. **Final Assessment**: Provides a comprehensive verdict based on all available data

## IP Assessment Logic & Decision Process

The core logic for determining if an IP is safe or malicious is implemented in the `is_malicious` method of the `IPTI` class. Here is how it works:

### Step-by-Step Logic

1. **Platform Results**: Each platform (AbuseIPDB, VirusTotal, ThreatBook IO, AlienVault OTX) is queried. Each returns a boolean:
   - `True` if the platform considers the IP **malicious** (based on its own thresholds and logic)
   - `False` if the platform considers the IP **safe**

2. **Result Aggregation**:
   - The results are collected in a dictionary, e.g.:
     ```python
     {
       "abuseipdb": False,
       "virustotal": True,
       "threatbook": False,
       "alienvault": False
     }
     ```

3. **Safe Ratio Calculation**:
   - The **safe ratio** is calculated as:
     
     ```
     safe_ratio = (Number of platforms that flagged as SAFE) / (Total number of platforms considered)
     ```
   - In code:
     ```python
     platforms_considered = len(result)
     platforms_flagged_as_safe = result.count(False)
     safe_ratio = platforms_flagged_as_safe / platforms_considered
     ```

4. **Final Verdict**:
   - The IP is considered **safe** if:
     ```
     safe_ratio ≥ SAFE_RATIO (default: 0.75)
     ```
   - Otherwise, the IP is considered **malicious**.
   - In code:
     ```python
     is_safe = safe_ratio >= self.safe_ratio
     ```

### Example

If 3 out of 4 platforms flag the IP as safe:
- `platforms_flagged_as_safe = 3`
- `platforms_considered = 4`
- `safe_ratio = 3 / 4 = 0.75`
- If `SAFE_RATIO` is 0.75 (default), the IP is considered **safe**.

### Returned Data Structure

The `is_malicious` function returns a dictionary with the following keys:
- `ip`: The IP address checked
- `max_age_in_days`, `score_threshold`, `user_threshold`: The thresholds used
- `check_date`: When the check was performed
- `malicious_report`: Dictionary of platform results
- `is_safe`: Final verdict (True = safe, False = malicious)
- `safe_ratio`: The calculated safe ratio
- `platforms_considered`: Number of platforms checked
- `platforms_flagged_as_safe`: Number of platforms that flagged as safe

This logic ensures a robust, threshold-based, and explainable assessment for each IP address.

## Dependencies

- `requests`: HTTP library for API calls
- `colorama`: Cross-platform colored terminal output
- `python-dotenv`: Environment variable management
- `certifi`: SSL certificate verification
- `charset-normalizer`: Character encoding detection
- `idna`: Internationalized domain names
- `urllib3`: HTTP client

## License

This repository is licensed under the GPL-3.0 license. See the [LICENSE](LICENSE) file for more information.

## Disclaimer

This tool is for educational and security research purposes. Always ensure you have proper authorization before scanning IP addresses that you don't own or control. 
