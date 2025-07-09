## IPTI Configuration Defaults Values ##

#### API KEYS ####
import os
from dotenv import load_dotenv
load_dotenv()

API_KEYS = {
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
    "threatbook": os.getenv("THREATBOOK_API_KEY"),
    "alienvault": os.getenv("ALIENVAULT_API_KEY"),
    "ipinfo": os.getenv("IPINFO_API_KEY"),
    "shodan": os.getenv("SHODAN_API_KEY")
}

#### MINIMUM SAFE RATIO ####
SAFE_RATIO = 0.75       # range 0.00 - 1.00 (recommended 0.75)

#### TRUSTED PLATFORMS CONFIGURATION ####
MAX_AGE_IN_DAYS = 30    # range 0 - 100 (recommended 30)
SCORE_THRESHOLD = 30    # range 0 - 100 (recommended 30)
USER_THRESHOLD = 3      # range 0 - 10 (recommended 3)


#### HIGH RISK INFORMATION ####
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

HIGH_RISK_PROVIDER = [
    "Cloudflare",
    "OVH",
    "DigitalOcean",
    "Linode",
    "Vultr",
    "Hetzner",
]
