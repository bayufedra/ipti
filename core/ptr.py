import socket
import re


def _is_unusual_ptr(ptr: str) -> bool:
    # No dots at all (very unusual for legitimate PTR)
    if "." not in ptr:
        return True
    
    # Contains only numbers and dots (unusual)
    if re.match(r'^[\d.]+$', ptr):
        return True
    
    # Very short PTR (less than 5 characters)
    if len(ptr) < 5:
        return True
    
    # Contains suspicious patterns
    suspicious_patterns = [
        r'^[0-9]+$',  # Only numbers
        r'^[a-f0-9]+$',  # Only hex characters
        r'^[a-z0-9]{1,3}$',  # Very short alphanumeric
    ]
    
    for pattern in suspicious_patterns:
        if re.match(pattern, ptr.lower()):
            return True
    
    return False

def check_ptr_risk(ip: str, timeout: int = 5) -> dict:
    try:
        # Set socket timeout for DNS lookup
        socket.setdefaulttimeout(timeout)
        ptr = socket.gethostbyaddr(ip)[0]
    except socket.timeout:
        return {"ptr": None, "ptr_risk": "DNS Timeout (Medium Risk)"}
    except socket.herror:
        return {"ptr": None, "ptr_risk": "No PTR (High Risk)"}
    except Exception:
        return {"ptr": None, "ptr_risk": "DNS Error (Medium Risk)"}

    # Lowercase for case-insensitive matching
    ptr_lower = ptr.lower()

    # Keywords indicating dynamic/residential IPs (higher risk)
    risky_keywords = [
        "dynamic", "dhcp", "dialup", "pool", "unknown", "cust", "rev", "nat", 
        "pppoe", "adsl", "cable", "dsl", "residential", "home", "isp"
    ]
    
    # Keywords indicating cloud providers (neutral risk)
    cloud_keywords = [
        "amazonaws", "aws", "googleusercontent", "google", "azure", "microsoft",
        "linode", "ovh", "digitalocean", "do", "cloudflare", "heroku", 
        "rackspace", "vultr", "gcp", "ec2", "compute", "cloud"
    ]

    # Check for risky patterns
    if any(k in ptr_lower for k in risky_keywords):
        return {"ptr": ptr, "ptr_risk": "Suspicious / Dynamic"}
    
    # Check for cloud providers
    elif any(k in ptr_lower for k in cloud_keywords):
        return {"ptr": ptr, "ptr_risk": "Cloud Provider (Neutral)"}
    
    # Check for unusual PTR patterns (more sophisticated than just "no dots")
    elif _is_unusual_ptr(ptr):
        return {"ptr": ptr, "ptr_risk": "Unusual PTR (Possibly Fake)"}
    
    else:
        return {"ptr": ptr, "ptr_risk": "Normal / Branded"}

