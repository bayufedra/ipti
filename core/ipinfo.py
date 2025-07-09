import requests
from config import API_KEYS, HIGH_RISK_COUNTRY, HIGH_RISK_PROVIDER

def get_ipinfo(ip: str) -> dict:
    api_key = API_KEYS["ipinfo"]
    if not api_key:
        raise Exception("Missing IPInfo API key. Please set IPINFO_API_KEY in your .env file.")

    url = f"https://ipinfo.io/{ip}/json?token={api_key}"
    response = requests.get(url)
    return response.json()

def assess_geographic_risk(country: str) -> dict:
    """Assess risk based on country location"""
    if country in HIGH_RISK_COUNTRY:
        return {
            "is_high_risk": True,
            "risk_level": "High",
            "reason": f"IP is located in {country}, which is flagged as high-risk"
        }
    else:
        return {
            "is_high_risk": False,
            "risk_level": "Low",
            "reason": f"IP is located in {country}, which is not flagged as high-risk"
        }

def assess_provider_risk(org: str, isp: str) -> dict:
    """Assess risk based on hosting provider"""
    # Check both org and isp fields for provider names
    org_lower = org.lower() if org else ""
    isp_lower = isp.lower() if isp else ""
    
    for provider in HIGH_RISK_PROVIDER:
        provider_lower = provider.lower()
        if provider_lower in org_lower or provider_lower in isp_lower:
            return {
                "is_high_risk": True,
                "risk_level": "Medium",
                "reason": f"IP is hosted by {provider}, which is flagged as high-risk provider"
            }
    
    return {
        "is_high_risk": False,
        "risk_level": "Low",
        "reason": "IP is not hosted by any flagged high-risk provider"
    }

def calculate_server_safe_ratio(geographic_risk: dict, provider_risk: dict, privacy: dict) -> float:
    """Calculate server safe ratio based on various risk factors"""
    base_ratio = 1.0
    
    # Geographic risk penalty
    if geographic_risk["is_high_risk"]:
        base_ratio -= 0.4  # 40% penalty for high-risk country (increased from 0.3)
    
    # Provider risk penalty
    if provider_risk["is_high_risk"]:
        base_ratio -= 0.3  # 30% penalty for high-risk provider (increased from 0.2)
    
    # Privacy/proxy risk penalties
    if privacy.get("proxy", False):
        base_ratio -= 0.15  # 15% penalty for proxy
    if privacy.get("vpn", False):
        base_ratio -= 0.1   # 10% penalty for VPN
    if privacy.get("tor", False):
        base_ratio -= 0.25  # 25% penalty for Tor
    if privacy.get("relay", False):
        base_ratio -= 0.2   # 20% penalty for relay
    

    return max(0.0, base_ratio)

def check_server_info(ip: str) -> dict:
    ipinfo = get_ipinfo(ip)
    
    # Assess risks
    geographic_risk = assess_geographic_risk(ipinfo.get("country", "Unknown"))
    provider_risk = assess_provider_risk(ipinfo.get("org", ""), ipinfo.get("isp", ""))
    
    # Calculate safe ratio
    server_safe_ratio = calculate_server_safe_ratio(
        geographic_risk, 
        provider_risk, 
        ipinfo.get("privacy", {})
    )
    
    return {
        "asn": ipinfo.get("asn", "Unknown"),
        "isp": ipinfo.get("isp", "Unknown"),
        "country": ipinfo.get("country", "Unknown"),
        "city": ipinfo.get("city", "Unknown"),
        "org": ipinfo.get("org", "Unknown"),
        "provider": ipinfo.get("provider", "Unknown"),
        "privacy": {
            "proxy": ipinfo.get("proxy", False),
            "vpn": ipinfo.get("vpn", False),
            "tor": ipinfo.get("tor", False),
            "relay": ipinfo.get("relay", False),
        },
        "risk_assessment": {
            "geographic": geographic_risk,
            "provider": provider_risk,
            "overall_risk_level": "High" if (geographic_risk["is_high_risk"] or provider_risk["is_high_risk"]) else "Low"
        },
        "server_safe_ratio": server_safe_ratio
    }