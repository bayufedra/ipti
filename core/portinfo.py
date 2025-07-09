import requests
import logging
import time
from typing import Dict, List, Optional, Tuple
from config import API_KEYS

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_port_cache = {}
_cache_ttl = 3600

HIGH_RISK_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

MEDIUM_RISK_PORTS = {
    135: "RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

# Service categorization
WEB_SERVICES = {80, 443, 8080, 8443, 3000, 5000, 8000, 9000}
DATABASE_SERVICES = {1433, 1521, 3306, 5432, 27017, 6379, 9200}
MAIL_SERVICES = {25, 110, 143, 465, 587, 993, 995}
REMOTE_ACCESS = {22, 23, 3389, 5900, 5901, 5902}
FILE_SERVICES = {21, 135, 139, 445, 2049}

def _get_cached_ports(ip: str) -> Optional[List[int]]:
    """Get ports from cache if available and not expired."""
    if ip in _port_cache:
        cached_data = _port_cache[ip]
        if time.time() - cached_data["timestamp"] < _cache_ttl:
            logger.info(f"Using cached port data for IP: {ip}")
            return cached_data["ports"]
        else:
            # Remove expired cache entry
            del _port_cache[ip]
    return None

def _cache_ports(ip: str, ports: List[int]) -> None:
    """Cache port data with timestamp."""
    _port_cache[ip] = {
        "ports": ports,
        "timestamp": time.time()
    }
    logger.info(f"Cached port data for IP: {ip}")

def get_ports(ip: str) -> List[int]:

    # Check cache first
    cached_ports = _get_cached_ports(ip)
    if cached_ports is not None:
        return cached_ports
    
    api_key = API_KEYS["shodan"]
    if not api_key:
        raise Exception("Missing Shodan API key. Please set SHODAN_API_KEY in your .env file.")

    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    
    try:
        logger.info(f"Fetching port information for IP: {ip}")
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            ports = data.get("ports", [])
            logger.info(f"Found {len(ports)} open ports for IP: {ip}")
            
            # Cache the results
            _cache_ports(ip, ports)
            return ports
        elif response.status_code == 404:
            logger.info(f"No data found for IP: {ip}")
            # Cache empty result to avoid repeated API calls
            _cache_ports(ip, [])
            return []
        else:
            error_msg = f"Shodan API error: {response.status_code} - {response.text}"
            logger.error(error_msg)
            raise Exception(error_msg)
            
    except requests.exceptions.Timeout:
        error_msg = f"Timeout while fetching port data for IP: {ip}"
        logger.error(error_msg)
        raise Exception(error_msg)
    except requests.exceptions.RequestException as e:
        error_msg = f"Network error while fetching port data for IP {ip}: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

def categorize_ports(ports: List[int]) -> Dict[str, List[int]]:

    categories = {
        "web_services": [],
        "database_services": [],
        "mail_services": [],
        "remote_access": [],
        "file_services": [],
        "other_services": []
    }
    
    for port in ports:
        if port in WEB_SERVICES:
            categories["web_services"].append(port)
        elif port in DATABASE_SERVICES:
            categories["database_services"].append(port)
        elif port in MAIL_SERVICES:
            categories["mail_services"].append(port)
        elif port in REMOTE_ACCESS:
            categories["remote_access"].append(port)
        elif port in FILE_SERVICES:
            categories["file_services"].append(port)
        else:
            categories["other_services"].append(port)
    
    return categories

def assess_port_risk(port: int) -> Tuple[float, str]:

    if port in HIGH_RISK_PORTS:
        service_name = HIGH_RISK_PORTS[port]
        if port in {22, 3389, 5900}:  # Remote access services
            return 0.8, f"High-risk remote access service ({service_name})"
        elif port in {21, 23}:  # Unencrypted services
            return 0.9, f"Unencrypted service ({service_name})"
        elif port in {80, 8080}:  # HTTP services
            return 0.6, f"Unencrypted web service ({service_name})"
        else:
            return 0.7, f"High-risk service ({service_name})"
    elif port in MEDIUM_RISK_PORTS:
        service_name = MEDIUM_RISK_PORTS[port]
        return 0.5, f"Medium-risk service ({service_name})"
    elif port < 1024:  # Well-known ports
        return 0.4, "Well-known port"
    elif 1024 <= port <= 49151:  # Registered ports
        return 0.3, "Registered port"
    else:  # Dynamic/private ports
        return 0.2, "Dynamic/private port"

def calculate_ports_safe_ratio(ports: List[int]) -> Tuple[float, Dict]:

    if not ports:
        # No open ports - classify as low risk (high score)
        return 0.9, {"reason": "No open ports found - low risk"}
    
    total_risk = 0.0
    port_analysis = []
    
    for port in ports:
        risk_score, risk_reason = assess_port_risk(port)
        total_risk += risk_score
        port_analysis.append({
            "port": port,
            "risk_score": risk_score,
            "risk_reason": risk_reason,
            "service_name": HIGH_RISK_PORTS.get(port, MEDIUM_RISK_PORTS.get(port, "Unknown"))
        })
    
    # Calculate average risk and convert to safe ratio
    avg_risk = total_risk / len(ports)
    safe_ratio = max(0.0, 1.0 - avg_risk)
    
    # Additional penalties for multiple high-risk services
    high_risk_count = len([p for p in ports if p in HIGH_RISK_PORTS])
    if high_risk_count > 3:
        safe_ratio *= 0.7  # 30% penalty for many high-risk services (increased from 0.8)
    elif high_risk_count > 1:
        safe_ratio *= 0.85  # 15% penalty for multiple high-risk services
    
    # Penalty for having both web and database services exposed
    categories = categorize_ports(ports)
    if categories["web_services"] and categories["database_services"]:
        safe_ratio *= 0.8  # 20% penalty for exposed database with web services (increased from 0.9)
    
    # Additional penalty for suspicious port combinations
    if len(ports) > 10:
        safe_ratio *= 0.9  # 10% penalty for too many open ports
    
    # Penalty for common malicious port patterns
    suspicious_patterns = [
        {22, 80, 443},  # Common web server pattern
        {22, 3389},     # Remote access combination
        {21, 22, 23},   # Multiple unencrypted services
    ]
    
    for pattern in suspicious_patterns:
        if pattern.issubset(set(ports)):
            safe_ratio *= 0.85  # 15% penalty for suspicious port patterns
            break
    
    return max(0.0, safe_ratio), {
        "port_analysis": port_analysis,
        "categories": categories,
        "high_risk_count": high_risk_count,
        "avg_risk": avg_risk
    }

def check_ports(ip: str) -> Dict:

    try:
        ports = get_ports(ip)
        ports_count = len(ports)
        
        if ports_count == 0:
            return {
                "ports": [],
                "ports_count": 0,
                "server_safe_ratio": 0.9,  # Low risk when no ports found
                "port_categories": {},
                "risk_analysis": {
                    "reason": "No open ports found - low risk",
                    "risk_level": "Low"
                }
            }
        
        # Calculate safe ratio and detailed analysis
        server_safe_ratio, detailed_analysis = calculate_ports_safe_ratio(ports)
        
        # Determine overall risk level
        if server_safe_ratio >= 0.85:
            risk_level = "Low"
        elif server_safe_ratio >= 0.7:
            risk_level = "Medium"
        elif server_safe_ratio >= 0.5:
            risk_level = "High"
        else:
            risk_level = "Critical"
        
        return {
            "ports": ports,
            "ports_count": ports_count,
            "server_safe_ratio": server_safe_ratio,
            "port_categories": detailed_analysis["categories"],
            "risk_analysis": {
                "risk_level": risk_level,
                "high_risk_services": detailed_analysis["high_risk_count"],
                "average_risk": detailed_analysis["avg_risk"],
                "port_details": detailed_analysis["port_analysis"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error analyzing ports for IP {ip}: {str(e)}")
        # Return conservative estimate on error
        return {
            "ports": [],
            "ports_count": 0,
            "server_safe_ratio": 0.5,  # Conservative estimate
            "port_categories": {},
            "risk_analysis": {
                "risk_level": "Unknown",
                "error": str(e)
            }
        }