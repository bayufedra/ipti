# Core package for IP Threat Intelligence

"""
IP Threat Intelligence Core Package

This package provides comprehensive IP threat intelligence analysis including:
- IP geolocation and server information analysis
- Port scanning and service analysis
- PTR (reverse DNS) record analysis
- Integration with threat intelligence platforms
- Overall IP scoring and risk assessment
"""

# Main scoring functionality
from .scoring import IPScoring, score_ip

# Individual analysis modules
from .ipinfo import check_server_info, get_ipinfo, assess_geographic_risk, assess_provider_risk
from .portinfo import check_ports, get_ports, categorize_ports, assess_port_risk
from .ptr import check_ptr_risk
from .platforms import TrustedPlatforms

# Version information
__version__ = "1.0.0"

# Package metadata
__author__ = "IP Threat Intelligence Team"
__description__ = "Core package for IP threat intelligence analysis"

# Main exports for easy access
__all__ = [
    # Main scoring classes and functions
    "IPScoring",
    "score_ip",
    
    # IP information analysis
    "check_server_info",
    "get_ipinfo", 
    "assess_geographic_risk",
    "assess_provider_risk",
    
    # Port analysis
    "check_ports",
    "get_ports",
    "categorize_ports", 
    "assess_port_risk",
    
    # PTR analysis
    "check_ptr_risk",
    
    # Platform integration
    "TrustedPlatforms",
]