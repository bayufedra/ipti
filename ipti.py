#### EXTERNAL LIBRARIES ####
import requests
from datetime import datetime, timezone

#### LOCAL LIBRARIES ####
import config as cfg
from core.platforms import TrustedPlatforms
from core.portinfo import check_ports
from core.ipinfo import check_server_info
from core.ptr import check_ptr_risk

#### CONSTANTS ####
API_KEYS = cfg.API_KEYS
MAX_AGE_IN_DAYS = cfg.MAX_AGE_IN_DAYS
SCORE_THRESHOLD = cfg.SCORE_THRESHOLD
USER_THRESHOLD = cfg.USER_THRESHOLD
SAFE_RATIO = cfg.SAFE_RATIO

#### IPTI CLASS ####
class IPTI:
    # Initialize the IPTI class
    def __init__(self, ip: str, max_age_in_days: int=MAX_AGE_IN_DAYS, score_threshold: int=SCORE_THRESHOLD, user_threshold: int=USER_THRESHOLD, safe_ratio: float=SAFE_RATIO):
        self.ip = ip
        self.score_threshold = score_threshold
        self.user_threshold = user_threshold
        self.max_age_in_days = max_age_in_days
        self.now = datetime.now(timezone.utc)
        self.safe_ratio = safe_ratio
        self.api_keys = API_KEYS
        
        # Check for missing API keys
        missing_keys = [platform for platform, key in self.api_keys.items() if not key]
        if missing_keys:
            raise Exception(f"Missing API keys for: {', '.join(missing_keys)}. Please check your .env file.")
        
        # Initialize the platform checker
        self.platform_checker = TrustedPlatforms(
            ip=self.ip,
            api_keys=self.api_keys,
            max_age_in_days=self.max_age_in_days,
            score_threshold=self.score_threshold,
            user_threshold=self.user_threshold,
            safe_ratio=self.safe_ratio
        )

    # Check if the IP address is malicious
    def ipti_check(self) -> dict:
        platforms_data = self.platform_checker.check_platforms()
        ports_data = check_ports(self.ip)
        server_info_data = check_server_info(self.ip)
        ptr_data = check_ptr_risk(self.ip)

        # Calculate comprehensive safe ratio including server factors
        platform_safe_ratio = platforms_data["platforms_safe_ratio"]
        server_safe_ratio = server_info_data["server_safe_ratio"]
        port_safe_ratio = ports_data["server_safe_ratio"]
        
        # Weighted average: 60% platforms, 25% server info, 15% ports
        comprehensive_safe_ratio = (
            platform_safe_ratio * 0.6 +
            server_safe_ratio * 0.25 +
            port_safe_ratio * 0.15
        )
        
        # Determine overall safety based on comprehensive ratio
        is_safe = comprehensive_safe_ratio >= self.safe_ratio

        return {
            "ip": self.ip,
            "check_date": self.now.strftime("%Y-%m-%d %H:%M:%S"),
            "platforms": platforms_data,
            "ports": ports_data,
            "server_info": server_info_data,
            "ptr": ptr_data,
            "safe_ratio": comprehensive_safe_ratio,
            "is_safe": is_safe,
            "risk_breakdown": {
                "platform_safe_ratio": platform_safe_ratio,
                "server_safe_ratio": server_safe_ratio,
                "port_safe_ratio": port_safe_ratio,
                "comprehensive_safe_ratio": comprehensive_safe_ratio
            }
        }
