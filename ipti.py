#### EXTERNAL LIBRARIES ####
import requests
from datetime import datetime, timezone

#### LOCAL LIBRARIES ####
import config as cfg
from core.platforms import TrustedPlatforms
from core.portinfo import check_ports
from core.ipinfo import check_server_info
from core.ptr import check_ptr_risk
from core.scoring import score_ip

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
        # Create platform configuration for scoring
        platform_config = {
            "max_age_in_days": self.max_age_in_days,
            "score_threshold": self.score_threshold,
            "user_threshold": self.user_threshold,
            "safe_ratio": self.safe_ratio
        }
        
        # Use the scoring system to get comprehensive results
        scoring_result = score_ip(self.ip, self.api_keys, platform_config)
        
        # Extract individual results from score breakdown
        score_breakdown = scoring_result.get("score_breakdown", {})
        platforms_details = score_breakdown.get("platforms", {}).get("details", {})
        ptr_details = score_breakdown.get("ptr", {}).get("details", {})
        ports_details = score_breakdown.get("ports", {}).get("details", {})
        ipinfo_details = score_breakdown.get("ipinfo", {}).get("details", {})
        
        # Determine overall safety based on the scoring result
        is_safe = scoring_result.get("overall_safe_score", 0.0) >= self.safe_ratio
        
        return {
            "ip": self.ip,
            "check_date": self.now.strftime("%Y-%m-%d %H:%M:%S"),
            "is_safe": is_safe,
            "safe_ratio": scoring_result.get("overall_safe_score", 0.0),
            "platforms": platforms_details,
            "ptr": ptr_details,
            "ports": ports_details,
            "server_info": ipinfo_details,
            "risk_breakdown": {
                "platform_safe_ratio": score_breakdown.get("platforms", {}).get("score", 0.0),
                "ptr_safe_ratio": score_breakdown.get("ptr", {}).get("score", 0.0),
                "port_safe_ratio": score_breakdown.get("ports", {}).get("score", 0.0),
                "server_safe_ratio": score_breakdown.get("ipinfo", {}).get("score", 0.0)
            }
        }
