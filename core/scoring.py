from typing import Dict, Any, Optional
from .platforms import TrustedPlatforms
from .ptr import check_ptr_risk
from .portinfo import check_ports
from .ipinfo import check_server_info


class IPScoring:
    
    def __init__(self, ip: str, api_keys: Dict[str, str], platform_config: Dict[str, Any]):
        self.ip = ip
        self.api_keys = api_keys
        self.platform_config = platform_config
        
        # Scoring weights (must sum to 1.0)
        self.weights = {
            "platforms": 0.5,  # 50% weight (reduced from 0.4)
            "ptr": 0.15,       # 15% weight (increased from 0.1)
            "ports": 0.15,      # 20% weight (unchanged)
            "ipinfo": 0.2     # 15% weight (reduced from 0.3)
        }
    
    def _calculate_ptr_score(self, ptr_result: Dict[str, Any]) -> float:
        ptr_risk = ptr_result.get("ptr_risk", "Unknown")
        
        # Score mapping based on risk levels
        risk_scores = {
            "Normal / Branded": 1.0,
            "Cloud Provider (Neutral)": 0.8,
            "DNS Timeout (Medium Risk)": 0.6,
            "Suspicious / Dynamic": 0.4,
            "Unusual PTR (Possibly Fake)": 0.3,
            "No PTR (High Risk)": 0.2,
            "DNS Error (Medium Risk)": 0.5,
            "Unknown": 0.5  # Default for unknown cases
        }
        
        return risk_scores.get(ptr_risk, 0.5)
    
    def _calculate_platforms_score(self, platforms_result: Dict[str, Any]) -> float:
        return platforms_result.get("platforms_safe_ratio", 0.0)
    
    def _calculate_ports_score(self, ports_result: Dict[str, Any]) -> float:
        # Use the server_safe_ratio directly as it's already normalized
        return ports_result.get("server_safe_ratio", 0.0)
    
    def _calculate_ipinfo_score(self, ipinfo_result: Dict[str, Any]) -> float:
        # Use the server_safe_ratio directly as it's already normalized
        return ipinfo_result.get("server_safe_ratio", 0.0)
    
    def calculate_overall_score(self) -> Dict[str, Any]:
        try:
            # Perform all assessments
            platforms = TrustedPlatforms(
                self.ip, 
                self.api_keys, 
                self.platform_config["max_age_in_days"],
                self.platform_config["score_threshold"],
                self.platform_config["user_threshold"],
                self.platform_config["safe_ratio"]
            )
            platforms_result = platforms.check_platforms()
            
            ptr_result = check_ptr_risk(self.ip)
            ports_result = check_ports(self.ip)
            ipinfo_result = check_server_info(self.ip)
            
            # Calculate individual scores
            platforms_score = self._calculate_platforms_score(platforms_result)
            ptr_score = self._calculate_ptr_score(ptr_result)
            ports_score = self._calculate_ports_score(ports_result)
            ipinfo_score = self._calculate_ipinfo_score(ipinfo_result)
            
            # Calculate weighted overall score
            overall_score = (
                platforms_score * self.weights["platforms"] +
                ptr_score * self.weights["ptr"] +
                ports_score * self.weights["ports"] +
                ipinfo_score * self.weights["ipinfo"]
            )
            
            # Determine risk level based on overall score
            if overall_score >= 0.85:
                risk_level = "Low"
            elif overall_score >= 0.7:
                risk_level = "Medium"
            elif overall_score >= 0.5:
                risk_level = "High"
            elif overall_score >= 0.3:
                risk_level = "Very High"
            else:
                risk_level = "Critical"
            
            return {
                "ip": self.ip,
                "overall_safe_score": round(overall_score, 4),
                "risk_level": risk_level,
                "score_breakdown": {
                    "platforms": {
                        "score": round(platforms_score, 4),
                        "weight": self.weights["platforms"],
                        "weighted_score": round(platforms_score * self.weights["platforms"], 4),
                        "details": platforms_result
                    },
                    "ptr": {
                        "score": round(ptr_score, 4),
                        "weight": self.weights["ptr"],
                        "weighted_score": round(ptr_score * self.weights["ptr"], 4),
                        "details": ptr_result
                    },
                    "ports": {
                        "score": round(ports_score, 4),
                        "weight": self.weights["ports"],
                        "weighted_score": round(ports_score * self.weights["ports"], 4),
                        "details": ports_result
                    },
                    "ipinfo": {
                        "score": round(ipinfo_score, 4),
                        "weight": self.weights["ipinfo"],
                        "weighted_score": round(ipinfo_score * self.weights["ipinfo"], 4),
                        "details": ipinfo_result
                    }
                },
                "weights_used": self.weights,
                "assessment_summary": {
                    "total_platforms_checked": platforms_result.get("platforms_considered", 0),
                    "platforms_flagged_safe": platforms_result.get("platforms_flagged_as_safe", 0),
                    "ptr_status": ptr_result.get("ptr_risk", "Unknown"),
                    "open_ports_count": ports_result.get("ports_count", 0),
                    "ip_country": ipinfo_result.get("country", "Unknown"),
                    "ip_isp": ipinfo_result.get("isp", "Unknown")
                }
            }
            
        except Exception as e:
            # Return error result with conservative scoring
            return {
                "ip": self.ip,
                "overall_safe_score": 0.0,
                "risk_level": "Error",
                "error": str(e),
                "score_breakdown": {
                    "platforms": {"score": 0.0, "weight": self.weights["platforms"], "weighted_score": 0.0, "error": "Failed"},
                    "ptr": {"score": 0.0, "weight": self.weights["ptr"], "weighted_score": 0.0, "error": "Failed"},
                    "ports": {"score": 0.0, "weight": self.weights["ports"], "weighted_score": 0.0, "error": "Failed"},
                    "ipinfo": {"score": 0.0, "weight": self.weights["ipinfo"], "weighted_score": 0.0, "error": "Failed"}
                },
                "weights_used": self.weights
            }
    
    def get_score_explanation(self, score: float) -> str:
        if score >= 0.9:
            return "Excellent - IP appears to be very safe with minimal risk indicators"
        elif score >= 0.85:
            return "Good - IP shows mostly safe characteristics with minor concerns"
        elif score >= 0.75:
            return "Fair - IP has some risk indicators but generally acceptable"
        elif score >= 0.7:
            return "Moderate - IP has several risk factors that warrant attention"
        elif score >= 0.6:
            return "Concerning - IP has significant risk indicators"
        elif score >= 0.5:
            return "High Risk - IP has multiple concerning characteristics"
        elif score >= 0.4:
            return "Very High Risk - IP shows many suspicious indicators"
        elif score >= 0.3:
            return "Critical Risk - IP has extensive risk factors"
        else:
            return "Extreme Risk - IP shows maximum risk indicators across all assessments"


def score_ip(ip: str, api_keys: Dict[str, str], platform_config: Dict[str, Any]) -> Dict[str, Any]:

    scorer = IPScoring(ip, api_keys, platform_config)
    result = scorer.calculate_overall_score()
    
    # Add explanation to the result
    if "overall_safe_score" in result:
        result["explanation"] = scorer.get_score_explanation(result["overall_safe_score"])
    
    return result
