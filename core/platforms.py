import requests
from datetime import datetime, timezone

class TrustedPlatforms:
    def __init__(self, ip, api_keys, max_age_in_days, score_threshold, user_threshold, safe_ratio):
        self.ip = ip
        self.api_keys = api_keys
        self.max_age_in_days = max_age_in_days
        self.score_threshold = score_threshold
        self.user_threshold = user_threshold
        self.now = datetime.now(timezone.utc)
        self.safe_ratio = safe_ratio
        
    def check_abuseipdb(self) -> bool:
        API_URL = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": self.api_keys["abuseipdb"],
            "Accept": "application/json"
        }
        payload = {
            "ipAddress": self.ip,
            "maxAgeInDays": self.max_age_in_days,
            "verbose": True
        }
        response = requests.get(API_URL, headers=headers, params=payload)
        if response.status_code != 200:
            raise Exception(f"AbuseIPDB API: HTTP {response.status_code} - {response.text}")
        data = response.json()['data']
        return data['abuseConfidenceScore'] >= self.score_threshold and data['numDistinctUsers'] >= self.user_threshold

    def check_virustotal(self) -> bool:
        API_URL = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}"
        headers = {
            "x-apikey": self.api_keys["virustotal"],
            "accept": "application/json"
        }
        response = requests.get(API_URL, headers=headers)
        if response.status_code != 200:
            raise Exception(f"VirusTotal API: HTTP {response.status_code} - {response.text}")
        data = response.json()['data']['attributes']
        stats = data['last_analysis_stats']
        return (
            stats['malicious'] >= self.user_threshold or 
            stats['suspicious'] >= self.user_threshold or 
            data['reputation'] < 0
        )

    def check_threatbookIO(self) -> bool:
        API_URL = f"https://api.threatbook.io/v1/community/ip"
        payload = {
            "resource": self.ip,
            "apikey": self.api_keys["threatbook"]
        }
        response = requests.post(API_URL, data=payload)
        if response.status_code != 200:
            raise Exception(f"ThreatBook API: HTTP {response.status_code} - {response.text}")
        data = response.json()['data']['summary']
        if data['judgments'] != []:
            last_seen = datetime.strptime(data['last_seen'], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return (self.now - last_seen).days < self.max_age_in_days
        return False

    def check_alienvault(self) -> bool:
        API_URL = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{self.ip}/general"
        headers = {
            "X-OTX-API-KEY": self.api_keys["alienvault"]
        }
        response = requests.get(API_URL, headers=headers)
        if response.status_code != 200:
            raise Exception(f"AlienVault API: HTTP {response.status_code} - {response.text}")
        data = response.json()['pulse_info']
        if data['count'] > 0:
            modified = data['pulses'][0]['modified']
            modified_dt = datetime.fromisoformat(modified).astimezone(timezone.utc)
            return (self.now - modified_dt).days < self.max_age_in_days
        return False

    def check_platforms(self) -> dict:
        data = {
            "abuseipdb": self.check_abuseipdb(),
            "virustotal": self.check_virustotal(),
            "threatbook": self.check_threatbookIO(),
            "alienvault": self.check_alienvault()
        }

        result = list(data.values())
        platforms_considered = len(result)
        platforms_flagged_as_safe = result.count(False)
        safe_ratio = platforms_flagged_as_safe / platforms_considered
        is_safe = safe_ratio >= self.safe_ratio


        return {
                "malicious_report": data,
                "max_age_in_days": self.max_age_in_days,
                "score_threshold": self.score_threshold,
                "user_threshold": self.user_threshold,
                "platforms_considered": platforms_considered,
                "platforms_flagged_as_safe": platforms_flagged_as_safe,
                "platforms_safe_ratio": safe_ratio,
                "is_safe": is_safe
        }