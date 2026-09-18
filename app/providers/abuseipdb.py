import os
from app.providers.base import BaseProvider

class AbuseIPDBProvider(BaseProvider):
    name = "abuseipdb"
    api_key_env = "ABUSEIPDB_API_KEY"
    supported_types = {"ip"}
    def _request(self, indicator, indicator_type):
        data = self.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": indicator, "maxAgeInDays": 90}, headers={"Key": os.getenv(self.api_key_env), "Accept": "application/json"}).json().get("data", {})
        return {"abuse_confidence": int(data.get("abuseConfidenceScore", 0)), "country": data.get("countryCode"), "isp": data.get("isp")}
