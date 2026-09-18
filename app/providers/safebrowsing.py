import os
from app.providers.base import BaseProvider
class SafeBrowsingProvider(BaseProvider):
    name = "safebrowsing"; api_key_env = "SAFEBROWSING_API_KEY"; supported_types = {"url", "domain"}
    def _request(self, indicator, indicator_type):
        return self.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": os.getenv(self.api_key_env)}, json={"client": {"clientId": "soc-toolkit", "clientVersion": "1"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": indicator}]}}).json()
