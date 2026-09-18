import os
from app.providers.base import BaseProvider
class IPQSProvider(BaseProvider):
    name = "ipqs"; api_key_env = "IPQUALITYSCORE_API_KEY"; supported_types = {"ip", "domain", "url"}
    def _request(self, indicator, indicator_type):
        return self.get(f"https://ipqualityscore.com/api/json/{'ip' if indicator_type == 'ip' else 'url'}/{os.getenv(self.api_key_env)}/{indicator}").json()
