import os
from app.providers.base import BaseProvider
class IPInfoProvider(BaseProvider):
    name = "ipinfo"; api_key_env = "IPINFO_API_KEY"; supported_types = {"ip"}
    def _request(self, indicator, indicator_type):
        return self.get(f"https://ipinfo.io/{indicator}/json", params={"token": os.getenv(self.api_key_env)}).json()
