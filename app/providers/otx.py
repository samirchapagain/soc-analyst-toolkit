import os
from app.providers.base import BaseProvider
class OTXProvider(BaseProvider):
    name = "otx"; api_key_env = "OTX_API_KEY"
    def _request(self, indicator, indicator_type):
        kind = "IPv4" if indicator_type == "ip" else "domain" if indicator_type == "domain" else "url"
        data = self.get(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{indicator}/general", headers={"X-OTX-API-KEY": os.getenv(self.api_key_env)}).json()
        return {"pulse_count": data.get("pulse_info", {}).get("count", 0)}
