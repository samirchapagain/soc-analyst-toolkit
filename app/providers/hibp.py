import os
from app.providers.base import BaseProvider
class HIBPProvider(BaseProvider):
    name = "hibp"; api_key_env = "HIBP_API_KEY"; supported_types = {"email"}
    def _request(self, indicator, indicator_type):
        return {"breaches": self.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{indicator}", headers={"hibp-api-key": os.getenv(self.api_key_env), "user-agent": "soc-analyst-toolkit"}).json()}
