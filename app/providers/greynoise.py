import os
from app.providers.base import BaseProvider
class GreyNoiseProvider(BaseProvider):
    name = "greynoise"; api_key_env = "GREYNOISE_API_KEY"; supported_types = {"ip"}
    def _request(self, indicator, indicator_type):
        data = self.get(f"https://api.greynoise.io/v3/community/{indicator}", headers={"key": os.getenv(self.api_key_env)}).json()
        return {"noise": data.get("noise"), "riot": data.get("riot"), "classification": data.get("classification")}
