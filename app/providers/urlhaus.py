import os
from app.providers.base import BaseProvider
class URLhausProvider(BaseProvider):
    name = "urlhaus"; api_key_env = ""; supported_types = {"url", "domain"}
    def _request(self, indicator, indicator_type):
        return self.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": indicator}).json()
