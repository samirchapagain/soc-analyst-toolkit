import os
from app.providers.base import BaseProvider
class ShodanProvider(BaseProvider):
    name = "shodan"; api_key_env = "SHODAN_API_KEY"; supported_types = {"ip", "domain"}
    def _request(self, indicator, indicator_type):
        data = self.get(f"https://api.shodan.io/{'shodan/host' if indicator_type == 'ip' else 'dns/resolve'}", params={"key": os.getenv(self.api_key_env), "ip": indicator, "hostnames": indicator}).json()
        return {"ports": data.get("ports", []), "organization": data.get("org")}
