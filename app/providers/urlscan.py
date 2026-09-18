import os
from app.providers.base import BaseProvider
class URLScanProvider(BaseProvider):
    name = "urlscan"; api_key_env = "URLSCAN_API_KEY"; supported_types = {"url", "domain", "ip"}
    def _request(self, indicator, indicator_type):
        data = self.get("https://urlscan.io/api/v1/search/", params={"q": f"page.url:{indicator}"}, headers={"API-Key": os.getenv(self.api_key_env)}).json()
        return {"result_count": data.get("total", len(data.get("results", [])))}
