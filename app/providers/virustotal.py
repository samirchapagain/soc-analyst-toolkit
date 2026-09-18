import base64
from app.providers.base import BaseProvider

class VirusTotalProvider(BaseProvider):
    name = "virustotal"
    api_key_env = "VIRUSTOTAL_API_KEY"

    def _request(self, indicator, indicator_type):
        key = __import__("os").getenv(self.api_key_env)
        resource = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=") if indicator_type == "url" else indicator
        kind = "files" if indicator_type in {"md5", "sha1", "sha256"} else f"{indicator_type}s"
        data = self.get(f"https://www.virustotal.com/api/v3/{kind}/{resource}", headers={"x-apikey": key}).json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        total = sum(int(v) for v in stats.values())
        positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        return {"vt_positives": positives, "vt_total": total, "score": round(positives * 100 / total) if total else 0}
