from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.greynoise import GreyNoiseProvider
from app.providers.hibp import HIBPProvider
from app.providers.ipinfo import IPInfoProvider
from app.providers.ipqs import IPQSProvider
from app.providers.malwarebazaar import MalwareBazaarProvider
from app.providers.otx import OTXProvider
from app.providers.safebrowsing import SafeBrowsingProvider
from app.providers.shodan import ShodanProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.urlscan import URLScanProvider
from app.providers.virustotal import VirusTotalProvider

PROVIDERS = {p.name: p() for p in (VirusTotalProvider, AbuseIPDBProvider, OTXProvider, URLScanProvider, ShodanProvider, GreyNoiseProvider, IPInfoProvider, HIBPProvider, MalwareBazaarProvider, URLhausProvider, SafeBrowsingProvider, IPQSProvider)}
def get_provider(name): return PROVIDERS.get(name)
def available_providers(): return [{"name": p.name, "configured": p.configured, "supported_types": sorted(p.supported_types)} for p in PROVIDERS.values()]
