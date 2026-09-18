"""Build and manage offline detection rules from ATT&CK metadata."""
from copy import deepcopy
from .attack_data import TECHNIQUES, THREAT_PROFILES

def generate_rules(techniques=None):
    return [{"id": f"mitre_{t['id'].lower().replace('.', '_')}", "name": t["name"],
             "severity": t["severity"], "mitre": t["id"], "tactic": t["tactic"],
             "description": t["description"], "keywords": t["keywords"],
             "remediation": "Investigate the host and contain confirmed malicious activity.",
             "why": f"Matches ATT&CK technique {t['id']}."}
            for t in (techniques or TECHNIQUES)]

def generate_profile(profile):
    data = THREAT_PROFILES.get(profile) if isinstance(profile, str) else profile
    if not data:
        raise KeyError(f"Unknown threat profile: {profile}")
    wanted = set(data["techniques"])
    return generate_rules([t for t in TECHNIQUES if t["id"] in wanted])

def load_rules(handwritten=None, generated=None):
    """Merge rules by id, keeping handwritten definitions authoritative."""
    merged = {r["id"]: deepcopy(r) for r in (generated or generate_rules())}
    merged.update({r["id"]: deepcopy(r) for r in (handwritten or [])})
    return list(merged.values())

def rules_for_profile(profile):
    return generate_profile(profile)
