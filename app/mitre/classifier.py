"""Classification and visualisation helpers for findings."""
from collections import Counter
from .attack_data import TECHNIQUES, TACTICS

_BY_ID = {t["id"]: t for t in TECHNIQUES}

def classify_findings(findings, text=None):
    findings = findings or []
    result = []
    for finding in findings:
        item = dict(finding)
        tid = item.get("mitre") or item.get("technique_id")
        meta = _BY_ID.get(tid, {})
        item["technique_id"] = tid
        item["technique"] = meta.get("name", item.get("rule_name", "Unknown"))
        item["tactic"] = item.get("tactic") or meta.get("tactic")
        item["tactic_id"] = meta.get("tactic_id")
        result.append(item)
    return {"findings": result, "tactics": sorted({x["tactic"] for x in result if x.get("tactic")}), "techniques": sorted({x["technique_id"] for x in result if x.get("technique_id")})}

def kill_chain_view(findings):
    classified = classify_findings(findings)["findings"]
    counts = Counter(x.get("tactic") for x in classified if x.get("tactic"))
    return [{"id": t["id"], "name": t["name"], "count": counts.get(t["name"], 0), "techniques": sorted({x["technique_id"] for x in classified if x.get("tactic") == t["name"]})} for t in TACTICS]

def attack_heatmap(findings):
    classified = classify_findings(findings)["findings"]
    counts = Counter(x.get("technique_id") for x in classified if x.get("technique_id"))
    return [{"technique_id": tid, "name": _BY_ID.get(tid, {}).get("name", tid), "tactic": _BY_ID.get(tid, {}).get("tactic"), "count": count} for tid, count in counts.most_common()]
