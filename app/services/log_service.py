import math
import re
from typing import Any

LOG_RULES: list[dict[str, Any]] = [
    {"id": "BRUTE_FORCE", "name": "Brute Force", "severity": "high", "mitre": "T1110", "pattern": r"failed password|authentication failure|failed login|4625", "description": "Repeated authentication failures.", "remediation": "Review source and lock or reset affected accounts.", "why": "May indicate password guessing."},
    {"id": "ENCODED_POWERSHELL", "name": "Encoded PowerShell", "severity": "high", "mitre": "T1059.001", "pattern": r"powershell.*-enc|powershell.*-encodedcommand|frombase64string", "description": "Encoded PowerShell execution.", "remediation": "Quarantine host and inspect decoded command.", "why": "Encoding commonly hides malicious commands."},
    {"id": "SQLI", "name": "SQL Injection", "severity": "high", "mitre": "T1190", "pattern": r"union select|or 1=1|' or '|sleep\(\d+\)|benchmark\(", "description": "SQL injection payload.", "remediation": "Block source and parameterize queries.", "why": "Can expose or modify application data."},
    {"id": "PORT_SCAN", "name": "Port Scan", "severity": "medium", "mitre": "T1046", "pattern": r"nmap|masscan|port scan|syn scan", "description": "Network discovery scan.", "remediation": "Validate asset ownership and rate-limit source.", "why": "Precedes exploitation or lateral movement."},
    {"id": "SUSPICIOUS_UA", "name": "Suspicious User Agent", "severity": "medium", "mitre": "T1595", "pattern": r"sqlmap|nikto|curl/|wget/|python-requests|hydra|zgrab", "description": "Known scanning or automation client.", "remediation": "Investigate source and request pattern.", "why": "Automated tooling is common in reconnaissance."},
    {"id": "LSASS_ACCESS", "name": "LSASS Access", "severity": "critical", "mitre": "T1003.001", "pattern": r"lsass\.exe|sekurlsa|mimikatz", "description": "Credential material access.", "remediation": "Isolate endpoint and rotate credentials.", "why": "LSASS memory access can expose reusable secrets."},
    {"id": "PSEXEC", "name": "PsExec", "severity": "high", "mitre": "T1021.002", "pattern": r"psexesvc|psexec\.exe", "description": "Remote service execution.", "remediation": "Validate administrative change and source host.", "why": "Often used for lateral movement."},
    {"id": "C2_BEACON", "name": "C2 Beacon", "severity": "critical", "mitre": "T1071", "pattern": r"beacon|cobaltstrike|meterpreter|reverse shell", "description": "Command-and-control indicator.", "remediation": "Isolate host and block infrastructure.", "why": "Strong signal of active remote control."},
    {"id": "NEW_SERVICE_INSTALL", "name": "New Service Install", "severity": "high", "mitre": "T1543", "pattern": r"7045|service installed", "description": "New Windows service installation.", "remediation": "Verify change ticket and service binary.", "why": "Services provide persistence and execution."},
    {"id": "SCHEDULED_TASK", "name": "Scheduled Task", "severity": "high", "mitre": "T1053.005", "pattern": r"schtasks|task scheduler", "description": "Scheduled task creation.", "remediation": "Inspect task action and creator.", "why": "Tasks can establish persistence."},
    {"id": "REGISTRY_RUN_PERSIST", "name": "Registry Run Persistence", "severity": "high", "mitre": "T1547.001", "pattern": r"CurrentVersion\\Run|Run\\", "description": "Registry run key persistence.", "remediation": "Remove unauthorized value and contain host.", "why": "Run keys execute at user logon."},
    {"id": "PROCESS_INJECTION", "name": "Process Injection", "severity": "critical", "mitre": "T1055", "pattern": r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory", "description": "Process injection API usage.", "remediation": "Capture memory and isolate endpoint.", "why": "Injection can hide execution in trusted processes."},
    {"id": "CREDENTIAL_DUMP", "name": "Credential Dumping", "severity": "critical", "mitre": "T1003", "pattern": r"procdump.*lsass|comsvcs\.dll|MiniDump", "description": "Credential dumping utility or API.", "remediation": "Rotate credentials and investigate process tree.", "why": "Credential theft enables account takeover."},
    {"id": "DEFENSE_EVASION", "name": "Defense Evasion", "severity": "high", "mitre": "T1562", "pattern": r"Set-MpPreference|Add-MpPreference -ExclusionPath|netsh advfirewall set", "description": "Security controls modified.", "remediation": "Restore controls and review actor.", "why": "Attackers disable defenses before execution."},
    {"id": "DNS_C2", "name": "DNS C2", "severity": "high", "mitre": "T1071.004", "pattern": r"(?:[a-z0-9]{31,}\.)+[a-z]{2,}", "description": "Long DNS label suggests tunneling.", "remediation": "Block domain and inspect DNS client.", "why": "DNS can carry covert command traffic."},
    {"id": "WEBSHELL", "name": "Web Shell", "severity": "critical", "mitre": "T1505.003", "pattern": r"eval\(\$_POST|system\(\$_GET|c99\.php|r57\.php", "description": "Web shell execution indicator.", "remediation": "Take web server offline and preserve evidence.", "why": "Web shells provide persistent server access."},
    {"id": "DATA_EXFIL", "name": "Data Exfiltration", "severity": "high", "mitre": "T1041", "pattern": r"curl -X POST|Invoke-WebRequest -Method POST.*base64", "description": "Outbound data transfer command.", "remediation": "Block destination and investigate transferred data.", "why": "May indicate theft over command channels."},
    {"id": "IMPOSSIBLE_TRAVEL", "name": "Impossible Travel", "severity": "high", "mitre": "T1078", "pattern": r"(?!)", "description": "GeoIP-dependent login anomaly.", "remediation": "Validate user and revoke sessions.", "why": "A successful account may be compromised."},
]


def analyze_logs(content: bytes) -> dict[str, Any]:
    lines = content.decode("utf-8", errors="replace").splitlines()
    findings: list[dict[str, Any]] = []
    severity_summary = {severity: 0 for severity in ("low", "medium", "high", "critical")}
    rule_summary: dict[str, int] = {}
    for line_number, line in enumerate(lines, 1):
        for rule in LOG_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                severity_summary[rule["severity"]] += 1
                rule_summary[rule["id"]] = rule_summary.get(rule["id"], 0) + 1
                if len(findings) < 500:
                    findings.append({"line": line_number, "rule_id": rule["id"], "rule_name": rule["name"], "severity": rule["severity"], "mitre": rule["mitre"], "evidence": line[:300], "description": rule["description"], "remediation": rule["remediation"], "why": rule["why"]})
    return {"total_lines": len(lines), "total_findings": sum(rule_summary.values()), "severity_summary": severity_summary, "rule_summary": rule_summary, "findings": findings}
