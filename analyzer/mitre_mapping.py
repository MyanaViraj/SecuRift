"""
MITRE ATT&CK Mapping Module for SecuRift Network Detection Engineering
Provides standardized enterprise techniques, tactics, and detection documentation rationale.
"""

MITRE_TECHNIQUES_CATALOG = [
    {
        "id": "T1046",
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable software or attack surface.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Identifies rapid TCP SYN or connect attempts across consecutive destination ports."
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt password guessing against authentication services like SSH, RDP, or HTTP POST.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Monitors repeated authentication failures or high-frequency login packets within a short window."
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer web protocols (HTTP/HTTPS) to blend in with normal network traffic.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Inspects HTTP requests for non-standard User-Agents, suspicious URI paths, or webshell parameter strings."
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Inspects network payloads for command execution indicators such as '/bin/sh', 'cmd.exe', or PowerShell invocations."
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Detects high-volume packet streams or unusual ICMP/UDP flooding exceeding baseline thresholds."
    },
    {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get information about running processes on a system.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Identifies remote management or webshell commands querying system process tables."
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing applications such as web servers or database interfaces.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Detects exploitation payloads such as SQL injection, path traversal, or remote code execution tokens in inbound requests."
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an alternative protocol such as DNS or ICMP.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Inspects abnormal DNS query lengths or base64-encoded labels indicating DNS tunneling."
    },
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
        "detection_logic_template": "Detection mapping based on the documented detection logic: Correlates network sweeps and probe packets targeting multiple IP addresses."
    }
]


def get_technique_details(technique_id):
    """Retrieve details for a given technique ID if in catalog."""
    tid = technique_id.strip().upper()
    for tech in MITRE_TECHNIQUES_CATALOG:
        if tech["id"].upper() == tid:
            return tech
    return None
