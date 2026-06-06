import httpx

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Keyword map — maps incident types to real MITRE ATT&CK technique IDs
TECHNIQUE_MAP = {
    "sql injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Attackers exploit weaknesses in internet-facing applications such as SQL injection to gain initial access.",
        "mitigations": [
            "M1048 - Application Isolation and Sandboxing",
            "M1030 - Network Segmentation",
            "M1026 - Privileged Account Management",
            "M1016 - Vulnerability Scanning"
        ],
        "detection": "Monitor application logs for unusual SQL query patterns, error messages, and unexpected data outputs."
    },
    "phishing": {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries send malicious emails to gain access to victim systems or steal credentials.",
        "mitigations": [
            "M1049 - Antivirus/Antimalware",
            "M1031 - Network Intrusion Prevention",
            "M1017 - User Training",
            "M1054 - Software Configuration"
        ],
        "detection": "Monitor email gateway logs, detect suspicious sender domains, track credential use anomalies."
    },
    "ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries encrypt data on target systems to interrupt availability and hold data for ransom.",
        "mitigations": [
            "M1053 - Data Backup",
            "M1049 - Antivirus/Antimalware",
            "M1040 - Behavior Prevention on Endpoint",
            "M1034 - Limit Hardware Installation"
        ],
        "detection": "Monitor for file system encryption activity, unusual process behavior, ransom note creation."
    },
    "ddos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries perform DoS attacks to degrade or block availability of targeted resources.",
        "mitigations": [
            "M1037 - Filter Network Traffic",
            "M1035 - Limit Access to Resource Over Network"
        ],
        "detection": "Monitor network traffic volume, detect unusual spikes, track connection rates per IP."
    },
    "brute force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries try many passwords to gain access to accounts without prior knowledge of credentials.",
        "mitigations": [
            "M1036 - Account Use Policies",
            "M1032 - Multi-factor Authentication",
            "M1027 - Password Policies"
        ],
        "detection": "Monitor authentication logs for repeated failed attempts, unusual login times or locations."
    },
    "malware": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
        "description": "Adversaries rely on user interaction to execute malicious code on target systems.",
        "mitigations": [
            "M1049 - Antivirus/Antimalware",
            "M1038 - Execution Prevention",
            "M1017 - User Training"
        ],
        "detection": "Monitor process creation events, file system changes, and network connections from new processes."
    },
    "data breach": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries steal data by exfiltrating it over an existing command and control channel.",
        "mitigations": [
            "M1031 - Network Intrusion Prevention",
            "M1037 - Filter Network Traffic",
            "M1057 - Data Loss Prevention"
        ],
        "detection": "Monitor network traffic for unusual data volumes, unexpected external connections, DNS anomalies."
    },
    "insider threat": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries use legitimate credentials to gain access, bypass security controls, and maintain persistence.",
        "mitigations": [
            "M1036 - Account Use Policies",
            "M1026 - Privileged Account Management",
            "M1032 - Multi-factor Authentication"
        ],
        "detection": "Monitor account usage patterns, flag access outside normal hours, track privilege escalation."
    }
}

DEFAULT_TECHNIQUE = {
    "technique_id": "T1059",
    "technique_name": "Command and Scripting Interpreter",
    "tactic": "Execution",
    "description": "Adversaries abuse command and script interpreters to execute commands and payloads.",
    "mitigations": [
        "M1042 - Disable or Remove Feature or Program",
        "M1049 - Antivirus/Antimalware",
        "M1038 - Execution Prevention"
    ],
    "detection": "Monitor command-line activity, script execution, and process creation events."
}


def get_mitre_technique(incident_text: str) -> dict:
    """Match incident text to the most relevant MITRE ATT&CK technique."""
    incident_lower = incident_text.lower()
    for keyword, technique in TECHNIQUE_MAP.items():
        if keyword in incident_lower:
            return technique
    return DEFAULT_TECHNIQUE


def format_mitre_for_prompt(technique: dict) -> str:
    """Format MITRE data into readable text for the LLM prompt."""
    mitigations = "\n".join(f"  - {m}" for m in technique["mitigations"])
    return f"""
MITRE ATT&CK FRAMEWORK MAPPING:
Technique ID: {technique['technique_id']}
Technique Name: {technique['technique_name']}
Tactic: {technique['tactic']}
Description: {technique['description']}
Official Mitigations:
{mitigations}
Detection: {technique['detection']}
"""