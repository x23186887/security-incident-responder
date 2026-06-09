# Keyword map — maps incident types to real MITRE ATT&CK technique IDs
TECHNIQUE_MAP = {
    # Credential & Access
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
    },
    # NEW — Supply Chain
    "supply chain": {
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "tactic": "Initial Access",
        "description": "Adversaries manipulate products or delivery mechanisms before the customer receives them, including compromising third-party software dependencies.",
        "mitigations": [
            "M1051 - Update Software",
            "M1016 - Vulnerability Scanning",
            "M1013 - Application Developer Guidance",
            "M1045 - Code Signing"
        ],
        "detection": "Monitor for unexpected changes in software packages, verify integrity of third-party dependencies, audit CI/CD pipeline access."
    },
    # NEW — Credential/Secret Exposure
    "credential exposure": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries search for and find unsecured credentials in files, environment variables, or version control systems.",
        "mitigations": [
            "M1047 - Audit",
            "M1027 - Password Policies",
            "M1026 - Privileged Account Management",
            "M1017 - User Training"
        ],
        "detection": "Monitor version control commits for secrets, scan repositories for exposed API keys and credentials."
    },
    "api key": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries search for and find unsecured credentials in files, environment variables, or version control systems.",
        "mitigations": [
            "M1047 - Audit",
            "M1027 - Password Policies",
            "M1026 - Privileged Account Management"
        ],
        "detection": "Monitor version control commits for secrets, scan repositories for exposed API keys and credentials."
    },
    # NEW — Cloud Storage Misconfiguration
    "s3": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversaries access data from improperly secured cloud storage such as misconfigured S3 buckets.",
        "mitigations": [
            "M1047 - Audit",
            "M1022 - Restrict File and Directory Permissions",
            "M1018 - User Account Management"
        ],
        "detection": "Monitor cloud storage access logs, alert on public bucket access, track unusual data downloads."
    },
    "cloud": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Adversaries access data from improperly secured cloud storage objects.",
        "mitigations": [
            "M1047 - Audit",
            "M1022 - Restrict File and Directory Permissions",
            "M1018 - User Account Management"
        ],
        "detection": "Monitor cloud storage access logs, alert on public bucket configurations, track unusual data access."
    },
    # NEW — Remote Code Execution
    "remote code execution": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries exploit vulnerabilities in internet-facing applications to execute arbitrary code remotely.",
        "mitigations": [
            "M1048 - Application Isolation and Sandboxing",
            "M1051 - Update Software",
            "M1030 - Network Segmentation",
            "M1016 - Vulnerability Scanning"
        ],
        "detection": "Monitor application logs for unusual requests, process creation from web server processes, unexpected outbound connections."
    },
    "apache": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries exploit vulnerabilities in Apache and other public-facing web servers to gain initial access.",
        "mitigations": [
            "M1048 - Application Isolation and Sandboxing",
            "M1051 - Update Software",
            "M1016 - Vulnerability Scanning"
        ],
        "detection": "Monitor Apache access and error logs, watch for path traversal patterns, alert on shell spawned from web processes."
    },
    # NEW — Backdoor / Persistence
    "backdoor": {
        "technique_id": "T1505",
        "technique_name": "Server Software Component",
        "tactic": "Persistence",
        "description": "Adversaries abuse legitimate extensible development features of servers to establish persistent access.",
        "mitigations": [
            "M1042 - Disable or Remove Feature or Program",
            "M1045 - Code Signing",
            "M1026 - Privileged Account Management"
        ],
        "detection": "Monitor for unexpected files in web server directories, new server-side scripts, unusual process spawning."
    },
    # EXISTING — kept for completeness
    "buffer overflow": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "description": "Adversaries exploit software vulnerabilities in client applications to execute code.",
        "mitigations": [
            "M1050 - Exploit Protection",
            "M1048 - Application Isolation and Sandboxing"
        ],
        "detection": "Monitor for application crashes, unexpected process creation, memory corruption indicators."
    },
    "privilege escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries exploit vulnerabilities to execute code with elevated permissions.",
        "mitigations": [
            "M1051 - Update Software",
            "M1050 - Exploit Protection",
            "M1048 - Application Isolation and Sandboxing"
        ],
        "detection": "Monitor for privilege changes, unexpected use of admin accounts, security tool tampering."
    },
    "exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries steal data by exfiltrating it over existing command and control channels.",
        "mitigations": [
            "M1031 - Network Intrusion Prevention",
            "M1057 - Data Loss Prevention"
        ],
        "detection": "Monitor for unusual outbound data transfers, large DNS queries, unexpected cloud uploads."
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
    """
    Match incident text to the most relevant MITRE ATT&CK technique.
    Checks longer/more specific phrases first to avoid false matches.
    """
    incident_lower = incident_text.lower()

    # Sort by keyword length descending — longer = more specific = higher priority
    sorted_techniques = sorted(TECHNIQUE_MAP.keys(), key=len, reverse=True)

    for keyword in sorted_techniques:
        if keyword in incident_lower:
            return TECHNIQUE_MAP[keyword]

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