from app.data.nvd import search_cves, format_cves_for_prompt
from app.data.mitre import get_mitre_technique, format_mitre_for_prompt
from app.data.cisa import get_actively_exploited, format_cisa_for_prompt
import re


def extract_keywords(incident_text: str) -> list:
    """
    Extract the most relevant security keywords from the incident description
    to use as search terms for NVD and CISA.
    """
    security_terms = [
        "sql injection", "xss", "cross-site scripting", "ransomware",
        "phishing", "malware", "ddos", "brute force", "buffer overflow",
        "remote code execution", "rce", "privilege escalation", "data breach",
        "insider threat", "zero day", "log4j", "apache", "nginx", "windows",
        "linux", "ssh", "rdp", "smb", "dns", "vpn", "firewall", "authentication"
    ]

    incident_lower = incident_text.lower()
    found = [term for term in security_terms if term in incident_lower]

    # Always add a generic keyword based on first few words
    words = re.findall(r'\b\w{4,}\b', incident_lower)
    generic = words[0] if words else "vulnerability"

    return found if found else [generic]


async def build_context(incident_text: str) -> dict:
    """
    Fetch real-world data from all three sources and build
    enriched context for the LLM.
    """
    keywords = extract_keywords(incident_text)
    primary_keyword = keywords[0]

    print(f"[RAG] Searching for keyword: {primary_keyword}")

    # Fetch from all three sources in parallel would be ideal
    # but for simplicity we do it sequentially here
    cves = await search_cves(primary_keyword, max_results=4)
    cisa_vulns = await get_actively_exploited(primary_keyword, max_results=3)
    mitre_technique = get_mitre_technique(incident_text)

    # Format everything for the LLM prompt
    context = {
        "cve_context": format_cves_for_prompt(cves),
        "mitre_context": format_mitre_for_prompt(mitre_technique),
        "cisa_context": format_cisa_for_prompt(cisa_vulns),
        "keywords_found": keywords,
        "mitre_technique_id": mitre_technique["technique_id"],
        "mitre_technique_name": mitre_technique["technique_name"],
        "raw_cves": cves,
        "raw_cisa": cisa_vulns
    }

    return context