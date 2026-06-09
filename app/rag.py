from app.data.nvd import search_cves, format_cves_for_prompt
from app.data.mitre import get_mitre_technique, format_mitre_for_prompt
from app.data.cisa import get_actively_exploited, format_cisa_for_prompt
import re


def extract_keywords(incident_text: str) -> list:
    """
    Extract the most relevant security keywords from the incident description.
    Uses priority matching — longer/more specific terms checked first.
    """
    # Ordered by specificity — longest phrases first to avoid partial matches
    security_terms = [
        # Specific attack types first
        "sql injection",
        "cross-site scripting",
        "remote code execution",
        "privilege escalation",
        "supply chain",
        "insider threat",
        "data breach",
        "credential exposure",
        "brute force",
        "ransomware",
        "phishing",
        "malware",
        "ddos",
        "buffer overflow",
        "zero day",
        "log4j",
        # Technologies
        "apache",
        "nginx",
        "windows",
        "linux",
        "aws",
        "s3",
        "ssh",
        "rdp",
        "smb",
        "dns",
        "vpn",
        # Generic security terms last
        "vulnerability",
        "exploit",
        "backdoor",
        "exfiltration",
        "encryption",
        "authentication",
        "firewall"
    ]

    incident_lower = incident_text.lower()
    found = [term for term in security_terms if term in incident_lower]

    # If nothing matched, extract meaningful nouns (4+ chars, not common words)
    if not found:
        stopwords = {
            "that", "this", "with", "have", "from", "they", "been",
            "were", "their", "also", "which", "when", "into", "than",
            "then", "some", "what", "about", "there", "during", "after",
            "before", "junior", "senior", "using", "used", "found",
            "show", "shows", "appear", "appears", "discovered", "contain",
            "containing", "including", "server", "system", "network",
            "access", "data", "file", "files", "account", "user", "port"
        }
        import re
        words = re.findall(r'\b[a-z]{4,}\b', incident_lower)
        found = [w for w in words if w not in stopwords][:2]

    return found if found else ["vulnerability"]

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