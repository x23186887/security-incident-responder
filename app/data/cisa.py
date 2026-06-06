import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def get_actively_exploited(keyword: str, max_results: int = 3) -> list:
    """
    Fetch vulnerabilities from CISA's Known Exploited Vulnerabilities catalog.
    These are vulnerabilities actively being exploited by attackers RIGHT NOW.
    """
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(CISA_KEV_URL)

            if response.status_code != 200:
                return []

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            keyword_lower = keyword.lower()
            matched = []

            for vuln in vulnerabilities:
                name = vuln.get("vulnerabilityName", "").lower()
                product = vuln.get("product", "").lower()
                vendor = vuln.get("vendorProject", "").lower()
                description = vuln.get("shortDescription", "").lower()

                # Check if keyword matches any field
                if any(keyword_lower in field for field in [name, product, vendor, description]):
                    matched.append({
                        "cve_id": vuln.get("cveID", "Unknown"),
                        "name": vuln.get("vulnerabilityName", "Unknown"),
                        "vendor": vuln.get("vendorProject", "Unknown"),
                        "product": vuln.get("product", "Unknown"),
                        "date_added": vuln.get("dateAdded", "Unknown"),
                        "due_date": vuln.get("dueDate", "Unknown"),
                        "description": vuln.get("shortDescription", "")[:250],
                        "required_action": vuln.get("requiredAction", "Apply vendor patch.")
                    })

                if len(matched) >= max_results:
                    break

            return matched

    except Exception as e:
        print(f"CISA KEV fetch error: {e}")
        return []


def format_cisa_for_prompt(vulns: list) -> str:
    """Format CISA KEV data into readable text for the LLM prompt."""
    if not vulns:
        return "No matching entries in CISA Known Exploited Vulnerabilities catalog."

    formatted = "CISA KNOWN EXPLOITED VULNERABILITIES (Actively exploited RIGHT NOW):\n"
    for v in vulns:
        formatted += f"""
CVE: {v['cve_id']} — {v['name']}
Vendor/Product: {v['vendor']} / {v['product']}
Added to CISA KEV: {v['date_added']} | Patch Due: {v['due_date']}
Description: {v['description']}
Required Action: {v['required_action']}
---"""
    return formatted