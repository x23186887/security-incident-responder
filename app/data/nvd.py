import httpx
import json

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def search_cves(keyword: str, max_results: int = 5) -> list:
    """
    Search the National Vulnerability Database for real CVEs
    related to the incident keyword.
    """
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(NVD_BASE_URL, params=params)

            if response.status_code != 200:
                return []

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            results = []
            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")

                # Get description
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description available"
                )

                # Get CVSS severity score
                metrics = cve.get("metrics", {})
                severity = "Unknown"
                score = "N/A"

                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = cvss.get("baseSeverity", "Unknown")
                    score = cvss.get("baseScore", "N/A")
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0]["cvssData"]
                    score = cvss.get("baseScore", "N/A")
                    severity = "MEDIUM" if float(score) >= 4.0 else "LOW"

                # Get published date
                published = cve.get("published", "Unknown")[:10]

                results.append({
                    "cve_id": cve_id,
                    "description": description[:300],
                    "severity": severity,
                    "score": score,
                    "published": published
                })

            return results

    except Exception as e:
        print(f"NVD fetch error: {e}")
        return []


def format_cves_for_prompt(cves: list) -> str:
    """Format CVE data into readable text for the LLM prompt."""
    if not cves:
        return "No specific CVEs found for this incident type."

    formatted = "REAL CVEs FROM NATIONAL VULNERABILITY DATABASE (NVD):\n"
    for cve in cves:
        formatted += f"""
CVE ID: {cve['cve_id']}
Severity: {cve['severity']} (Score: {cve['score']}/10)
Published: {cve['published']}
Description: {cve['description']}
---"""
    return formatted