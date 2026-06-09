import asyncio
import time
import json
from app.agent import generate_workflow

# ─────────────────────────────────────────
# 10 TEST CASES WITH EXPECTED VALUES
# ─────────────────────────────────────────
TEST_CASES = [
    {
        "id": 1,
        "incident": "At 3AM our entire hospital network was hit by ransomware. 47 Windows servers across 3 sites have files encrypted with .lockbit extension. Ransom note demands 15 Bitcoin. Patient records system, MRI machines, and pharmacy systems are all offline. Initial vector appears to be an RDP port left open on a legacy Windows Server 2008 machine. Backups are on the same network and also encrypted.",
        "expected_severity": "Critical",
        "expected_mitre": "T1486",
        "expected_keywords": ["ransomware"]
    },
    {
        "id": 2,
        "incident": "Our web application login portal was attacked via SQL injection at approximately 2AM. The attacker bypassed authentication entirely and gained admin access. Database logs show a full dump of the users table — 50,000 records including emails and bcrypt hashes were exfiltrated.",
        "expected_severity": "High",
        "expected_mitre": "T1190",
        "expected_keywords": ["sql injection"]
    },
    {
        "id": 3,
        "incident": "An employee in the finance department received a convincing phishing email impersonating our CEO requesting an urgent wire transfer. They clicked the link and entered Office 365 credentials on a fake login page. The attackers now have full access to their email and we suspect lateral movement.",
        "expected_severity": "High",
        "expected_mitre": "T1566",
        "expected_keywords": ["phishing"]
    },
    {
        "id": 4,
        "incident": "Our e-commerce platform has been under a sustained DDoS attack for 6 hours. Traffic surged from normal 800 req/sec to over 120,000 req/sec. The site is completely unavailable and we are losing approximately 15,000 euro per hour.",
        "expected_severity": "High",
        "expected_mitre": "T1498",
        "expected_keywords": ["ddos"]
    },
    {
        "id": 5,
        "incident": "A software engineer who resigned last Friday accessed our GitHub organisation at 11PM on their last day using still-active credentials. They cloned 14 private repositories containing proprietary source code and AWS infrastructure as code. Git logs show they also pushed a backdoor commit to our main branch.",
        "expected_severity": "High",
        "expected_mitre": "T1078",
        "expected_keywords": ["insider threat"]
    },
    {
        "id": 6,
        "incident": "We discovered that a third-party npm package we use in production was compromised and contained malicious code that harvested AWS credentials from our CI/CD pipeline environment variables and sent them to an external server. Our AWS account shows 14 unrecognised IAM users created.",
        "expected_severity": "Critical",
        "expected_mitre": "T1195",
        "expected_keywords": ["malware"]
    },
    {
        "id": 7,
        "incident": "Our server monitoring dashboard had its admin login portal exposed on port 8080 without IP whitelisting. Auth logs show 450,000 failed login attempts over 72 hours from automated tools. One attempt succeeded using the password admin123 on an account that was never secured.",
        "expected_severity": "High",
        "expected_mitre": "T1110",
        "expected_keywords": ["brute force"]
    },
    {
        "id": 8,
        "incident": "A junior developer accidentally committed an .env file containing our production Stripe API key, SendGrid API key, and PostgreSQL connection string to a public GitHub repository. The repo was public for approximately 2 hours. Stripe logs show 3 unauthorised API calls querying customer payment methods.",
        "expected_severity": "High",
        "expected_mitre": "T1552",
        "expected_keywords": ["data breach"]
    },
    {
        "id": 9,
        "incident": "Our Apache web servers running version 2.4.49 were exploited using a path traversal and remote code execution vulnerability. Attacker used it to read system files and execute arbitrary commands. We found a reverse shell script planted and evidence of cryptocurrency mining software installed.",
        "expected_severity": "Critical",
        "expected_mitre": "T1190",
        "expected_keywords": ["apache"]
    },
    {
        "id": 10,
        "incident": "During a routine security audit we discovered our AWS S3 bucket named company-backups-prod was set to public read access for the past 8 months. The bucket contains daily database backups including full customer PII, internal financial reports, and employee HR records. S3 access logging was not enabled.",
        "expected_severity": "Critical",
        "expected_mitre": "T1530",
        "expected_keywords": ["data breach"]
    }
]

# ─────────────────────────────────────────
# REQUIRED SECTIONS IN EVERY OUTPUT
# ─────────────────────────────────────────
REQUIRED_SECTIONS = [
    "INCIDENT SUMMARY",
    "SEVERITY",
    "IMMEDIATE ACTIONS",
    "SHORT-TERM REMEDIATION",
    "LONG-TERM",
    "RECOMMENDED SECURITY TOOLS",
    "RELEVANT CVEs",
    "COMPLIANCE"
]


# ─────────────────────────────────────────
# EVALUATION FUNCTIONS
# ─────────────────────────────────────────

def check_completeness(workflow_text: str) -> dict:
    """Check if all required sections are present in the output."""
    results = {}
    score = 0
    for section in REQUIRED_SECTIONS:
        found = section.upper() in workflow_text.upper()
        results[section] = "true" if found else "false"
        if found:
            score += 1
    results["score"] = f"{score}/{len(REQUIRED_SECTIONS)}"
    results["percentage"] = round((score / len(REQUIRED_SECTIONS)) * 100)
    return results


def check_severity(workflow_text: str, expected: str) -> dict:
    """Check if AI correctly identified the severity level."""
    workflow_upper = workflow_text.upper()
    detected = "Unknown"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level in workflow_upper:
            detected = level.capitalize()
            break
    match = detected.upper() == expected.upper()
    return {
        "expected": expected,
        "detected": detected,
        "match": "true" if match else "false"
    }


def check_mitre(metadata: dict, expected_technique: str) -> dict:
    """Check if the correct MITRE ATT&CK technique was identified."""
    detected = metadata.get("mitre_technique", "")
    match = expected_technique in detected
    return {
        "expected": expected_technique,
        "detected": detected,
        "match": "true" if match else "false"
    }


def check_groundedness(workflow_text: str, metadata: dict) -> dict:
    """
    Check if the LLM actually used the real CVE data injected.
    Groundedness = AI references real CVE IDs in its output.
    """
    cves_found = metadata.get("cves_found", 0)
    cve_referenced = "CVE-" in workflow_text

    if cves_found == 0:
        return {
            "cves_fetched": 0,
            "cves_in_output": cve_referenced,
            "grounded": " No CVEs fetched to verify"
        }

    return {
        "cves_fetched": cves_found,
        "cves_in_output": cve_referenced,
        "grounded": "true" if cve_referenced else " LLM ignored fetched CVEs"
    }


def check_data_sources(metadata: dict) -> dict:
    """Check if all three data sources returned results."""
    return {
        "NVD":  "true" if metadata.get("cves_found", 0) > 0 else " No CVEs returned",
        "MITRE": "true" if metadata.get("mitre_technique") else " No technique mapped",
        "CISA": "true" if metadata.get("cisa_matches", 0) > 0 else " No CISA matches"
    }


# ─────────────────────────────────────────
# MAIN EVALUATION RUNNER
# ─────────────────────────────────────────

async def run_evaluation():
    print("\n" + "="*70)
    print("   AI SECURITY INCIDENT RESPONDER — EVALUATION REPORT")
    print("="*70)

    all_results = []
    total_latency = 0

    for test in TEST_CASES:
        print(f"\n{'─'*70}")
        print(f"TEST {test['id']}/10 — {test['incident'][:80]}...")
        print(f"{'─'*70}")

        # Time the full pipeline
        start = time.time()
        try:
            result = await generate_workflow(test["incident"])
            latency = round(time.time() - start, 2)
            total_latency += latency

            workflow = result.get("workflow", "")
            metadata = result.get("metadata", {})

            # Run all checks
            completeness  = check_completeness(workflow)
            severity      = check_severity(workflow, test["expected_severity"])
            mitre         = check_mitre(metadata, test["expected_mitre"])
            groundedness  = check_groundedness(workflow, metadata)
            data_sources  = check_data_sources(metadata)

            # Print results
            print(f"\n Latency:          {latency}s")
            print(f"\n COMPLETENESS:     {completeness['score']} ({completeness['percentage']}%)")
            for section, status in completeness.items():
                if section not in ["score", "percentage"]:
                    print(f"   {status} {section}")

            print(f"\n SEVERITY:         {severity['match']}  Expected: {severity['expected']} | Detected: {severity['detected']}")
            print(f" MITRE TECHNIQUE:  {mitre['match']}  Expected: {mitre['expected']} | Detected: {mitre['detected']}")
            print(f" GROUNDEDNESS:     {groundedness['grounded']}")
            print(f"  CVEs fetched: {groundedness['cves_fetched']} | Referenced in output: {groundedness['cves_in_output']}")

            print(f"\n DATA SOURCES:")
            for source, status in data_sources.items():
                print(f"   {source}: {status}")

            all_results.append({
                "test_id": test["id"],
                "latency": latency,
                "completeness_pct": completeness["percentage"],
                "severity_match": severity["match"] == "true",
                "mitre_match": mitre["match"] == "true",
                "grounded": "true" in str(groundedness["grounded"]),
                "nvd_hit": data_sources["NVD"] == "true",
                "cisa_hit": data_sources["CISA"] == "true"
            })

        except Exception as e:
            latency = round(time.time() - start, 2)
            print(f"ERROR after {latency}s: {str(e)}")
            all_results.append({
                "test_id": test["id"],
                "latency": latency,
                "completeness_pct": 0,
                "severity_match": False,
                "mitre_match": False,
                "grounded": False,
                "nvd_hit": False,
                "cisa_hit": False
            })

    # ─────────────────────────────────────────
    # SUMMARY REPORT
    # ─────────────────────────────────────────
    total = len(all_results)
    print(f"\n{'='*70}")
    print("   FINAL EVALUATION SUMMARY")
    print(f"{'='*70}\n")

    avg_completeness = round(sum(r["completeness_pct"] for r in all_results) / total)
    avg_latency      = round(total_latency / total, 2)
    severity_acc     = round(sum(r["severity_match"] for r in all_results) / total * 100)
    mitre_acc        = round(sum(r["mitre_match"] for r in all_results) / total * 100)
    groundedness_rate= round(sum(r["grounded"] for r in all_results) / total * 100)
    nvd_hit_rate     = round(sum(r["nvd_hit"] for r in all_results) / total * 100)
    cisa_hit_rate    = round(sum(r["cisa_hit"] for r in all_results) / total * 100)

    print(f"   Output Completeness:     {avg_completeness}%")
    print(f"   Severity Accuracy:        {severity_acc}%")
    print(f"   MITRE Mapping Accuracy:   {mitre_acc}%")
    print(f"   Groundedness Rate:        {groundedness_rate}%")
    print(f"   NVD Hit Rate:             {nvd_hit_rate}%")
    print(f"   CISA Hit Rate:            {cisa_hit_rate}%")
    print(f"   Average Latency:          {avg_latency}s")
    print(f"\n  Tests run: {total}/10")

    # Save results to JSON
    with open("evaluation_results.json", "w") as f:
        json.dump({
            "summary": {
                "completeness_pct": avg_completeness,
                "severity_accuracy_pct": severity_acc,
                "mitre_accuracy_pct": mitre_acc,
                "groundedness_pct": groundedness_rate,
                "nvd_hit_rate_pct": nvd_hit_rate,
                "cisa_hit_rate_pct": cisa_hit_rate,
                "avg_latency_seconds": avg_latency
            },
            "individual_results": all_results
        }, f, indent=2)

    print(f"\n  Full results saved to: evaluation_results.json")
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    asyncio.run(run_evaluation())
