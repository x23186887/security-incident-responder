from langchain_groq import ChatGroq
from langchain.prompts import ChatPromptTemplate
from langchain.schema.output_parser import StrOutputParser
from app.rag import build_context
import os
from dotenv import load_dotenv

load_dotenv()


def get_llm():
    return ChatGroq(
        api_key=os.getenv("GROQ_API_KEY"),
        model_name="llama-3.3-70b-versatile",
        temperature=0.3
    )


async def generate_workflow(incident_description: str) -> dict:
    """
    Full RAG pipeline:
    1. Fetch real CVE, MITRE, CISA data
    2. Inject into prompt as context
    3. LLM generates grounded remediation workflow
    """

    # Step 1 — Fetch real world context
    print("[Agent] Fetching real-world threat intelligence...")
    context = await build_context(incident_description)

    # Step 2 — Build enriched prompt with real data injected
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a senior cybersecurity incident response expert at a top MSSP.
You have been given REAL threat intelligence data from:
- NIST National Vulnerability Database (NVD)
- MITRE ATT&CK Framework
- CISA Known Exploited Vulnerabilities Catalog

Use this real data to generate a precise, actionable remediation workflow.
Always reference the real CVE IDs and MITRE technique IDs provided.
Be specific, technical, and prioritized. Format your response exactly as shown below.

---

{cve_context}

{mitre_context}

{cisa_context}

---

Based on the above real-world threat intelligence, generate the remediation workflow."""),

        ("human", """SECURITY INCIDENT REPORTED:
{incident}

Generate a complete remediation workflow using the real CVE and MITRE data provided above.
Format your response EXACTLY like this:

 INCIDENT SUMMARY
[2-3 sentence summary of what happened and what attack vector was used]

 SEVERITY ASSESSMENT
Severity: [Critical/High/Medium/Low]
MITRE Technique: {mitre_technique_id} — {mitre_technique_name}
Reasoning: [Why this severity based on real CVE scores above]

 IMMEDIATE ACTIONS (Within 1 hour)
1. [Specific action]
2. [Specific action]
3. [Specific action]

 SHORT-TERM REMEDIATION (Within 24 hours)
1. [Step with specific tool/command where relevant]
2. [Step]
3. [Step]
4. [Step]

 LONG-TERM PREVENTIVE MEASURES
1. [Measure]
2. [Measure]
3. [Measure]
 RECOMMENDED SECURITY TOOLS
[List 4-5 specific tools relevant to this incident type]

 RELEVANT CVEs TO PATCH
[Reference the real CVE IDs provided above with their severity scores]

 COMPLIANCE & REPORTING
[Note relevant compliance frameworks — NIST, ISO 27001, GDPR etc. and reporting obligations]""")
    ])

    # Step 3 — Run through LLM
    chain = prompt | get_llm() | StrOutputParser()

    print("[Agent] Generating workflow with real-world context...")
    result = chain.invoke({
        "incident": incident_description,
        "cve_context": context["cve_context"],
        "mitre_context": context["mitre_context"],
        "cisa_context": context["cisa_context"],
        "mitre_technique_id": context["mitre_technique_id"],
        "mitre_technique_name": context["mitre_technique_name"]
    })

    return {
        "workflow": result,
        "metadata": {
            "keywords_detected": context["keywords_found"],
            "mitre_technique": f"{context['mitre_technique_id']} — {context['mitre_technique_name']}",
            "cves_found": len(context["raw_cves"]),
            "cisa_matches": len(context["raw_cisa"])
        }
    }