# AI Security Incident Responder

> An AI-powered security incident response agent that queries real-world threat intelligence databases and auto-generates structured remediation workflows.

## What It Does

Give a description of any security incident — a ransomware attack, SQL injection, phishing campaign, DDoS, insider threat — and the app will:

1. **Search NIST NVD** for real CVEs matching the attack type
2. **Map to MITRE ATT&CK** framework — identifying the exact tactic and technique used
3. **Check CISA KEV** for actively exploited vulnerabilities related to the incident
4. **Feed all of this real data** into a LangChain agent running LLaMA3
5. **Generate a grounded remediation workflow** with severity assessment, immediate actions, short-term fixes, long-term prevention, tool recommendations, CVEs to patch, and compliance obligations

This is **RAG (Retrieval Augmented Generation)** applied to cybersecurity — the same architecture used by enterprise security platforms, built from scratch.

---

## Architecture

```
User Input (Security Incident Description)
              │
              ▼
    ┌─────────────────────┐
    │   FastAPI Backend   │  ← REST API endpoint /generate
    └─────────────────────┘
              │
              ▼
    ┌─────────────────────┐
    │     RAG Engine      │  ← Keyword extraction + parallel data fetch
    └─────────────────────┘
         │        │        │
         ▼        ▼        ▼
    ┌────────┐ ┌──────┐ ┌──────────┐
    │  NVD   │ │MITRE │ │ CISA KEV │   ← Real-world threat intelligence
    │  API   │ │ATT&CK│ │   Feed   │
    └────────┘ └──────┘ └──────────┘
         │        │        │
         └────────┴────────┘
                  │
                  ▼
    ┌─────────────────────────┐
    │   LangChain Agent       │  ← Enriched prompt with real CVE/MITRE data
    │   (LLaMA3 via Groq)     │
    └─────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────┐
    │  Structured Remediation │  ← Severity, actions, CVEs, compliance
    │       Workflow          │
    └─────────────────────────┘
```

---

## Real-World Data Sources

| Source | What It Provides | Why It Matters |
|--------|-----------------|----------------|
| **[NIST National Vulnerability Database](https://nvd.nist.gov/)** | 200,000+ real CVEs with CVSS severity scores | Grounds the AI response in actual known vulnerabilities |
| **[MITRE ATT&CK Framework](https://attack.mitre.org/)** | Adversary tactics, techniques, mitigations | Maps the incident to how real attackers operate |
| **[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** | Vulnerabilities actively exploited right now | Prioritises patching based on real-world threat activity |

All three are **free, official, government-maintained databases** — the same sources used by enterprise security teams at Fortune 500 companies.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **LLM** | LLaMA 3.3 70B via Groq API | Free, fast inference |
| **Agent Framework** | LangChain 0.2 | Prompt chaining and output parsing |
| **Backend** | FastAPI + Uvicorn | Async REST API |
| **Frontend** | HTML/CSS/Vanilla JS | Lightweight UI |
| **Containerisation** | Docker | Portable, reproducible deployment |
| **Deployment** | Render (free tier) | Cloud hosting |
| **Data Fetching** | httpx (async HTTP) | Non-blocking API calls to NVD/CISA |

---

## Project Structure

```
security-incident-responder/
├── app/
│   ├── data/
│   │   ├── __init__.py
│   │   ├── nvd.py          # NIST NVD CVE fetcher
│   │   ├── mitre.py        # MITRE ATT&CK technique mapper
│   │   └── cisa.py         # CISA KEV active exploit checker
│   ├── templates/
│   │   └── index.html      # Frontend UI
│   ├── __init__.py
│   ├── main.py             # FastAPI routes
│   ├── agent.py            # LangChain agent + RAG pipeline
│   └── rag.py              # Context builder (keyword extraction + data fetch)
├── Dockerfile
├── requirements.txt
├── .env                    # API keys (not committed)
├── .gitignore
└── README.md
```

---

## Running Locally with Docker

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- A free [Groq API key](https://console.groq.com)

### Steps

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/security-incident-responder.git
cd security-incident-responder
```

**2. Create your `.env` file**
```bash
# Create a .env file in the root directory
GROQ_API_KEY=your_groq_api_key_here
```

**3. Build the Docker image**
```bash
docker build -t security-incident-responder .
```

**4. Run the container**
```bash
docker run -p 8000:8000 --env-file .env security-incident-responder
```

**5. Open your browser**
```
http://localhost:8000
```

---

## Example Output

**Input:**
> At 3AM our entire hospital network was hit by ransomware. 47 Windows servers across 3 sites have files encrypted with .lockbit extension. Patient records system, MRI machines, and pharmacy systems are all offline. Initial vector appears to be an RDP port left open on a legacy Windows Server 2008 machine.

**Output includes:**

-  **Severity:** Critical
-  **MITRE Technique:** T1486 — Data Encrypted for Impact
-  **CVEs Found:** 4 real CVEs from NVD (e.g. CVE-2017-18362, Score: 9.8/10)
-  **CISA KEV Matches:** 2 actively exploited vulnerabilities
-  Immediate actions (isolate, snapshot, notify)
-  Short-term remediation (patch specific CVEs, scan, restore)
-  Long-term prevention (network segmentation, offline backups)
-  Recommended tools (Nessus, Veeam, Splunk, Suricata)
-  Compliance obligations (HIPAA, NIST, ISO 27001)

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI |
| `POST` | `/generate` | Generate remediation workflow |
| `GET` | `/health` | Health check + data source status |

**POST `/generate` — Request body:**
```json
{
  "incident": "Description of the security incident..."
}
```

**Response:**
```json
{
  "workflow": "Full remediation workflow text...",
  "metadata": {
    "keywords_detected": ["ransomware", "windows", "rdp"],
    "mitre_technique": "T1486 — Data Encrypted for Impact",
    "cves_found": 4,
    "cisa_matches": 2
  }
}
```

---

##  Evaluation Results

The system was evaluated across 10 real-world security incident test cases covering ransomware, SQL injection, phishing, DDoS, insider threats, supply chain attacks, brute force, credential exposure, RCE, and cloud misconfiguration.

### Evaluation Metrics

| Metric | Score | Description |
|--------|-------|-------------|
| **Output Completeness** | 100% | All 8 required sections present in every response |
| **Groundedness** | 100% | LLM consistently referenced real CVE IDs from NVD |
| **NVD Hit Rate** | 100% | Real CVEs successfully fetched for all incident types |
| **CISA KEV Hit Rate** | 90% | Active exploit matches found for 9/10 incident types |
| **MITRE Mapping Accuracy** | 80% | Correct ATT&CK technique identified in 8/10 cases |
| **Severity Accuracy** | 70-80% | Correct severity classification (note: inherently subjective) |
| **Average Latency** | ~4.2s | Full pipeline: data fetch + LLM generation |

### Evaluation Methodology

Each test case was evaluated against five dimensions:

- **Completeness** — Does the output contain all required sections (incident summary, severity, immediate actions, short-term remediation, long-term prevention, tools, CVEs, compliance)?
- **Groundedness / Faithfulness** — Does the LLM actually reference the real CVE IDs fetched from NVD, rather than hallucinating its own?
- **MITRE Accuracy** — Does the RAG pipeline correctly map the incident to the right ATT&CK technique ID?
- **Severity Accuracy** — Does the AI classify severity (Critical/High/Medium/Low) correctly based on defined criteria?
- **Data Source Hit Rate** — How reliably does each data source (NVD, MITRE, CISA) return relevant results?

This evaluation framework aligns with the [RAGAS](https://docs.ragas.io/) standard for RAG system evaluation, measuring faithfulness, answer relevancy, context precision, and context recall.

### Known Limitations & Improvement Paths

- **Severity subjectivity** — Severity classification is inherently contextual. The LLM's reasoning was defensible in most disagreements (e.g. classifying a SQL injection with 9.8 CVSS CVEs as Critical rather than High).
- **Keyword-based MITRE mapping** — Current implementation uses keyword matching. Upgrading to semantic vector search (ChromaDB + embeddings) would improve accuracy on ambiguous incidents.
- **CISA KEV gaps** — CISA catalog does not cover all vulnerability types equally; phishing-related entries are sparse by nature.


