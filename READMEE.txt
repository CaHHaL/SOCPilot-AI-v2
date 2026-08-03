# SOCPilot AI

**SOCPilot AI** is an AI-powered Security Operations Center (SOC) investigation assistant built to autonomously triage, enrich, and analyse security alerts. 

By leveraging **LangGraph**, **LangChain**, and **Retrieval-Augmented Generation (RAG)**, it behaves like a junior SOC analyst: it parses alerts, identifies Indicators of Compromise (IoCs), queries threat intelligence APIs, retrieves MITRE ATT&CK techniques, and synthesises all evidence into a professional investigation report.

## 🚀 Features

- **Stateful Workflows (LangGraph)**: Orchestrates a multi-node pipeline from alert ingestion to final report generation.
- **Dynamic Tool Routing**: Automatically decides which threat intelligence tools to query based on extracted IoCs (e.g., IPs trigger AbuseIPDB, file hashes trigger VirusTotal).
- **Retrieval-Augmented Generation (RAG)**: Uses a `MultiQueryRetriever` backed by ChromaDB and HuggingFace embeddings to inject relevant cybersecurity knowledge into the LLM's reasoning process.
- **Dual-Memory System**:
  - **Short-Term Memory**: `MemorySaver` provides continuity within a single investigation session (`thread_id`).
  - **Long-Term Memory**: Stores completed incidents in ChromaDB to retrieve semantically similar historical alerts in future investigations.
- **Deterministic & Fallback Capabilities**: 
  - Dual LLM/regex IoC extraction ensures no indicators are missed.
  - Fully functional offline/demo mode if external API keys (Groq, VirusTotal, AbuseIPDB) are not provided.
- **Structured Pydantic Outputs**: Guarantees type-safe generation of the final `SOCReport` (JSON and Markdown formats).

## 🏗️ Technology Stack

| Category | Technology |
|----------|------------|
| Programming Language | Python 3.11+ |
| AI Framework | LangChain |
| Agent Workflow | LangGraph |
| Large Language Model | Groq (Llama 3.x / Mixtral / Gemma Models) |
| Vector Database | ChromaDB |
| Embedding Model | HuggingFace Sentence Transformers (all-MiniLM-L6-v2) |
| Retrieval | MultiQueryRetriever (LangChain) |
| Long-Term Memory | ChromaDB |
| Short-Term Memory | LangGraph MemorySaver |
| Data Validation | Pydantic v2 |
| Configuration Management | python-dotenv, pydantic-settings |
| HTTP Client | Requests, HTTPX |
| Report Generation | Jinja2 Templates |
| CLI Interface | Rich |
| Serialization | JSON |
| Environment Management | .env |
| Threat Intelligence APIs | VirusTotal API, AbuseIPDB API |
| Security Knowledge Base | MITRE ATT&CK Framework |
| Vulnerability Database | National Vulnerability Database (NVD) |
| Development Paradigm | Agentic AI |
| AI Technique | Retrieval-Augmented Generation (RAG) |

## 📦 Major Libraries Used

| Library | Purpose |
|----------|---------|
| LangChain | LLM orchestration and prompt management |
| LangGraph | Stateful agent workflow orchestration |
| langchain-groq | Groq LLM integration |
| langchain-chroma | Chroma vector database integration |
| langchain-community | Community integrations and retrievers |
| langchain-huggingface | HuggingFace embedding support |
| ChromaDB | Persistent vector database |
| sentence-transformers | Embedding generation |
| Groq SDK | Access to Groq inference API |
| Pydantic | Structured output validation |
| Jinja2 | Markdown report templating |
| Requests | REST API communication |
| HTTPX | Async HTTP support |
| Rich | Professional CLI formatting |
| python-dotenv | Environment variable loading |

## 📂 Project Structure

```text
SOC_Agent/
│
├── chroma_db/                     # Persistent Chroma vector database
├── reports/                       # Generated investigation reports
│
├── socpilot/
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py            # Environment & configuration
│   │
│   ├── graph/
│   │   ├── __init__.py
│   │   └── builder.py             # LangGraph workflow builder
│   │
│   ├── memory/
│   │   ├── __init__.py
│   │   ├── short_term.py          # LangGraph MemorySaver
│   │   └── long_term.py           # ChromaDB memory
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── graph_state.py         # Shared workflow state
│   │   ├── ioc_models.py          # IoC schemas
│   │   └── report_models.py       # SOCReport schemas
│   │
│   ├── nodes/
│   │   ├── __init__.py
│   │   ├── alert_ingest.py
│   │   ├── memory_node.py
│   │   ├── rag_node.py
│   │   ├── tool_router.py
│   │   ├── reasoning_node.py
│   │   └── report_node.py
│   │
│   ├── prompts/
│   │   ├── __init__.py
│   │   ├── extraction_prompt.py
│   │   └── reasoning_prompt.py
│   │
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── retriever.py
│   │   └── seed_documents.py
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   └── templates/
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── abuse_ipdb.py
│   │   ├── cve_lookup.py
│   │   ├── sigma_rules.py
│   │   └── virustotal.py
│   │
│   └── __init__.py
│
├── .env
├── .example.env
├── .gitignore
├── main.py
├── setup_rag.py
├── project_documentation.md
├── README.md
└── requirements.txt
```

## 🛠️ Architecture

```
User provides alert text
         │
         ▼
┌─────────────────────┐
│  ALERT INGEST NODE  │  ← LLM + Regex extracts IoCs
└──────────┬──────────┘
           ▼
┌──────────────────────────────────────────────┐
│            PARALLEL ENRICHMENT PHASE         │
│  ┌───────────────┐   ┌──────────────────┐    │
│  │  MEMORY NODE  │   │    RAG NODE      │    │
│  └───────┬───────┘   └────────┬─────────┘    │
└──────────┼────────────────────┼──────────────┘
           ▼                    ▼
┌──────────────────────────────────────────────┐
│           CONDITIONAL TOOL ROUTING           │
│  IP found?  ──────────► AbuseIPDB Node       │
│  Hash found? ─────────► VirusTotal Node      │
│  CVE found?  ─────────► CVE Lookup Node      │
│  Suspicious process? ─► MITRE / Sigma Nodes  │
└──────────────────────────────────────────────┘
           ▼
┌─────────────────────┐
│   REASONING NODE    │  ← LLM synthesises evidence → SOCReport
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│    REPORT NODE      │  ← Writes .md/.json, stores incident to ChromaDB
└─────────────────────┘
```

## ⚙️ Installation

1. Clone this repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Open `.env` and add your API keys. **Groq** (`GROQ_API_KEY`) is highly recommended for the LLM reasoning phase.

4. Seed the RAG Knowledge Base (Run this once):
   ```bash
   python setup_rag.py
   ```

## 💻 Usage

Run the agent via the CLI, passing an alert inline or via a file.

**Investigate an inline alert:**
```bash
python main.py --alert "Suspicious PowerShell execution on HR-PC-21 by john. Source IP: 185.120.33.8. Command: powershell -enc SQBmAC..."
```

**Investigate an alert from a file:**
```bash
python main.py --file my_alert.txt
```

**Session Continuity (Short-Term Memory):**
If an investigation requires multiple turns, use the same `--thread-id`:
```bash
python main.py --thread-id inc-101 --alert "Initial alert..."
python main.py --thread-id inc-101 --alert "The user also downloaded a file with hash 44d88612fea8a8f36de82e1278abb02f"
```

## 📁 Output

Generated reports are saved in the `reports/` directory as both:
- `RPT-*.md`: Beautifully formatted Markdown report (rendered via Jinja2).
- `RPT-*.json`: Machine-readable structured JSON report.

## 🧠 AI Investigation Workflow

SOCPilot AI follows an autonomous multi-agent investigation pipeline.

1. Receive raw SOC alert.
2. Parse alert using LLM.
3. Perform regex fallback extraction.
4. Identify IoCs.
5. Retrieve similar incidents.
6. Search cybersecurity knowledge base.
7. Route to appropriate intelligence tools.
8. Aggregate intelligence.
9. Generate reasoning.
10. Produce structured report.
11. Store investigation for future retrieval.

Each investigation is represented as a stateful LangGraph workflow where every node contributes evidence before passing the updated state to the next node.

## 📚 Retrieval-Augmented Generation (RAG)

Instead of relying solely on the LLM's internal knowledge, SOCPilot AI augments every investigation using a cybersecurity knowledge base.

The RAG pipeline performs:

- MultiQuery Retrieval
- Semantic Search
- Context Ranking
- Similar Incident Retrieval
- Knowledge Injection

Knowledge Sources include:

- MITRE ATT&CK
- Sigma Rules
- Detection Engineering Notes
- Previous Investigations
- CVE Knowledge
- Internal Documentation

This significantly reduces hallucination while improving explanation quality.

## 🧠 Memory Architecture

SOCPilot AI uses two independent memory systems.

### Short-Term Memory

Maintains conversation context during an active investigation.

Technology:
- LangGraph MemorySaver

Purpose:
- Multi-turn investigations
- Follow-up questions
- Analyst interaction

---

### Long-Term Memory

Stores completed investigations inside ChromaDB.

Purpose:

- Retrieve similar incidents
- Improve investigation speed
- Build organizational knowledge
- Incident correlation

Stored Information:

- Alert Summary
- IoCs
- Threat Classification
- Final Report
- Severity

## 🔀 Dynamic Tool Routing

The agent automatically decides which external tools should be executed.

| Detected Indicator | Tool |
|-------------------|------|
| IPv4 Address | AbuseIPDB |
| File Hash | VirusTotal |
| CVE ID | NVD Lookup |
| Windows Process | MITRE ATT&CK |
| Command Line | Sigma Rules |
| Domain | DNS Intelligence |
| URL | Reputation Lookup |

Only relevant APIs are queried, minimizing unnecessary requests and improving efficiency.

## 📑 Generated Investigation Report

Each report contains:

- Executive Summary
- Incident Severity
- Alert Overview
- Extracted IoCs
- Threat Intelligence Results
- MITRE ATT&CK Mapping
- CVE Information
- Risk Assessment
- Analyst Recommendations
- Detection Opportunities
- Response Actions
- References

Reports are generated in:

- Markdown
- JSON

This enables both analyst readability and machine integration.

## ⚙️ Engineering Decisions

Several design choices were made to improve reliability.

### Why LangGraph?

- Stateful execution
- Deterministic workflows
- Node-based architecture
- Easy debugging

### Why ChromaDB?

- Lightweight
- Local storage
- Fast semantic search

### Why Groq?

- Extremely fast inference
- Low latency
- High-quality reasoning

### Why Pydantic?

- Type safety
- Structured outputs
- Validation

### Why MultiQueryRetriever?

Instead of searching using one embedding, multiple search queries are generated to maximize document recall.

## 🔒 Security Considerations

SOCPilot AI follows secure engineering practices.

- Environment variables for API keys
- No hardcoded credentials
- Offline mode support
- Local vector database
- Structured outputs
- Input validation
- Type-safe models
- Deterministic workflow execution

## 📌 Example Investigation

### Input Alert

```
PowerShell executed with encoded command.

Host: HR-PC-12

User: john

Source IP: 185.220.101.34

SHA256:
44d88612fea8a8f36de82e1278abb02f
```

### Agent Actions

✅ Extract IoCs

✅ Query VirusTotal

✅ Query AbuseIPDB

✅ Retrieve MITRE ATT&CK

✅ Search Similar Incidents

✅ Generate SOC Report

### Output

```
Severity: HIGH

Threat:
Credential Access

MITRE:
T1059
T1027

Confidence:
96%

Recommendation:

- Isolate endpoint
- Block source IP
- Reset credentials
- Hunt similar activity
```

## 🌟 Why SOCPilot AI?

Modern Security Operations Centers receive thousands of alerts daily. Manual investigation is repetitive, time-consuming, and susceptible to analyst fatigue.

SOCPilot AI acts as an intelligent investigation assistant that automates repetitive enrichment tasks while preserving human oversight. By combining LLM reasoning, retrieval-augmented generation, threat intelligence APIs, and historical incident memory, it reduces investigation time and improves consistency.

The project demonstrates how Agentic AI can augment SOC analysts rather than replace them, enabling faster triage, improved contextual understanding, and standardized reporting.

## 📜 License

This project is developed for educational and research purposes as part of a university capstone project.

The software is intended to demonstrate the application of Agentic AI, Retrieval-Augmented Generation (RAG), and cybersecurity automation in Security Operations Centers.

Commercial use may require compliance with the licenses of third-party APIs and libraries.
