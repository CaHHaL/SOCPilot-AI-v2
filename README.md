<div align="center">

# 🛡️ SOCPilot AI

### Agentic AI-Powered Security Operations Center (SOC) Investigation Platform

**Real-Time SIEM Integration • LangGraph • RAG • Long-Term Memory • Threat Intelligence • Automated Incident Response**

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![LangGraph](https://img.shields.io/badge/LangGraph-Agentic%20Workflow-success)
![FastAPI](https://img.shields.io/badge/FastAPI-Webhooks-009688)
![Docker](https://img.shields.io/badge/Docker-Wazuh-blue)
![Dashboard](https://img.shields.io/badge/Dashboard-Live%20UI-00d4ff)
![License](https://img.shields.io/badge/License-MIT-green)

---

*An autonomous AI SOC Analyst capable of receiving live SIEM alerts, investigating incidents using LLM reasoning, enriching Indicators of Compromise (IoCs), retrieving historical cybersecurity knowledge, and generating professional incident response reports automatically.*

</div>

---

# 📖 Overview

Modern Security Operation Centers (SOCs) generate thousands of security alerts every day. Analysts spend significant time manually triaging alerts, investigating Indicators of Compromise (IoCs), correlating previous incidents, collecting threat intelligence, and writing incident reports.

**SOCPilot AI** automates this entire workflow.

Instead of requiring an analyst to manually investigate every alert, SOCPilot AI receives alerts directly from a SIEM platform, performs autonomous AI reasoning using LangGraph, enriches threat intelligence from multiple sources, retrieves relevant cybersecurity knowledge using Retrieval-Augmented Generation (RAG), remembers previous investigations through long-term memory, and produces a professional incident report within seconds.

The platform is designed to simulate the workflow of a modern SOC analyst while remaining modular, extensible, and suitable for future integration with enterprise SIEM platforms.

---

# 🚀 Key Features

## 🤖 Agentic AI Investigation

Unlike traditional chatbot-based assistants, SOCPilot AI uses a multi-node LangGraph workflow that reasons step-by-step through each investigation.

The investigation pipeline includes:

- Alert Understanding
- IOC Extraction
- Threat Intelligence Enrichment
- MITRE ATT&CK Mapping
- CVE Lookup
- Historical Incident Retrieval
- AI Reasoning
- Incident Report Generation

---

## ⚡ Real-Time SIEM Integration (Version 2)

SOCPilot AI no longer requires manual alert input.

It automatically receives live security alerts from Wazuh SIEM using webhook integrations.

Current implementation:

- ✅ Windows Wazuh Agent
- ✅ Wazuh Manager
- ✅ Docker Deployment
- ✅ FastAPI Webhook Server
- ✅ Automatic Alert Parsing
- ✅ Background Investigation
- ✅ Markdown Report Generation

Future SIEM support:

- Microsoft Sentinel
- Splunk Enterprise
- Elastic Security
- IBM QRadar
- Google Chronicle

---

## 🧠 Long-Term Memory

SOCPilot remembers previous investigations.

Every completed investigation is embedded using HuggingFace Embeddings and stored in ChromaDB.

Future investigations retrieve semantically similar incidents, allowing the AI to learn from historical cases.

Example:

```
Previous Investigation

↓

"PowerShell encoded command"

↓

Memory Retrieval

↓

Current Investigation

↓

AI correlates previous findings
```

---

## 📚 Retrieval-Augmented Generation (RAG)

SOCPilot combines LLM reasoning with cybersecurity knowledge.

Supported sources include:

- MITRE ATT&CK
- NVD
- Security Documentation
- Internal Playbooks
- Uploaded Documentation

The AI retrieves only the most relevant information before reasoning, reducing hallucinations and improving technical accuracy.

---

## 🌐 Threat Intelligence Enrichment

Automatically enriches Indicators of Compromise using external intelligence sources.

Current integrations include:

- VirusTotal
- AbuseIPDB
- NVD (National Vulnerability Database)

Future integrations:

- AlienVault OTX
- Shodan
- GreyNoise
- URLHaus
- CISA KEV

---

## 📝 Automated Incident Reports

Every investigation generates a professional Markdown report containing:

- Executive Summary
- Severity Assessment
- Timeline
- Extracted IoCs
- MITRE ATT&CK Techniques
- Threat Intelligence Findings
- AI Investigation Notes
- Recommended Actions
- References

Reports are saved automatically inside:

```
reports/
```

---

# 🏗️ System Architecture

```
                    Windows Endpoint
                           │
                           │
                     Wazuh Agent
                           │
                           ▼
                 Wazuh Manager (Docker)
                           │
                           │
                 custom-socpilot Integration
                           │
                           ▼
                  FastAPI Webhook Server
                           │
                           ▼
                  SIEM Adapter Layer
                           │
                           ▼
                LangGraph Investigation
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
 IOC Extraction   RAG Search   Threat Intelligence
      │              │              │
      └──────────────┼──────────────┘
                     ▼
              AI Investigation
                     │
                     ▼
          Markdown Incident Report
```

---

# 🔄 Investigation Pipeline

```
Windows Event

↓

Wazuh Agent

↓

Wazuh Manager

↓

Integration Script

↓

FastAPI Webhook

↓

SOCPilot AI

↓

Alert Normalization

↓

IOC Extraction

↓

Threat Intelligence

↓

MITRE Mapping

↓

Memory Retrieval

↓

LLM Reasoning

↓

Incident Report
```

---

# ⭐ What's New in Version 2

Version 2 transforms SOCPilot from a standalone investigation assistant into a real-time SOC automation platform.

### New Features

✅ Live Wazuh SIEM Integration

✅ Windows Endpoint Monitoring

✅ Automatic Alert Ingestion

✅ FastAPI Webhook Server

✅ Background Investigation

✅ Modular SIEM Adapter Framework

✅ Automatic Report Generation

✅ Docker-Based Deployment

Previously:

```
Manual Alert

↓

CLI

↓

Investigation
```

Now:

```
Windows Host

↓

Wazuh

↓

Webhook

↓

SOCPilot AI

↓

Automatic Investigation
```

---

# 🛠 Technology Stack

## AI & LLM

- LangGraph
- LangChain
- OpenAI / Groq Compatible LLMs
- HuggingFace Embeddings

---

## Backend

- Python
- FastAPI
- AsyncIO
- Uvicorn

---

## Memory

- ChromaDB
- Vector Embeddings
- Semantic Search

---

## Threat Intelligence

- VirusTotal API
- AbuseIPDB API
- NVD API

---

## SIEM

- Wazuh Manager
- Wazuh Windows Agent
- FastAPI Webhooks

---

## Deployment

- Docker
- Docker Compose

---

## Report Generation

- Markdown
- JSON
- Structured Investigation Reports

---

# 📂 Project Structure

```
SOC_Agent_V2/
│
├── socpilot/                    ← Core AI investigation engine
│   ├── graph/
│   │   ├── builder.py
│   │   └── state.py
│   ├── nodes/
│   ├── rag/
│   ├── memory/
│   ├── tools/
│   ├── config/
│   ├── models/
│   └── reports/
│
├── integrations/
│   ├── base.py
│   ├── registry.py
│   └── wazuh.py
│
├── dashboard/                   ← NEW: Web UI Dashboard
│   ├── api_server.py            ← FastAPI dashboard API (port 8080)
│   ├── start_dashboard.py       ← One-click launcher
│   ├── requirements-dashboard.txt
│   └── static/
│       ├── index.html
│       ├── css/styles.css
│       └── js/
│           ├── app.js
│           ├── dashboard.js
│           ├── reports.js
│           ├── report-detail.js
│           └── notifications.js
│
├── reports/                     ← Auto-generated investigation reports
│
├── chroma_db/                   ← Long-term vector memory
│
├── docs/
│
├── siem_server.py               ← SIEM webhook server (port 8000)
├── main.py
├── setup_rag.py
├── requirements.txt
└── README.md
```

---

# 🎯 Project Goals

The primary objective of SOCPilot AI is to reduce the workload of SOC analysts by automating repetitive investigation tasks while maintaining explainability and structured reporting.

The project focuses on:

- AI-assisted incident response
- Automated SOC investigations
- Threat intelligence enrichment
- Long-term cybersecurity memory
- Retrieval-Augmented Generation (RAG)
- Real-time SIEM integrations
- Modular multi-SIEM architecture
- Professional incident reporting

---

# ⚙️ Installation

## Prerequisites

Before installing SOCPilot AI, ensure the following software is available on your system.

### Operating System

- Windows 10 / 11
- Ubuntu 22.04+
- Kali Linux
- macOS (Experimental)

---

### Python

Python 3.11 or later is recommended.

Verify installation:

```bash
python --version
```

---

### Docker

Docker Desktop (Windows)

or

Docker Engine + Docker Compose (Linux)

Verify installation:

```bash
docker --version
docker compose version
```

---

### Git

```bash
git --version
```

---

# 📥 Clone Repository

```bash
git clone https://github.com/<your-username>/SOCPilot-AI.git

cd SOCPilot-AI
```

---

# 📦 Install Dependencies

Create Virtual Environment

Windows

```powershell
python -m venv venv

.\venv\Scripts\activate
```

Linux

```bash
python3 -m venv venv

source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# 🔑 Environment Variables

Create a `.env` file.

Example

```env
###########################################
# LLM
###########################################

GROQ_API_KEY=YOUR_GROQ_API_KEY

###########################################
# Threat Intelligence
###########################################

VT_API_KEY=YOUR_VIRUSTOTAL_API_KEY

ABUSEIPDB_API_KEY=YOUR_ABUSEIPDB_API_KEY

NVD_API_KEY=YOUR_NVD_API_KEY

###########################################
# Memory
###########################################

CHROMA_DB=./memory/chroma_db

###########################################
# Webhook
###########################################

WAZUH_WEBHOOK_TOKEN=high_level_security_token

WAZUH_MIN_ALERT_LEVEL=5
```

---

# 🛡 Wazuh Deployment

SOCPilot AI uses Wazuh as its real-time SIEM platform.

Deployment is based on Docker Compose.

Project structure:

```
wazuh/

└── wazuh-docker/

    └── single-node/

        ├── config/
        ├── integrations/
        ├── docker-compose.yml
```

---

## Start Wazuh

Navigate to

```text
wazuh/wazuh-docker/single-node
```

Start the stack

```bash
docker compose up -d
```

Verify

```bash
docker ps
```

Expected containers

```
wazuh.manager

wazuh.dashboard

wazuh.indexer
```

All containers should display

```
STATUS = Up
```

---

## Access Dashboard

Open browser

```
https://localhost
```

Default credentials

```
Username

admin

Password

SecretPassword
```

(Replace if customized.)

---

# 🖥 Windows Agent Installation

Download the latest Wazuh Windows Agent.

Install

```powershell
Invoke-WebRequest `
-Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi `
-OutFile $env:TEMP\wazuh-agent.msi

msiexec.exe /i `
$env:TEMP\wazuh-agent.msi `
/q `
WAZUH_MANAGER="YOUR_MANAGER_IP" `
WAZUH_AGENT_NAME="HOSTNAME"
```

Example

```powershell
WAZUH_MANAGER=10.36.65.62

WAZUH_AGENT_NAME=CAHAL-WIN11
```

---

## Verify Agent

Inside Wazuh Dashboard

```
Endpoints

↓

Agents
```

Expected

```
Status

Active
```

---

# 🔌 SOCPilot Webhook

SOCPilot exposes a webhook endpoint for SIEM integrations.

Default endpoint

```
POST

/webhook/wazuh
```

Authentication

```
Bearer Token
```

Configured through

```
WAZUH_WEBHOOK_TOKEN
```

---

# ▶ Running SOCPilot

Activate virtual environment

Windows

```powershell
.\venv\Scripts\activate
```

Linux

```bash
source venv/bin/activate
```

Start server

```bash
uvicorn siem_server:app --host 0.0.0.0 --port 8000
```

Expected output

```
Application startup complete

Running on

http://0.0.0.0:8000
```

Leave this terminal running.

---

# 🧪 Manual Investigation Mode

SOCPilot still supports manual investigations.

Example

```bash
python main.py \
--alert "Suspicious PowerShell execution from HR-PC-21"
```

This bypasses SIEM integration and directly starts an investigation.

---

# ⚡ Automatic Investigation Mode

Version 2 introduces fully automated investigations.

Workflow

```
Windows Event

↓

Windows Agent

↓

Wazuh Manager

↓

custom-socpilot Integration

↓

FastAPI Webhook

↓

SOCPilot AI

↓

LangGraph Investigation

↓

Markdown Report
```

No manual alert submission is required.

---

# 📄 Generated Reports

Reports are automatically stored inside

```
reports/
```

Example

```
reports/

├── RPT-20230916-1234_20260801_061407.json
├── RPT-20230916-1234_20260801_061407.md
├── RPT-20240416-1234_20260730_071056.json
├── RPT-20240416-1234_20260730_071056.md
```

Each report is saved in **two formats** simultaneously:

| Format | Contents |
|--------|----------|
| `.json` | Full structured data (IOCs, MITRE, verdicts, scores) — consumed by the Dashboard |
| `.md` | Human-readable Markdown report with formatted tables and MITRE links |

Each report contains

- Executive Summary
- Severity Assessment (CRITICAL / HIGH / MEDIUM / LOW)
- Risk Score (0–100)
- Confidence Score
- Indicators of Compromise
- MITRE ATT&CK Mapping
- Sigma Rule Detections
- Threat Intelligence
- AI Analysis & Reasoning Chain
- Recommended Actions
- Escalation Flag
- False Positive Likelihood

---

# 🖥️ SOCPilot AI Dashboard

Version 2 ships with a **production-grade web dashboard** that displays all generated reports with rich visualizations, live notifications, and full-text search — completely isolated from the investigation backend.

> **Port:** `8080` (SIEM webhook server stays on `8000` — no conflicts)

---

## ✨ Dashboard Features

### Overview Page
- Live stat cards: Total reports, Critical / High / Medium / Low counts, Escalation count, Average Risk Score, Malicious IOC count
- **Severity Trend Chart** — reports over time, color-coded by severity
- **Severity Donut Chart** — at-a-glance distribution
- **MITRE ATT&CK Heatmap** — technique frequency, links to attack.mitre.org
- **Threat Intel Verdict Chart** — malicious vs clean ratio
- Recent investigations panel

### Reports Page
- **Full-text search** across Report ID, summary, thread ID, severity
- **Severity filter pills** — All / Critical / High / Medium / Low / Escalation Required
- **Multi-sort** — newest, oldest, highest risk, lowest risk, by severity
- Animated report cards with IOC count, MITRE count, Sigma count, risk pill, confidence, FP likelihood

### Report Detail Page (6 tabs)

| Tab | Contents |
|-----|----------|
| **Summary** | At-a-glance stats, RAG context, recommended actions checklist |
| **IOCs** | Color-coded IOC chips by type (IP, domain, hostname, hash, process) — click to copy |
| **MITRE ATT&CK** | Technique cards linked to attack.mitre.org, tactic color coding |
| **Sigma Rules** | Collapsible cards with severity badge, tags, syntax-highlighted detection logic |
| **Threat Intel** | Full verdict table (MALICIOUS/CLEAN/SUSPICIOUS) with confidence & details |
| **Reasoning** | AI analyst reasoning chain + RAG context used |

Additional detail view features:
- Animated score meters (Risk Score, Confidence, Intel, MITRE)
- Download JSON button
- View Markdown button (renders in new tab with styled HTML)
- Back navigation

### Statistics Page
- Risk score timeline (line chart, color-coded points)
- Severity breakdown bar chart
- Top MITRE tactics horizontal bar chart
- False positive likelihood pie chart
- Full sortable report summary table

### 🔔 Live Notifications
When SOCPilot AI generates a new report:
1. The dashboard detects the new file within **3 seconds**
2. A **severity-colored toast notification** pops up (bottom-right)
3. The notification drawer updates with the new report details
4. The badge counter increments
5. If you're on the Overview or Reports page, the data **auto-refreshes**

---

## 🚀 Starting the Dashboard

**Option A — One-click launcher (opens browser automatically):**

```powershell
python dashboard/start_dashboard.py
```

**Option B — Direct uvicorn:**

```powershell
python -m uvicorn dashboard.api_server:app --host 0.0.0.0 --port 8080
```

Then open: **http://localhost:8080**

---

## 📋 Dashboard API Endpoints

The dashboard exposes a read-only REST API (no writes to your investigation data):

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Server health check + report count |
| `GET` | `/api/reports` | List all reports (metadata only) |
| `GET` | `/api/reports/{filename}` | Full JSON for a single report |
| `GET` | `/api/reports/{filename}/markdown` | Markdown content for a report |
| `GET` | `/api/stats` | Aggregated statistics across all reports |
| `GET` | `/api/stream` | SSE endpoint for live new-report notifications |
| `GET` | `/api/docs` | Interactive API documentation (Swagger UI) |

---

## 🔒 Dashboard Isolation

The dashboard is **100% read-only** and **completely isolated** from the investigation backend:

- Runs as a separate process on a different port
- Never imports from `socpilot/`, `integrations/`, or `siem_server.py`
- Only reads `.json` and `.md` files from `reports/`
- Stopping the dashboard does not affect any running investigations

---

# 🔍 Supported SIEM Platforms

| Platform | Status |
|-----------|--------|
| Wazuh | ✅ Supported |
| Splunk | 🚧 Planned |
| Microsoft Sentinel | 🚧 Planned |
| Elastic Security | 🚧 Planned |
| IBM QRadar | 🚧 Planned |
| Google Chronicle | 🚧 Planned |

---

# 🔧 Configuration

Minimum Alert Level

```env
WAZUH_MIN_ALERT_LEVEL=5
```

Webhook Token

```env
WAZUH_WEBHOOK_TOKEN=high_level_security_token
```

Webhook URL

```
http://localhost:8000/webhook/wazuh
```

---

# ▶ Starting the Complete Platform

## Step 1

Start Wazuh

```bash
docker compose up -d
```

---

## Step 2

Activate Python Environment

```bash
source venv/bin/activate
```

or

```powershell
.\venv\Scripts\activate
```

---

## Step 3

Start the SOCPilot SIEM webhook server (port 8000)

```bash
uvicorn siem_server:app --host 0.0.0.0 --port 8000
```

---

## Step 4 — Start the Dashboard (NEW)

In a **second terminal**, launch the web dashboard (port 8080)

```powershell
python dashboard/start_dashboard.py
```

or

```powershell
python -m uvicorn dashboard.api_server:app --host 0.0.0.0 --port 8080
```

Open your browser at **http://localhost:8080** to view the SOCPilot AI Dashboard.

---

## Step 5

Generate a Windows security event.

SOCPilot automatically receives the alert, investigates it, saves the report, and the **dashboard notifies you in real-time**.

---

# ⏹ Stopping the Platform

Stop SOCPilot

```
CTRL + C
```

Stop Wazuh

```bash
docker compose stop
```

Recommended

✔ docker compose stop

✔ docker compose start

Avoid

```
docker compose down -v
```

unless a complete reset is required.

---

# 🐞 Troubleshooting

## Agent Offline

Verify

- Wazuh Agent Service
- Manager IP
- Port 1514
- Port 1515

---

## No Reports Generated

Verify

- FastAPI server running
- Correct webhook token
- Wazuh integration enabled
- Alert severity ≥ configured minimum

---

## Docker Issues

Restart stack

```bash
docker compose restart
```

---

## View Logs

Manager

```bash
docker logs single-node-wazuh.manager-1
```

SOCPilot

Observe terminal output running

```
uvicorn siem_server:app
```

---

# 🔐 Security Notes

SOCPilot is intended for:

- Defensive Security
- Security Operations Centers
- Threat Hunting
- Incident Response
- Cybersecurity Research
- Educational Use

The project should only be deployed within authorized environments.

# 🚀 How SOCPilot AI Works

SOCPilot AI follows a fully autonomous investigation pipeline. Once a security event is detected on an endpoint, every stage of the investigation is performed automatically without analyst intervention.

```
Windows Event
        │
        ▼
Wazuh Agent
        │
        ▼
Wazuh Manager
        │
        ▼
Custom Integration
        │
        ▼
FastAPI Webhook
        │
        ▼
SIEM Adapter
        │
        ▼
LangGraph Workflow
        │
        ▼
IOC Extraction
        │
        ▼
Threat Intelligence
        │
        ▼
Memory Retrieval
        │
        ▼
RAG Search
        │
        ▼
LLM Investigation
        │
        ▼
Incident Report
```

---

# 🤖 LangGraph Investigation Workflow

SOCPilot AI uses LangGraph to model the investigation process as a multi-stage workflow.

```
                   Incoming Alert
                         │
                         ▼
                Normalize Alert
                         │
                         ▼
                 Extract IoCs
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
 Threat Intelligence             Memory Retrieval
          │                             │
          └──────────────┬──────────────┘
                         ▼
                  RAG Search
                         │
                         ▼
                  AI Reasoning
                         │
                         ▼
               Incident Report
```

Each node performs a specific responsibility, allowing the workflow to remain modular, explainable, and extensible.

---

# 🧠 AI Investigation Process

For every incoming alert, SOCPilot AI performs the following sequence:

### Step 1 – Alert Reception

Receive the SIEM alert through the webhook.

Example:

```json
{
    "rule": {
        "level": 10,
        "description": "Suspicious PowerShell execution"
    },
    "agent": {
        "name": "HR-PC-21"
    }
}
```

---

### Step 2 – Alert Normalization

Different SIEM platforms produce different alert formats.

SOCPilot converts all alerts into a common internal representation before investigation begins.

---

### Step 3 – IOC Extraction

The AI extracts all Indicators of Compromise.

Examples

- IP Addresses
- Domains
- URLs
- File Hashes
- CVEs
- Usernames
- Hostnames
- Registry Keys
- PowerShell Commands
- Executables

---

### Step 4 – Threat Intelligence

Each extracted IOC is enriched using external intelligence.

Current sources include

- VirusTotal
- AbuseIPDB
- NVD

Future integrations

- AlienVault OTX
- Shodan
- GreyNoise
- URLHaus

---

### Step 5 – Long-Term Memory

The investigation searches previous incidents stored inside ChromaDB.

If similar attacks were previously investigated, the AI retrieves those findings to improve reasoning.

---

### Step 6 – RAG Retrieval

Relevant cybersecurity documentation is retrieved from the local knowledge base.

Examples

- MITRE ATT&CK
- NVD
- Internal Playbooks
- Security Documentation

---

### Step 7 – AI Reasoning

The LLM correlates

- Alert
- Threat Intelligence
- Previous Incidents
- Retrieved Knowledge

to determine

- Attack Type
- Severity
- Confidence
- Recommended Response

---

### Step 8 – Report Generation

A professional Markdown report is generated automatically.

---

# 💾 Memory Architecture

SOCPilot AI maintains two independent memory systems.

## Short-Term Memory

Maintains investigation context during the current workflow.

Used by LangGraph for reasoning continuity.

---

## Long-Term Memory

Uses

- HuggingFace Embeddings
- ChromaDB

to permanently store completed investigations.

Future investigations retrieve semantically similar incidents.

```
Investigation

↓

Embedding

↓

Vector Database

↓

Future Similar Alert

↓

Retrieve Previous Case
```

---

# 📚 Retrieval-Augmented Generation (RAG)

Traditional LLMs rely only on pre-trained knowledge.

SOCPilot AI improves investigation quality by retrieving external cybersecurity knowledge before reasoning.

Current knowledge sources include

- MITRE ATT&CK
- NVD
- Security Playbooks
- Uploaded Documentation

Benefits

- Reduced hallucinations
- Improved technical accuracy
- Up-to-date investigation context

---

# 🌍 Threat Intelligence Pipeline

```
Extract IOC

↓

VirusTotal

↓

AbuseIPDB

↓

NVD

↓

Combine Results

↓

AI Investigation
```

Every IOC is investigated independently before being passed to the reasoning engine.

---

# 📑 Sample Investigation Report

Each investigation produces a structured Markdown report.

Example

```
Incident Summary

Severity:
High

Attack Type:
Suspicious PowerShell Execution

Affected Host:
HR-PC-21

Indicators of Compromise

- PowerShell Encoded Command
- External IP
- Suspicious Domain

Threat Intelligence

VirusTotal

Detected by 41 vendors

AbuseIPDB

Confidence Score 100%

MITRE ATT&CK

T1059.001

Recommendations

- Isolate endpoint
- Reset credentials
- Block IOC
- Perform malware scan
```

---

# 🎬 Demonstration Workflow

The following sequence demonstrates the complete automated pipeline.

## Step 1

Start Docker

```
docker compose up -d
```

---

## Step 2

Start SOCPilot

```
uvicorn siem_server:app --host 0.0.0.0 --port 8000
```

---

## Step 3

Generate a Windows security event.

Examples

- Scheduled Task Creation
- Suspicious PowerShell
- Failed Logon Attempts
- Process Creation

---

## Step 4

Observe Wazuh Dashboard

The alert appears inside Wazuh.

---

## Step 5

Observe SOCPilot Terminal

```
POST /webhook/wazuh

↓

Investigation Started

↓

Processing

↓

Report Generated
```

---

## Step 6

View the report in the **SOCPilot Dashboard**

```
http://localhost:8080
```

Or open the raw files in

```
reports/
```

---

# 📸 Screenshots

> Replace the placeholders below with actual screenshots.

## Dashboard

```
docs/images/dashboard.png
```

---

## Live Alert

```
docs/images/alert.png
```

---

## SOCPilot Terminal

```
docs/images/terminal.png
```

---

## Generated Report

```
docs/images/report.png
```

---

## Architecture Diagram

```
docs/images/architecture.png
```

---

# 📁 Output Directory

```
reports/

├── incident_2026-08-01.md

├── incident_2026-08-02.md

├── incident_2026-08-03.md
```

---

# 📊 Current Capabilities

| Capability | Status |
|------------|--------|
| LangGraph Agentic Workflow | ✅ |
| Long-Term Semantic Memory (ChromaDB) | ✅ |
| Retrieval-Augmented Generation (RAG) | ✅ |
| Multi-Source Threat Intelligence | ✅ |
| VirusTotal Integration | ✅ |
| AbuseIPDB Integration | ✅ |
| NVD Integration | ✅ |
| Automatic JSON + Markdown Reports | ✅ |
| Wazuh SIEM Integration | ✅ |
| Windows Endpoint Agent | ✅ |
| Docker Deployment | ✅ |
| FastAPI Webhook Server | ✅ |
| Modular Multi-SIEM Framework | ✅ |
| **Web Dashboard (port 8080)** | ✅ |
| **Live Report Notifications (SSE)** | ✅ |
| **Full-Text Report Search** | ✅ |
| **MITRE ATT&CK Heatmap** | ✅ |
| **Statistics & Analytics Charts** | ✅ |
| Splunk Integration | 🚧 |
| Microsoft Sentinel Integration | 🚧 |
| Elastic Security Integration | 🚧 |

---

# ⚡ Performance

Current workflow

```
Alert Received

↓

Webhook

↓

Normalization

↓

IOC Extraction

↓

Threat Intelligence

↓

Memory Retrieval

↓

LLM Investigation

↓

Markdown Report
```

Average investigation time depends on

- LLM response latency
- Threat intelligence APIs
- Number of extracted IoCs
- Retrieved knowledge size

---

# 🎯 Use Cases

SOCPilot AI can be used for

- Security Operations Centers
- Incident Response
- Threat Hunting
- Malware Investigations
- Security Research
- SOC Training
- Cybersecurity Education
- Capstone Projects
- AI Security Research

---

# 🗺️ Project Roadmap

SOCPilot AI follows an incremental development roadmap focused on building a fully autonomous AI-powered Security Operations Center (SOC).

---

## ✅ Version 1 – AI Investigation Assistant

The first version focused on building an intelligent investigation assistant capable of analyzing manually supplied alerts.

### Features

- LangGraph Agentic Workflow
- AI Investigation Pipeline
- IOC Extraction
- Threat Intelligence Enrichment
- VirusTotal Integration
- AbuseIPDB Integration
- NVD Integration
- Retrieval-Augmented Generation (RAG)
- ChromaDB Long-Term Memory
- Markdown Incident Reports
- CLI-Based Investigation

---

## ✅ Version 2 – Real-Time SOC Automation + Dashboard

Version 2 transforms SOCPilot AI into a real-time SOC investigation platform with a production-grade web interface.

### New Features

- Live Wazuh SIEM Integration
- Windows Wazuh Agent
- FastAPI Webhook Server (port 8000)
- Automatic Alert Ingestion
- Background Investigation Pipeline
- Modular SIEM Adapter Framework
- Docker Deployment
- Fully Automated JSON + Markdown Report Generation
- **Web Dashboard with dark glassmorphism UI (port 8080)**
- **Live SSE notifications for new reports**
- **Full-text search, filter, and sort across all reports**
- **6-tab report detail view (IOCs, MITRE, Sigma, Threat Intel, Reasoning)**
- **Interactive charts and statistics page**

Instead of manually entering alerts or reading raw files, SOCPilot AI now receives live alerts directly from Wazuh, investigates them automatically, and surfaces results in a polished dashboard.

---

## 🚀 Version 3 – Enterprise AI SOC Platform (Planned)

Future development aims to transform SOCPilot AI into an enterprise-grade autonomous SOC platform.

### Planned Features

- Microsoft Sentinel Integration
- Splunk Integration
- Elastic Security Integration
- IBM QRadar Integration
- Google Chronicle Integration
- Multi-SIEM Correlation
- Analyst Chat Interface
- AI Detection Engineering Assistant
- Threat Hunting Assistant
- IOC Correlation Engine
- Automatic Playbook Execution
- Active Response Automation
- Malware Sandbox Integration
- Sigma Rule Generation
- YARA Rule Suggestions
- Case Management Dashboard
- ~~Web UI~~ ✅ **Dashboard shipped in v2**
- Role-Based Access Control (RBAC)
- PDF / HTML Report Export
- Dashboard Authentication

---

# 📈 Future Enhancements

The following improvements are currently under consideration.

## AI

- Multi-Agent Investigation
- Autonomous Planning
- Root Cause Analysis
- Timeline Reconstruction
- Threat Actor Attribution
- Confidence Scoring

---

## Threat Intelligence

Additional integrations

- AlienVault OTX
- GreyNoise
- URLHaus
- CISA KEV
- Shodan
- Hybrid Analysis
- MalwareBazaar

---

## Knowledge Base

Future RAG improvements

- Organization Playbooks
- SOC Runbooks
- Internal Documentation
- Detection Engineering Guides
- Threat Hunting Notes
- Company Policies

---

## Reporting

Future report formats

- HTML
- PDF
- DOCX
- Executive Dashboard
- SOC Metrics
- Timeline Visualization

---

# 🧩 Why SOCPilot AI?

Unlike traditional security chatbots, SOCPilot AI is designed as an **autonomous investigation platform** rather than a conversational assistant.

It combines:

- Agentic AI
- Retrieval-Augmented Generation (RAG)
- Long-Term Memory
- Threat Intelligence
- SIEM Integration
- Automated Reporting

into a single investigation pipeline.

The goal is to reduce analyst workload while maintaining transparency and explainability throughout the investigation process.

---

# 🏆 Project Highlights

✔ Agentic AI Workflow

✔ LangGraph-Based Architecture

✔ Long-Term Semantic Memory

✔ Retrieval-Augmented Generation

✔ Multi-Source Threat Intelligence

✔ Automated IOC Extraction

✔ Live SIEM Integration

✔ Background Investigation

✔ Professional JSON + Markdown Incident Reports

✔ Modular Architecture

✔ Docker Deployment

✔ Enterprise-Oriented Design

✔ **Production-Grade Web Dashboard**

✔ **Real-Time SSE Notifications**

✔ **Interactive Charts & Analytics**

✔ **MITRE ATT&CK Heatmap**

✔ **Full-Text Report Search & Filtering**

---

# 🤝 Contributing

Contributions are welcome.

If you would like to contribute:

1. Fork the repository

2. Create a new branch

```bash
git checkout -b feature/new-feature
```

3. Commit your changes

```bash
git commit -m "Add new feature"
```

4. Push your branch

```bash
git push origin feature/new-feature
```

5. Open a Pull Request

---

# 🐛 Reporting Issues

If you encounter any issues, please create a GitHub Issue containing:

- Operating System
- Python Version
- Docker Version
- Error Message
- Steps to Reproduce
- Screenshots (if applicable)

This helps improve project stability.

---

# 📖 Documentation

Documentation includes:

- Installation Guide
- Architecture Overview
- SIEM Integration
- AI Workflow
- Threat Intelligence
- Memory System
- RAG Pipeline
- Deployment
- Troubleshooting

Future documentation will include:

- API Reference
- Developer Guide
- Plugin Development
- Multi-SIEM Integration Guide

---

# 🎓 Academic Purpose

SOCPilot AI was developed as a cybersecurity research and educational project.

The objective is to explore how Agentic AI can assist Security Operations Centers by automating repetitive investigation tasks while preserving analyst oversight.

The project demonstrates concepts including:

- Security Operations
- Incident Response
- Threat Intelligence
- Retrieval-Augmented Generation
- Agentic AI
- Long-Term Memory
- SIEM Integration
- Security Automation

---

# ⚠ Disclaimer

SOCPilot AI is intended for:

- Educational Use
- Security Research
- Defensive Security
- Authorized Security Assessments

The software must only be used in environments where explicit authorization has been obtained.

The authors assume no responsibility for misuse.

---

# 📜 License

This project is licensed under the MIT License.

See the LICENSE file for additional details.

---

# 🙏 Acknowledgements

Special thanks to the following open-source projects and communities:

- LangChain
- LangGraph
- FastAPI
- Wazuh
- ChromaDB
- HuggingFace
- VirusTotal
- AbuseIPDB
- National Vulnerability Database (NVD)
- MITRE ATT&CK Framework

Without these projects, SOCPilot AI would not have been possible.

---

# ⭐ Support the Project

If you found this project useful:

⭐ Star the repository

🍴 Fork the project

🛠 Contribute improvements

📢 Share feedback

Every contribution helps improve the platform.

---

# 📬 Contact

Feel free to reach out for discussions, collaboration, or feedback.

GitHub

```
https://github.com/<your-github-username>
```

LinkedIn

```
https://linkedin.com/in/<your-linkedin>
```

Email

```
your-email@example.com
```

---

# 📚 Citation

If you use SOCPilot AI in academic work or research, please cite:

```
SOCPilot AI

Agentic AI-Powered Security Operations Center Investigation Platform

2026
```

---

<div align="center">

# ⭐ Thank You for Visiting SOCPilot AI ⭐

### Building the Future of AI-Powered Security Operations Centers

**Agentic AI • LangGraph • RAG • Memory • Threat Intelligence • SIEM Automation**

If you like this project, don't forget to ⭐ the repository!

</div>