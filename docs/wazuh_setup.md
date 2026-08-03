# Wazuh → SOCPilot Integration Setup Guide

This guide explains how to configure Wazuh to automatically send alerts to SOCPilot AI for investigation.

---

## Overview

Wazuh supports **Custom Integrations** — a built-in feature that sends alert JSON to an external HTTP endpoint when a rule fires. We use this to POST every alert above your minimum severity level directly to the SOCPilot webhook server.

```
Wazuh Manager → HTTP POST → SOCPilot Webhook → SOCPilot Investigation → Report
```

---

## Prerequisites

- Wazuh Manager installed and running
- SOCPilot AI installed and configured (`.env` with API keys)
- SOCPilot server reachable from the Wazuh Manager host
- `fastapi` and `uvicorn` installed (`pip install -r requirements.txt`)

---

## Step 1: Start the SOCPilot SIEM Server

On the machine running SOCPilot, start the webhook server:

```bash
uvicorn siem_server:app --host 0.0.0.0 --port 8000
```

Or for production (with multiple workers):

```bash
uvicorn siem_server:app --host 0.0.0.0 --port 8000 --workers 2
```

Verify it's running:

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "service": "SOCPilot SIEM Integration Server",
  "supported_siems": ["wazuh"]
}
```

---

## Step 2: Configure Wazuh Custom Integration

Wazuh's custom integration is configured in `/var/ossec/etc/ossec.conf` on the **Wazuh Manager**.

### Option A: Simple HTTP (no auth)

Add inside the `<ossec_config>` block:

```xml
<ossec_config>
  <!-- ... your existing config ... -->

  <integration>
    <name>custom-socpilot</name>
    <hook_url>http://<SOCPILOT_HOST>:8000/webhook/wazuh</hook_url>
    <level>5</level>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>
```

### Option B: With Bearer Token Authentication (recommended)

If you set `WAZUH_WEBHOOK_TOKEN` in your `.env`, you must pass it as a header. Wazuh's `<integration>` block does not natively support custom headers, so use the **custom integration script** approach:

**1. Create the integration script** at `/var/ossec/integrations/custom-socpilot`:

```bash
#!/usr/bin/env python3
"""
Wazuh custom integration script for SOCPilot AI.
Place at: /var/ossec/integrations/custom-socpilot
Make executable: chmod +x /var/ossec/integrations/custom-socpilot
"""

import json
import sys
import os
import urllib.request

SOCPILOT_URL = "http://<SOCPILOT_HOST>:8000/webhook/wazuh"
BEARER_TOKEN  = "<your-token-here>"   # Must match WAZUH_WEBHOOK_TOKEN in .env

def send_alert(alert_file_path):
    with open(alert_file_path) as f:
        alert_data = json.load(f)

    body = json.dumps(alert_data).encode("utf-8")

    req = urllib.request.Request(
        SOCPILOT_URL,
        data=body,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {BEARER_TOKEN}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"SOCPilot response: {resp.status} {resp.read().decode()}")
    except Exception as e:
        print(f"SOCPilot integration error: {e}", file=sys.stderr)

if __name__ == "__main__":
    # Wazuh passes: <script> <alert_file> <api_key> <hook_url>
    if len(sys.argv) < 2:
        sys.exit(1)
    send_alert(sys.argv[1])
```

**2. Make it executable:**
```bash
chmod +x /var/ossec/integrations/custom-socpilot
chown root:wazuh /var/ossec/integrations/custom-socpilot
```

**3. Reference the script in `ossec.conf`:**
```xml
<integration>
  <name>custom-socpilot</name>
  <hook_url>http://<SOCPILOT_HOST>:8000/webhook/wazuh</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

---

## Step 3: Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
# or
sudo /var/ossec/bin/wazuh-control restart
```

---

## Step 4: Test the Integration

### Send a test alert manually

```bash
curl -X POST http://<SOCPILOT_HOST>:8000/webhook/wazuh \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-token>" \
  -d '{
    "timestamp": "2024-01-15T10:23:45.000+0000",
    "rule": {
      "id": "100002",
      "level": 10,
      "description": "Suspicious PowerShell execution detected",
      "groups": ["windows", "powershell"]
    },
    "agent": {
      "id": "001",
      "name": "HR-PC-21",
      "ip": "192.168.1.50"
    },
    "data": {
      "srcip": "185.220.101.34",
      "win": {
        "eventdata": {
          "commandLine": "powershell -enc SQBmAC...",
          "user": "john"
        },
        "system": {
          "eventID": "4688"
        }
      }
    },
    "full_log": "Jan 15 10:23:45 HR-PC-21 WinEvtLog: Security: 4688"
  }'
```

Expected response:
```json
{
  "status": "accepted",
  "thread_id": "wazuh-a1b2c3d4",
  "siem": "wazuh",
  "severity_level": 10,
  "message": "Investigation started. Report will be saved to the reports/ directory."
}
```

### Check the report

```bash
ls -lt reports/
```

A new `RPT-*.md` and `RPT-*.json` file should appear within ~30 seconds.

---

## Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `SIEM_SERVER_HOST` | `0.0.0.0` | Bind address for the webhook server |
| `SIEM_SERVER_PORT` | `8000` | Port for the webhook server |
| `WAZUH_MIN_ALERT_LEVEL` | `5` | Minimum Wazuh rule level to investigate (1–15) |
| `WAZUH_WEBHOOK_TOKEN` | *(empty)* | Bearer token for webhook auth. Empty = no auth |

---

## Wazuh Alert Level Reference

| Level | Severity | Recommended Action |
|-------|----------|--------------------|
| 1–3 | Informational | Skip (below default threshold) |
| 4 | Low | Skip (below default threshold) |
| 5–7 | Medium | Investigate (default threshold) |
| 8–11 | High | Investigate |
| 12–15 | Critical | Investigate immediately |

---

## Adding Future SIEMs

The integration is modular. To add Splunk, Sentinel, Elastic, or QRadar:

1. Create `integrations/<siem_name>.py` — subclass `BaseSIEMAdapter`
2. Register in `integrations/registry.py`
3. Configure the SIEM to POST to `http://<host>:8000/webhook/<siem_name>`

No changes to the investigation engine or existing code are needed.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `404 Not Found` on `/webhook/wazuh` | Wrong URL or server not started | Check server is running, URL is correct |
| `401 Unauthorized` | Token mismatch | Verify `WAZUH_WEBHOOK_TOKEN` matches the header |
| `200 skipped` response | Alert level below `WAZUH_MIN_ALERT_LEVEL` | Lower the threshold or raise the alert level |
| No report generated | Investigation error | Check SOCPilot server logs for the `thread_id` |
| Wazuh not sending alerts | Integration misconfigured | Check `/var/ossec/logs/ossec.log` for integration errors |
