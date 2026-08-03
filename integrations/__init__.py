"""
SOCPilot AI — SIEM Integrations Package
========================================
This package provides a modular SIEM integration layer.

Each SIEM is implemented as an adapter (subclass of BaseSIEMAdapter) that
normalizes the SIEM-specific JSON payload into plain alert text, which is
then fed directly into the existing SOCPilot investigation pipeline.

Supported SIEMs:
  - Wazuh (wazuh.py)

Adding a new SIEM:
  1. Create a new file, e.g. integrations/splunk.py
  2. Subclass BaseSIEMAdapter and implement normalize()
  3. Register it in integrations/registry.py
  No other files need to change.
"""
