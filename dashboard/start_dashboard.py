"""
SOCPilot AI Dashboard — One-Click Launcher
==========================================
Run this from the project root:
  python dashboard/start_dashboard.py

Opens the dashboard at http://localhost:8080
"""
import os
import sys
import subprocess
import time
import webbrowser
from pathlib import Path

# Ensure we're running from the right place
ROOT = Path(__file__).parent.parent
os.chdir(ROOT)

print("""
╔══════════════════════════════════════════════════════╗
║         SOCPilot AI — Dashboard Launcher             ║
║   Production-grade Security Operations Dashboard     ║
╚══════════════════════════════════════════════════════╝
""")

print("📂 Project root:", ROOT)
print("📊 Reports directory:", ROOT / "reports")
print("🌐 Dashboard URL: http://localhost:8080")
print()

# Check/install dependencies
required = ["fastapi", "uvicorn"]
for pkg in required:
    try:
        __import__(pkg.replace("-", "_"))
    except ImportError:
        print(f"📦 Installing {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

print("✅ All dependencies available")
print()
print("🚀 Starting SOCPilot Dashboard API server...")
print("   Press Ctrl+C to stop\n")

# Open browser after a short delay
def open_browser():
    time.sleep(2)
    webbrowser.open("http://localhost:8080")

import threading
threading.Thread(target=open_browser, daemon=True).start()

# Start the server
import uvicorn
uvicorn.run(
    "dashboard.api_server:app",
    host="0.0.0.0",
    port=8080,
    reload=False,
    log_level="info",
)
