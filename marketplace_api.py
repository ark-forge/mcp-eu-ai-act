#!/usr/bin/env python3
"""marketplace_api.py — Entry point for arkforge-euaiact-api.service.

Runs api_wrapper/main.py (FastAPI) via uvicorn on EUAIACT_API_PORT (default 8200).
"""
import os
import sys
from pathlib import Path

# Ensure api_wrapper is importable
_BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(_BASE))

import uvicorn
from api_wrapper.main import app

if __name__ == "__main__":
    port = int(os.environ.get("EUAIACT_API_PORT", 8200))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
