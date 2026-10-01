#!/usr/bin/env python3
"""
Single-command local development orchestrator for StegoSentinel.
Runs FastAPI backend and Next.js frontend concurrently.
"""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"


def main():
    print("[*] Starting StegoSentinel Local Development Stack...")

    # Ensure synthetic fixtures are present
    fixtures_dir = ROOT_DIR / "fixtures" / "clean"
    if not fixtures_dir.exists() or not list(fixtures_dir.glob("*.png")):
        print("[*] Generating missing test fixtures...")
        subprocess.run([sys.executable, str(ROOT_DIR / "scripts" / "generate_fixtures.py")], check=True)

    processes = []
    try:
        # Start Backend API
        print("[+] Launching FastAPI Backend on http://localhost:8000...")
        venv_uvicorn = BACKEND_DIR / ".venv" / "bin" / "uvicorn"
        backend_cmd = (
            [str(venv_uvicorn), "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
            if venv_uvicorn.exists()
            else ["uv", "run", "--no-sync", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
        )
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=str(BACKEND_DIR),
        )
        processes.append(backend_proc)

        # Wait 1s for backend to initialize
        time.sleep(1)

        # Start Frontend
        print("[+] Launching Next.js Frontend on http://localhost:3000...")
        frontend_proc = subprocess.Popen(
            ["npm", "run", "dev"],
            cwd=str(FRONTEND_DIR),
        )
        processes.append(frontend_proc)

        print("\n========================================================")
        print("  StegoSentinel Services Active:")
        print("  - Web UI:       http://localhost:3000")
        print("  - REST API:     http://localhost:8000/api/v1")
        print("  - Interactive:  http://localhost:8000/docs")
        print("========================================================\n")
        print("Press Ctrl+C to terminate all services.\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Shutting down StegoSentinel services...")
    finally:
        for p in processes:
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        print("[+] Services stopped.")


if __name__ == "__main__":
    main()
