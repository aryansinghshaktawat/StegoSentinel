#!/usr/bin/env python3
"""
Database schema migration script for StegoSentinel.
Upgrades existing SQLite or PostgreSQL database schema to support recovered payload metadata
without data loss.
"""
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from app.core.database import engine, init_db, migrate_db  # noqa: E402


def main():
    print("[*] Running StegoSentinel database migration...")
    init_db()
    print("[+] Migration completed successfully. Candidates table schema is up to date.")


if __name__ == "__main__":
    main()
