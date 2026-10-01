# StegoSentinel: Local Development Guide

## 1. Quick Start (Zero Config Local Run)

StegoSentinel is designed to run locally with minimum friction. By default, it uses SQLite and synchronous background processing so you don't even need Docker or Redis running for initial development!

### Prerequisites
- Python 3.11+ (Python 3.14 supported, `uv` package manager recommended)
- Node.js 18+ & npm
- (Optional) Docker & Docker Compose for containerized stack

### 1.1 Automated Setup
```bash
# Clone repository and enter directory
cd StegoSentinel

# Setup environment file
cp .env.example .env

# Run full setup (dependencies, fixtures, migrations)
make setup

# Start development servers (Backend API on :8000, Frontend on :3000)
make dev
```

---

## 2. Running Individual Services

### Backend API
```bash
cd backend
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Web UI
```bash
cd frontend
npm install
npm run dev
```

### Worker (when running with Redis)
```bash
cd backend
uv run python -m app.worker
```

---

## 3. Code Quality & Formatting
```bash
# Lint backend with Ruff
make lint

# Run type checks with MyPy
make typecheck

# Format code
make format
```
