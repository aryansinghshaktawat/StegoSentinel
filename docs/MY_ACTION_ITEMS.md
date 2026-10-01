# StegoSentinel: Action Items & Responsibilities

## 1. What Can Be Done Automatically (Completed or In Progress)
- [x] Initialized Git repository and documented architecture.
- [x] Create formal threat model, security guide, API spec, and forensic model.
- [x] Build synthetic fixtures for clean and stego files across formats.
- [x] Implement backend API with FastAPI, SQLAlchemy, and Pydantic.
- [x] Implement multi-format analyzers (Image, Text, Archive, Audio, Document, Video).
- [x] Implement coarse-to-fine candidate generation and validation engine.
- [x] Implement tabular ML candidate ranking model and feature extraction.
- [x] Implement recursive payload extraction and evidence tree DAG.
- [x] Implement report generation (JSON and Markdown) with LLM provider abstraction and mock provider.
- [x] Implement Next.js 14 responsive frontend dashboard with dark mode forensics UI.
- [x] Build automated test suites: Unit, Analyzer, Security, Integration, E2E.
- [x] Build Dockerfiles, Docker Compose, and root Makefile.

---

## 2. Tasks Requiring User Input / Credentials (Optional Enhancements)

These tasks are optional for local development and are only needed if deploying to external production cloud environments:

### 2.1 External LLM Provider (Optional)
- **Action**: Provide OpenAI or Anthropic API key to enable live LLM report synthesis.
- **Where to configure**: In `.env` or production secrets store:
  ```env
  LLM_PROVIDER=openai
  LLM_API_KEY=sk-...
  LLM_MODEL=gpt-4o-mini
  ```
- **Expected Result**: LLM reports will be synthesized via OpenAI API instead of the built-in deterministic `MockLLMProvider`.

### 2.2 S3-Compatible Object Storage (Optional)
- **Action**: Connect AWS S3 or MinIO bucket for multi-worker distributed object storage.
- **Where to configure**: In `.env`:
  ```env
  STORAGE_BACKEND=s3
  S3_ENDPOINT_URL=https://s3.amazonaws.com
  S3_ACCESS_KEY=AKIA...
  S3_SECRET_KEY=...
  S3_BUCKET_NAME=stegosentinel-quarantine
  ```
- **Expected Result**: Quarantined files and extracted evidence payloads are written to S3 rather than local disk.

### 2.3 Production Domain & SSL (Optional)
- **Action**: Configure DNS and TLS certificates for public domain reverse proxy.
