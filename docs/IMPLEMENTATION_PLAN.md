# StegoSentinel: Implementation Plan & Progress Tracking

## 1. Overview & Phased Roadmap

This plan establishes the implementation sequence from project foundation to production readiness, tracking completed components, active work, and upcoming verification phases.

---

## 2. Phase Breakdown

### Phase 1: Foundations & Architecture Baseline (Current)
- [x] Repository discovery and environment assessment (`Python 3.14`, `Node v26`, `Docker`, `uv`).
- [x] Initialized Git repository.
- [x] Create foundational architectural documentation:
  - [x] `docs/ARCHITECTURE.md`
  - [x] `docs/IMPLEMENTATION_PLAN.md`
  - [x] `docs/DECISIONS.md`
  - [x] `docs/THREAT_MODEL.md`
  - [x] `docs/SECURITY.md`
  - [x] `docs/API.md`
  - [x] `docs/DEVELOPMENT.md`
  - [x] `docs/DEPLOYMENT.md`
  - [x] `docs/ANALYZERS.md`
  - [x] `docs/AI.md`
  - [x] `docs/TESTING.md`
  - [x] `docs/FORENSIC_MODEL.md`
  - [x] `docs/SECRETS.md`
  - [x] `docs/TROUBLESHOOTING.md`
  - [x] `docs/BLOCKERS.md`
  - [x] `docs/MY_ACTION_ITEMS.md`

### Phase 2: Synthetic Fixtures & Security Test Suite
- [ ] Safe synthetic fixture generator (`fixtures/generate_fixtures.py`):
  - Clean PNG, synthetic LSB stego PNG (RGB LSB plane 0).
  - Clean BMP, synthetic LSB stego BMP.
  - Clean JPEG with metadata overlay and appended payload.
  - Zero-width Unicode hidden text fixture.
  - Whitespace stego text fixture.
  - Synthetic WAV audio with LSB payload.
  - Clean ZIP and nested ZIP with mock payload.
  - Malformed file with extension mismatch (e.g. executable disguised as PNG).
  - Malicious path traversal fixture (`../etc/passwd` zip entry test).

### Phase 3: Backend Core, Database, & Storage Quarantine
- [ ] Python project setup (`backend/pyproject.toml` managed via `uv`).
- [ ] Core configuration (`backend/app/core/config.py`) with environment variable parsing.
- [ ] Storage abstraction (`backend/app/core/storage.py`) for quarantine management.
- [ ] Database models (`backend/app/models/`):
  - `Analysis`, `Finding`, `Candidate`, `EvidenceObject`, `LLMReport`, `AuditEvent`, `User`.
- [ ] Database engine & session management with SQLite fallback for offline dev and PostgreSQL support.
- [ ] Pydantic Schemas (`backend/app/schemas/`).
- [ ] Core limits & security guardrails (`backend/app/core/limits.py`).

### Phase 4: Forensic Analyzers & Safe Extraction Engine
- [ ] General Forensics (`analyzers/general.py`):
  - Multi-hash calculation (SHA-256, SHA-512, MD5).
  - Magic byte classification and extension mismatch detection.
  - Shannon entropy & sliding window entropy.
  - Printable ASCII/UTF-8 ratio and suspicious string scanning.
  - Appended/trailing overlay byte detection.
- [ ] Image Analyzer (`analyzers/image.py`):
  - Channel split, bit-plane decomposition (planes 0-7).
  - LSB statistical anomaly detection (chi-square test, sample pair analysis).
  - Structure & chunk validation.
  - Tool wrappers (`exiftool`, `zsteg`, `steghide`, `binwalk`) with capability detection and graceful fallback.
- [ ] Text Analyzer (`analyzers/text.py`):
  - Unicode zero-width character detection (`U+200B`, `U+200C`, `U+200D`, `U+FEFF`).
  - Bidirectional override markers (`U+202E`, etc.).
  - Whitespace steganography analysis.
  - Base64, hex, and encoded sequence extraction.
- [ ] Archive Analyzer (`analyzers/archive.py`):
  - Safe ZIP parser with zip-bomb detection, decompression size ratio checks, path traversal mitigation.
- [ ] Audio Analyzer (`analyzers/audio.py`):
  - WAV header validation, sample LSB extraction.
- [ ] Document Analyzer (`analyzers/document.py`):
  - PDF stream and dictionary inspection; Office OOXML relationship inspection.
- [ ] Video Analyzer (`analyzers/video.py`):
  - Container inspection and keyframe sampling hooks.

### Phase 5: Coarse-to-Fine Candidate Search & ML Ranking
- [ ] Candidate Search Engine (`candidates/generator.py`):
  - Multi-stage search: coarse statistical screening -> parameter permutation -> sample extraction.
  - Technique metadata recording (channel, bit_plane, order, stride).
- [ ] Candidate Validation (`extraction/validators.py`):
  - Content typing: text, binary magic bytes, archives, media formats.
- [ ] ML Tabular Ranker (`ai/scorer.py`):
  - Feature extraction vector (entropy, printable ratio, magic match, chi-square).
  - Pre-trained interpretable Random Forest / Logistic Regression model.
  - Model serialization and inference pipeline with confidence calibration.
- [ ] Safe Payload Extractor & Recursive Analysis Engine (`extraction/recursion.py`):
  - Recursive traversal with strict depth and object count limits.
  - Evidence hierarchy construction (`EvidenceObject`).

### Phase 6: Report Generation & LLM Explanation Layer
- [ ] Report Generator (`reports/generator.py`):
  - Structured JSON export.
  - Analyst-grade Markdown report with forensic disclaimers and explicit terminology.
- [ ] LLM Provider Interface (`ai/llm/provider.py`):
  - `MockLLMProvider` (deterministic, test-friendly).
  - `OpenAIProvider` / `GenericHTTPProvider` (configurable via environment variables).
  - Prompt injection mitigation wrapper with strict untrusted data isolation.

### Phase 7: REST API & Authentication Architecture
- [ ] FastAPI Application Setup (`backend/app/main.py`).
- [ ] API v1 Endpoints:
  - `POST /api/v1/analyses`: Upload & initiate analysis.
  - `GET /api/v1/analyses/{id}`: Status & summary.
  - `GET /api/v1/analyses/{id}/findings`: Detailed findings list.
  - `GET /api/v1/analyses/{id}/candidates`: Ranked extraction candidates.
  - `GET /api/v1/analyses/{id}/evidence`: Hierarchical evidence tree.
  - `GET /api/v1/analyses/{id}/report`: Formatted JSON or Markdown report.
  - `GET /api/v1/analyses/{id}/events`: Audit event log.
  - `GET /api/v1/health`: Liveness & readiness probes.
  - `POST /api/v1/auth/token`: Authentication & JWT issuance.
- [ ] RBAC Middleware & IDOR protection:
  - Role enforcement (Admin, Analyst, Viewer).
  - Object ownership verification.

### Phase 8: Worker Architecture & Async Job Queue
- [ ] Redis job queue integration with Celery/custom async worker.
- [ ] In-process fallback execution for standalone dev and unit test speed.
- [ ] Resource limits, timeout enforcement, and unhandled exception containment.

### Phase 9: Modern Forensic Frontend (Next.js & TypeScript)
- [ ] Next.js 14 App Router project setup (`frontend/`).
- [ ] Design system: Cyber-forensics dark mode, high contrast data tables, sleek indicators.
- [ ] Pages:
  - `/dashboard`: High-level metrics, recent jobs, queue health.
  - `/upload`: Drag-and-drop quarantine intake with validation.
  - `/analysis/[id]`: Live telemetry, multi-layer findings, anomaly charts.
  - `/evidence/[id]`: Interactive tree view of extracted payloads.
  - `/reports/[id]`: Forensic report viewer with raw JSON/Markdown copy.
  - `/settings`: Configuration and tool capability matrix.
- [ ] Frontend mock/API client and tests.

### Phase 10: Security Hardening, Testing & Verification
- [ ] Backend Unit Tests (hashing, entropy, analyzers, candidates, scoring, limits).
- [ ] Security Tests (traversal, zip bomb, prompt injection, extension spoofing, IDOR).
- [ ] Integration & E2E Pipeline Tests (upload -> queue -> analysis -> extraction -> recursion -> report).
- [ ] Frontend Component Tests.
- [ ] Dockerfiles (API, Worker, Frontend) & `docker-compose.yml`.
- [ ] Root `Makefile` with all standard workflows (`make dev`, `make test`, `make lint`, etc.).
- [ ] GitHub Actions CI workflow (`.github/workflows/ci.yml`).
- [ ] Verification of all test suites, linting, and final status reporting.

---

## 3. Risks & Mitigations

| Risk | Impact | Mitigation Strategy |
|---|---|---|
| Algorithmic Denial of Service (ReDoS, Decompression Bombs) | High | Hard analysis timeout (60s default), max memory cap, strict decompression size limit (250MB), bounded candidate budget (max 1000). |
| Parser Vulnerabilities in Underlying Libraries | High | Isolation in non-root worker container, defensive parsing with error isolation, no arbitrary shell command execution. |
| Over-confident Stego Claims / False Positives | Medium | Strict terminology ("Steganography likelihood: X%"), explicit limitations section in report, deterministic ground truth priority. |
| External Tool Dependencies Missing on Host | Low | Tool capability detection with native pure-Python analyzer fallbacks; clear reporting of tool availability. |
