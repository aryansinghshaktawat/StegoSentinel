# StegoSentinel

### AI-Assisted Multi-Format Steganalysis & Hidden-Payload Forensics Platform

[![CI Pipeline](https://github.com/aryansinghshaktawat/StegoSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/aryansinghshaktawat/StegoSentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://python.org)
[![Next.js 14](https://img.shields.io/badge/Next.js-14.2-black.svg)](https://nextjs.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)

---

## 1. Project Overview

**StegoSentinel** is an enterprise-grade digital forensics and incident response (DFIR) platform engineered to accept untrusted binary artifacts, perform multi-layer forensic analysis, detect indicators of steganography and covert channels, generate and rank extraction hypotheses through a coarse-to-fine candidate engine, safely extract supported payloads, recursively analyze extracted evidence objects, and compile an explainable, auditable forensic report.

### Core Guiding Principles
- **Zero Trust File Handling**: Every uploaded file and every extracted artifact is untrusted. Payloads are **NEVER** executed during normal operations.
- **Defensible Terminology**: Uses calibrated statements (*"Steganography likelihood: 87%"*). Never claims that a file contains no hidden data merely because supported tests found nothing.
- **Deterministic Ground Truth**: Deterministic forensic evidence (cryptographic hashes, magic signatures, bit plane variance, PoV Chi-Square) is the foundation of truth. Machine learning ranks extraction hypotheses; LLMs explain and summarize evidence.
- **Reproducible Chain of Custody**: Every finding, candidate, and extracted object stores its exact extraction parameters, analyzer versions, and timestamps.

---

## 2. High-Level Architecture

```
[DFIR Analyst / Web UI] (Next.js 14 / TypeScript)
       │ HTTPS / JWT Auth
[FastAPI Gateway] (:8000)
       ├── [Quarantine Storage] (0600 Permissions, Path Traversal Defense)
       ├── [PostgreSQL / SQLite] (Unified Database Layer)
       └── [Redis Broker / In-Process Queue]
              │
       [Isolated Forensic Workers]
              ├── General Forensics (Hashes, MIME, Magic, Entropy, Strings, Trailing Data)
              ├── Format Analyzers (Image, Audio, Text, Archive, Document, Video)
              ├── External Adapters (ExifTool, zsteg, steghide, binwalk - Graceful Fallbacks)
              ├── Coarse-to-Fine Candidate Search Engine
              ├── Tabular ML Candidate Ranker & Statistical Scorer
              ├── Safe Payload Extractor & Recursive Analysis Engine (Max Depth: 3)
              └── Forensic Report Generator (JSON & Markdown Briefings)
```

---

## 3. Supported Formats & Capabilities

| Format Family | Key Features & Forensic Techniques |
|---|---|
| **Images (PNG, BMP, JPEG, GIF)** | Channel decomposition (R, G, B, Alpha), 8-level bit-plane slicing (planes 0-7), LSB spatial analysis, Pairs of Values (PoV) Chi-Square test, sample pair analysis, non-standard PNG chunk detection, appended overlay extraction past EOI (`FF D9`) or IEND. |
| **Text & Documents** | Zero-width Unicode inspection (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`), bidirectional override markers (`\u202E`), SNOW whitespace steganography, Base64/Hex scanning, PDF script/object inspection (`/JavaScript`, `/Launch`, `/EmbeddedFiles`), Office OOXML macro detection (`vbaProject.bin`). |
| **Archives (ZIP, Nested)** | Decompression bomb protection (ratio > 100:1), Zip Slip path traversal mitigation (`..` and absolute paths), symlink neutralization, child evidence DAG generation. |
| **Audio (WAV PCM)** | RIFF header validation, sample rate, bit depth, sample-level LSB bitstream extraction and entropy analysis. |
| **Video (MP4, MKV, AVI)** | Container metadata, embedded subtitle track scanning, keyframe sampling hooks. |

---

## 4. Quick Start (Zero Config Local Development)

StegoSentinel is designed to run locally with zero external setup friction! By default, it uses SQLite and synchronous background processing so you don't even need Docker or Redis running for initial evaluation.

### Prerequisites
- Python 3.11+ (Python 3.14 supported, `uv` recommended)
- Node.js 18+ and npm

### 4.1 Automated Setup & Launch
```bash
# 1. Clone repository
git clone https://github.com/aryansinghshaktawat/StegoSentinel.git
cd StegoSentinel

# 2. Copy environment configuration
cp .env.example .env

# 3. Install dependencies and generate safe test fixtures
make setup

# 4. Start local development stack (Backend + Frontend)
make dev
```

The services will become available at:
- **Web UI Dashboard**: [http://localhost:3000](http://localhost:3000)
- **REST API Gateway**: [http://localhost:8000/api/v1](http://localhost:8000/api/v1)
- **Interactive OpenAPI Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 5. Production Docker Compose Deployment

StegoSentinel provides a production-grade multi-container stack with network isolation:

```bash
# Build and launch all services in detached mode
docker compose up -d --build

# Inspect running container status
docker compose ps

# Follow worker forensic logs
docker compose logs -f worker
```

Services in Docker Compose:
- `frontend`: Next.js 14 on `:3000`
- `api`: FastAPI service on `:8000`
- `worker`: Hardened non-root worker with read-only root and ephemeral tmpfs
- `postgres`: PostgreSQL 16 database
- `redis`: Redis 7 job queue

---

## 6. Testing & Quality Assurance

StegoSentinel utilizes **safe, synthetic test fixtures** generated entirely within the repository. **No live malware is ever stored in the codebase.**

```bash
# Run all test suites
make test

# Run unit tests only
make test-unit

# Run security and boundary tests
make test-security

# Run integration tests
make test-integration

# Code formatting and linting
make lint
make format
```

---

## 7. Security Model & Defense in Depth

1. **Path Traversal Shield**: Quarantined files are saved under randomized UUIDs. Archive extractions strictly validate paths against canonical target roots.
2. **Decompression Bomb Protection**: Hard caps on maximum expansion ratios (100:1) and maximum cumulative extracted sizes (250MB).
3. **Least-Privilege Isolation**: Containerized workers execute under unprivileged UID `10001` with no outbound internet access.
4. **IDOR / BOLA Prevention**: Case lookups enforce tenant ownership and role-based access control (`ADMIN`, `ANALYST`, `VIEWER`).
5. **AI Prompt Injection Shield**: Extracted strings provided to LLMs are quarantined within strict `<UNTRUSTED_EVIDENCE>` delimiters with prompt instructions forbidding execution.

---

## 8. Limitations & Forensic Disclaimers

1. **No Universal Steganography Detector**: Steganalysis is fundamentally probabilistic. The absence of findings does not guarantee that a file is clean.
2. **Encrypted Payloads**: Payloads encrypted with modern ciphers (e.g. AES-256) present as high entropy and cannot be deciphered without key material.
3. **Proprietary Steganography**: Novel or customized embedding algorithms that deviate from tested bit-plane and frequency parameters may evade automated heuristic models.

---

## 9. Documentation Directory

- [Architecture Specification](docs/ARCHITECTURE.md)
- [Formal Threat Model](docs/THREAT_MODEL.md)
- [Security Controls & Hardening](docs/SECURITY.md)
- [REST API Specification](docs/API.md)
- [Forensic Evidence Model](docs/FORENSIC_MODEL.md)
- [Forensic Analyzers Reference](docs/ANALYZERS.md)
- [Machine Learning & AI Architecture](docs/AI.md)
- [Testing & Validation Strategy](docs/TESTING.md)
- [Local Development Guide](docs/DEVELOPMENT.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Secrets & Credential Policy](docs/SECRETS.md)
- [Troubleshooting & FAQ](docs/TROUBLESHOOTING.md)
- [Action Items](docs/MY_ACTION_ITEMS.md)
- [Architecture Decisions (ADR)](docs/DECISIONS.md)

---

## 10. License

StegoSentinel is licensed under the Apache 2.0 / MIT License.
