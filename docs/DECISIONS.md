# StegoSentinel: Architecture Decision Records (ADR)

## ADR-001: Separation of Deterministic Evidence, ML Ranking, and LLM Explanations

### Context
In digital forensics and incident response (DFIR), forensic reports may be used in investigations or legal proceedings. LLMs are non-deterministic and susceptible to hallucinations or prompt injection from untrusted files. Pure statistical rules can be rigid and miss nuanced correlations.

### Decision
We adopt a strictly layered architecture:
1. **Layer 1: Deterministic Forensics (Ground Truth)**: Magic byte matching, cryptographic hashing, chunk structure checks, structural anomalies, and bit-level extraction.
2. **Layer 2: Statistical & ML Candidate Ranking**: Tabular machine learning (Random Forest / Logistic Regression) trained on extractable statistical features to order extraction hypotheses without claiming definitive proof.
3. **Layer 3: LLM Explanation & Correlation Layer**: LLMs are solely used to summarize findings into human-readable narratives, correlation summaries, and executive briefings. Untrusted data is segregated with strict delimiter protections. LLMs never make binary verdicts on steganography presence without underlying deterministic evidence.

---

## ADR-002: Safe Quarantine Storage & Zero Execution Policy

### Context
Uploaded files can contain live exploits, malicious shell scripts, or disguised executables. Any automatic execution or unsafe ingestion poses severe danger to host systems and analysts.

### Decision
1. All files are isolated upon arrival in an ephemeral quarantine directory with randomized filenames and access permissions (`0600`).
2. Execution permissions (`chmod +x`) are never set.
3. Extracted files (from archives or steganographic payloads) are treated identically as untrusted evidence objects and ingested into quarantine with full SHA-256 identification and recursion limits.

---

## ADR-003: Coarse-to-Fine Candidate Search Strategy

### Context
Steganography parameters (channel combinations, bit planes, traversal directions, strides, bit alignments) produce a massive combinatorial search space ($>10,000$ combinations per image). Running deep extraction on all combinations causes denial-of-service and extreme latency.

### Decision
Implement a 5-stage coarse-to-fine search:
1. **Stage 1 (Coarse Statistics)**: Fast entropy, chi-square, and bit-plane randomness tests on raw buffers.
2. **Stage 2 (Candidate Pruning)**: Filter permutations that exhibit statistical flatness or zero entropy.
3. **Stage 3 (Candidate Feature Extraction)**: Extract a small sample window (e.g. 512 bytes) and compute feature vectors.
4. **Stage 4 (ML Scoring)**: Score sample candidates with pre-trained tabular classifier.
5. **Stage 5 (High-Value Extraction)**: Only candidates surpassing the scoring threshold are extracted to completion, validated, and converted into child evidence objects.
A hard budget (`MAX_CANDIDATES = 1000`) prevents unbounded searches.

---

## ADR-004: Dual-Mode Database Support (SQLite for Local Dev, PostgreSQL for Production)

### Context
Developers should be able to run and test StegoSentinel locally with zero setup overhead (without needing a live PostgreSQL cluster), while production deployments require concurrent transactions in PostgreSQL.

### Decision
We use SQLAlchemy 2.0 with a unified dialect model. The default connection string checks for `DATABASE_URL`. If not set or during local development/unit testing, it defaults to a local SQLite database (`stegosentinel.db` or in-memory `:memory:`). In production and Docker Compose, PostgreSQL is used.

---

## ADR-005: Resilient External Tool Wrapper Pattern with Pure-Python Native Fallbacks

### Context
Specialized tools like `zsteg`, `steghide`, `exiftool`, and `binwalk` provide deep analysis for specific file types, but may not be available on all host architectures or container environments.

### Decision
1. Never assume external binaries are present.
2. Check tool availability dynamically at runtime using `shutil.which`.
3. Wrap external tools in standardized adapters that normalize output into the common `Finding` schema.
4. If a tool is missing, flag it as `UNAVAILABLE` in system capabilities, do not fake output, and execute comprehensive pure-Python native forensic analyzers (LSB analyzer, chunk inspector, entropy calculator).

---

## ADR-006: Asynchronous Job Processing with Direct In-Process Fallback

### Context
Forensic analysis jobs can take seconds to minutes. Long-running HTTP requests degrade user experience. However, requiring Redis during lightweight unit tests adds unnecessary friction.

### Decision
We implement a dual-mode job dispatcher:
- **Redis Queue Mode**: In production and Docker environments, tasks are pushed to a Redis queue and processed by dedicated isolated workers.
- **In-Process Background Task Mode**: When Redis is unavailable or during local testing (`ASYNC_MODE=sync` or `ASYNC_MODE=thread`), tasks execute via FastAPI background tasks or direct synchronous execution, ensuring zero-configuration local runs.
