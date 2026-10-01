# StegoSentinel: Forensic Analyzers Reference

## 1. Analyzer Architecture

All analyzers inherit from `BaseAnalyzer` (`backend/app/analyzers/base.py`) which defines standard capabilities:
- `can_analyze(mime_type: str, file_bytes: bytes) -> bool`
- `analyze(file_path: Path, context: AnalysisContext) -> List[Finding]`
- Standardized `Finding` schema with `id`, `type`, `severity`, `confidence`, `description`, `evidence`, `analyzer`, `analyzer_version`.

---

## 2. Implemented Forensic Analyzers

### 2.1 General Forensics (`general.py`)
- **Cryptographic Hashes**: SHA-256, SHA-512, MD5.
- **MIME & Magic Identification**: Magic bytes lookup against header database.
- **Extension Mismatch**: Flags discrepancies where file extension does not match true binary signature.
- **Shannon Entropy Analysis**:
  - Global entropy: $H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$ (scale 0.0 - 8.0).
  - Sliding window entropy (256-byte blocks) to locate localized steganographic injection zones.
- **String & Character Distribution**:
  - Printable ASCII/UTF-8 ratio.
  - Suspicious string signatures (URLs, IPv4/IPv6, base64 blobs, shell command signatures).
- **Trailing Data & Overlay Detection**:
  - Identifies bytes past format end-of-file markers (e.g. JPEG `FF D9`, PNG `IEND`, ZIP Central Directory).

### 2.2 Image Steganalysis (`image.py`)
- **Formats**: PNG, BMP, JPEG, TIFF, GIF.
- **Channel Isolation & Bit-Plane Analysis**:
  - Separates channels: Red, Green, Blue, Alpha.
  - Slices each channel into 8 bit-planes (Plane 0 = LSB, Plane 7 = MSB).
  - Calculates plane entropy: clean natural images have near-zero entropy on planes 4-7, and structured gradient patterns on plane 0. Injected LSB noise produces near-maximum entropy ($\approx 7.9-8.0$).
- **LSB Statistical Anomaly Tests**:
  - **Chi-Square ($\chi^2$) Attack**: Measures pairs of values (PoVs) $2k$ and $2k+1$. Equalization of PoV frequencies indicates sequential LSB embedding.
  - **Sample Pair Analysis (SPA)**: Estimates embedding rate for randomly distributed LSB stego.
- **Structural Integrity**:
  - PNG chunk CRC validation, detection of non-standard private chunks.
  - JPEG EXIF metadata anomalies, double compression indicators.

### 2.3 External Tool Adapters (`analyzers/external/`)
- **`ExifToolWrapper`**: Comprehensive metadata and camera forensics.
- **`ZstegWrapper`**: Deep PNG/BMP multi-channel bit-plane steganography scanner.
- **`SteghideWrapper`**: Detects steghide payloads in JPEG, BMP, WAV.
- **`BinwalkWrapper`**: Signature scanner for embedded file offsets.
- **Resilience**: Dynamic check via `shutil.which`. If missing, logs `TOOL_UNAVAILABLE` and falls back cleanly to native engines without error.

### 2.4 Text Steganalysis (`text.py`)
- **Zero-Width Character Inspection**:
  - Zero-Width Space (`\u200B`), Zero-Width Non-Joiner (`\u200C`), Zero-Width Joiner (`\u200D`), Zero-Width No-Break Space (`\uFEFF`).
- **Bidirectional Control Characters**:
  - Detects Unicode spoofing (`\u202E` Right-to-Left Override).
- **Whitespace Steganography**:
  - Patterns of trailing tabs and spaces (SNOW steganography).
  - Inter-word and inter-sentence spacing variations.
- **Encodings**:
  - Identifies Base64, Hex, Base32, Base85, and Rot13 strings.

### 2.5 Archive Forensics (`archive.py`)
- Safe ZIP inspection.
- Decompression bomb detection ($>100:1$ ratio check).
- Path traversal rejection (`..`, absolute paths).
- Emits extracted member files as child evidence objects up to `MAX_RECURSION_DEPTH`.

### 2.6 Audio Forensics (`audio.py`)
- Supported format: WAV PCM (extensible to MP3, FLAC).
- RIFF header validation and chunk inspection.
- Sample-level LSB extraction across 8, 16, 24-bit audio tracks.
- High-frequency noise floor analysis and sample entropy.

### 2.7 Document Forensics (`document.py`)
- PDF: Stream decompression, object catalog analysis, detection of `/EmbeddedFiles`, `/JavaScript`, `/Launch`, `/URI`.
- Office (DOCX, XLSX, PPTX): OOXML relationship traversal, macro stream (`vbaProject.bin`) detection.

### 2.8 Video Forensics (`video.py`)
- Container inspection (MP4, MKV, AVI).
- Keyframe sampling hooks for forwarding sampled frames to `ImageAnalyzer`.
