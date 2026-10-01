# StegoSentinel: Testing & Validation Strategy

## 1. Testing Philosophy

- **Zero Real Malware**: Tests strictly utilize synthetic, controlled fixtures generated inside the repository.
- **Fail-Safe Security Tests**: Path traversal, zip bombs, prompt injections, and extension spoofing have dedicated, automated test cases.
- **Full Coverage Across Tiers**:
  - Unit Tests: Mathematical functions, hashing, entropy, candidate generation, parsers.
  - Analyzer Tests: Image, audio, text, archive, and document analyzers on clean vs stego fixtures.
  - Integration Tests: API upload, database persistence, asynchronous worker tasks.
  - Security Tests: Boundary violations, resource limit enforcement, IDOR checks.
  - End-to-End Tests: Complete flow from file upload to evidence tree generation and report export.

---

## 2. Test Execution Commands

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run analyzer tests
uv run pytest backend/tests/unit/test_analyzers.py -v

# Run security test suite
make test-security

# Run integration tests
make test-integration

# Generate code coverage report
uv run pytest --cov=backend/app --cov-report=html
```

---

## 3. Synthetic Fixtures Roster (`fixtures/`)
- `clean_sample.png`: Standard PNG with natural gradient and standard metadata.
- `stego_lsb_rgb_p0.png`: Synthetic PNG with hidden ASCII message embedded in LSB Plane 0 across RGB channels.
- `clean_sample.bmp`: Uncompressed standard BMP.
- `stego_lsb_sample.bmp`: Synthetic BMP with sequential LSB payload.
- `clean_sample.jpg`: JPEG with standard markers.
- `appended_payload.jpg`: JPEG with raw binary overlay appended past the EOI `0xFF 0xD9` marker.
- `zero_width_stego.txt`: Text file with invisible payload encoded using zero-width spaces (`\u200B`) and zero-width non-joiners (`\u200C`).
- `whitespace_snow.txt`: Text file with trailing tab and space encoding.
- `clean_audio.wav`: Synthetic sinusoidal PCM audio.
- `stego_audio.wav`: Audio sample with least significant bit encoded bitstream.
- `safe_archive.zip`: Standard multi-file ZIP archive.
- `nested_archive.zip`: Multi-level nested ZIP to test recursion depth limits.
- `zip_slip_malicious.zip`: Synthetic archive containing path traversal entry (`../../malicious.txt`) to verify path traversal blocking.
- `extension_mismatch.png`: Executable binary renamed to `.png` to test magic byte validation.
