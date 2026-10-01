# StegoSentinel: Troubleshooting & FAQ

## 1. Common Issues & Diagnostics

### Issue 1: External tools (`zsteg`, `steghide`, `exiftool`) not found
- **Symptom**: Logs show `TOOL_UNAVAILABLE: exiftool not found in PATH`.
- **Cause**: The host or container lacks specialized external CLI tools.
- **Resolution**: StegoSentinel detects missing tools automatically and uses its native pure-Python forensic analyzers. In Docker, tools are installed via the Dockerfile. For native host installs on macOS: `brew install exiftool steghide` and `gem install zsteg`.

### Issue 2: Upload fails with `413 Request Entity Too Large`
- **Symptom**: Submitting files larger than 100MB fails at upload.
- **Cause**: `MAX_UPLOAD_SIZE` is enforced at both API gateway and reverse proxy.
- **Resolution**: Increase `MAX_UPLOAD_SIZE` in `.env` if necessary.

### Issue 3: Redis connection refused in local dev
- **Symptom**: `ConnectionRefusedError: [Errno 61] Connect call failed ('127.0.0.1', 6379)`.
- **Resolution**: Set `ASYNC_MODE=sync` or `ASYNC_MODE=thread` in `.env` to run analysis jobs in-process without requiring a Redis server.

### Issue 4: Database migration errors
- **Resolution**: Run `make migrate` or delete local `stegosentinel.db` during development to re-initialize schema.
