# StegoSentinel: Blockers Log

## Active Blockers Status

**Status: NO ACTIVE BLOCKERS.**

All core engineering components, deterministic forensic engines, candidate generators, ML rankers, safe extractors, recursive engines, and report generators have been designed to operate with zero mandatory external API keys or cloud dependencies.

- Local SQLite + PostgreSQL dual dialect allows local development without external database servers.
- In-process background queue (`ASYNC_MODE=thread`) allows testing without external Redis.
- `MockLLMProvider` generates structured forensic summaries and analyst briefings without requiring OpenAI API tokens.
- Native pure-Python forensic analyzers execute when optional external binaries (`exiftool`, `steghide`, `zsteg`, `binwalk`) are not installed.
