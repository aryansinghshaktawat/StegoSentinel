# StegoSentinel: Deployment Guide

## 1. Production Docker Compose Stack

StegoSentinel includes a production-ready `docker-compose.yml` with segregated network isolation:

```
[Internet]
    │ HTTPS (443)
[Traefik / Nginx Reverse Proxy]
    │
    ├─── [frontend:3000] (Next.js Node Container)
    │
    └─── [api:8000] (FastAPI Uvicorn Container)
            │
            ├─── [postgres:5432] (PostgreSQL 16)
            │
            ├─── [redis:6379] (Redis Message Broker)
            │
            └─── [worker] (Sandboxed Forensic Engine)
                    │ (Internal Network Only, No Outbound Internet)
                    └─── [quarantine-storage] (Shared Read-Only/Tmpfs)
```

---

## 2. Launching with Docker Compose

```bash
# Build and launch all services in detached mode
docker compose up -d --build

# Inspect running container health
docker compose ps

# Follow logs from analysis workers
docker compose logs -f worker
```

---

## 3. Worker Hardening in Docker Compose
The `worker` container is configured with defense-in-depth:
- `user: "10001:10001"` (Non-root user).
- `read_only: true` (Base root filesystem is strictly read-only).
- `tmpfs: /tmp:size=512M` (Only memory-backed ephemeral temp directory is writable).
- `security_opt: [ "no-new-privileges:true" ]`.
- `networks: [ internal_net ]` (Worker has no external internet gateway, preventing data exfiltration or external command triggers).
