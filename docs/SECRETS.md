# StegoSentinel: Secrets & Credential Management Policy

## 1. Zero Secrets in Source Code Policy

1. No secrets, credentials, tokens, or private keys are ever committed to Git, baked into Docker images, or shipped to frontend clients.
2. All sensitive configuration is loaded via environment variables (`.env`).
3. Local development uses `.env.example` as a template.

---

## 2. Environment Variables Matrix

| Variable | Description | Default (Local Dev) | Production Requirement |
|---|---|---|---|
| `JWT_SECRET_KEY` | Secret key for signing authentication tokens | `dev-insecure-secret-key-change-in-prod-32bytes!` | **REQUIRED**: 256-bit random hex string |
| `DATABASE_URL` | PostgreSQL connection string | `sqlite:///./stegosentinel.db` | **REQUIRED**: PostgreSQL connection string |
| `REDIS_URL` | Redis broker connection string | `redis://localhost:6379/0` | **REQUIRED**: Redis connection URL |
| `LLM_PROVIDER` | AI Explanation provider (`mock`, `openai`) | `mock` | Optional (`openai` or `generic`) |
| `LLM_API_KEY` | API Key for LLM reporting service | Empty (uses `mock`) | Required if using external LLM |
| `LLM_MODEL` | Target model name | `gpt-4o-mini` | Configurable |
| `STORAGE_BACKEND` | Object storage provider (`local`, `s3`) | `local` | `local` or `s3` |
| `STORAGE_LOCAL_PATH` | Directory for quarantine storage | `./storage/quarantine` | Persistent volume path |
| `S3_ENDPOINT_URL` | S3-compatible endpoint (MinIO / AWS) | Empty | Required if `STORAGE_BACKEND=s3` |
| `S3_ACCESS_KEY` | S3 Access Key | Empty | Required if `STORAGE_BACKEND=s3` |
| `S3_SECRET_KEY` | S3 Secret Key | Empty | Required if `STORAGE_BACKEND=s3` |
| `S3_BUCKET_NAME` | S3 Bucket Name | `stegosentinel-quarantine` | Bucket name |

---

## 3. Secret Rotation & Handling
- If `JWT_SECRET_KEY` is rotated, all existing analyst sessions are invalidated safely.
- In production Kubernetes / Docker Swarm deployments, secrets must be injected via Docker Secrets, HashiCorp Vault, or AWS Secrets Manager.
