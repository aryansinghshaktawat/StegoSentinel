# StegoSentinel: REST API Specification (v1)

## 1. Overview

All API endpoints reside under `/api/v1`. Authentication is conducted using HTTP Bearer Tokens (JWT). All request and response bodies use JSON, except upload endpoints which accept `multipart/form-data`.

---

## 2. Endpoints Summary

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/v1/auth/token` | Authenticate and obtain JWT access token | No |
| `GET` | `/api/v1/auth/me` | Return currently authenticated user profile | Yes |
| `POST` | `/api/v1/analyses` | Upload file and initiate forensic analysis | Yes |
| `GET` | `/api/v1/analyses` | List analyses with pagination and filters | Yes |
| `GET` | `/api/v1/analyses/{id}` | Get status, metadata, and summary of analysis | Yes |
| `GET` | `/api/v1/analyses/{id}/findings` | Retrieve all multi-layer findings | Yes |
| `GET` | `/api/v1/analyses/{id}/candidates` | Retrieve ranked steganographic extraction candidates | Yes |
| `GET` | `/api/v1/analyses/{id}/evidence` | Retrieve hierarchical evidence tree of extracted objects | Yes |
| `GET` | `/api/v1/analyses/{id}/report` | Retrieve complete forensic report (JSON or Markdown) | Yes |
| `GET` | `/api/v1/analyses/{id}/events` | Retrieve audit event trail for the analysis | Yes |
| `GET` | `/api/v1/health` | Health and liveness probe | No |
| `GET` | `/api/v1/health/ready` | Readiness probe (database, redis, storage) | No |

---

## 3. Detailed Endpoint Specs

### 3.1 Upload & Create Analysis
- **`POST /api/v1/analyses`**
- **Content-Type**: `multipart/form-data`
- **Form Parameters**:
  - `file`: Binary file stream (max 100MB).
  - `generate_report`: Boolean (`true` by default).
  - `max_candidates`: Integer (`100` by default, max 1000).
- **Response**: `202 Accepted`
  ```json
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "status": "PENDING",
    "original_filename": "sample.png",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size": 1048576,
    "created_at": "2026-10-01T20:30:00Z"
  }
  ```

### 3.2 Get Analysis Details
- **`GET /api/v1/analyses/{id}`**
- **Response**: `200 OK`
  ```json
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "user_id": "usr_01",
    "status": "COMPLETED",
    "original_filename": "sample.png",
    "sha256": "e3b0c442...",
    "detected_type": "image/png",
    "size": 1048576,
    "entropy": 7.942,
    "stego_likelihood": 0.87,
    "created_at": "2026-10-01T20:30:00Z",
    "started_at": "2026-10-01T20:30:01Z",
    "completed_at": "2026-10-01T20:30:05Z",
    "findings_count": 4,
    "candidates_count": 12,
    "evidence_count": 2
  }
  ```

### 3.3 Get Findings
- **`GET /api/v1/analyses/{id}/findings`**
- **Response**: `200 OK`
  ```json
  [
    {
      "id": "fnd_01",
      "analysis_id": "3fa85f64...",
      "type": "LSB_ENTROPY_ANOMALY",
      "severity": "HIGH",
      "confidence": 0.92,
      "description": "Bit plane 0 of Red channel exhibits statistically anomalous Shannon entropy (7.98)",
      "evidence": {
        "channel": "R",
        "plane": 0,
        "entropy": 7.98,
        "chi_square_p_value": 0.0001
      },
      "analyzer": "ImageAnalyzer",
      "analyzer_version": "1.0.0",
      "created_at": "2026-10-01T20:30:02Z"
    }
  ]
  ```

### 3.4 Get Extraction Candidates
- **`GET /api/v1/analyses/{id}/candidates`**
- **Response**: `200 OK`
  ```json
  [
    {
      "id": "cand_01",
      "analysis_id": "3fa85f64...",
      "technique": "LSB_SEQUENTIAL",
      "parameters": {
        "channel": "RGB",
        "bit_plane": 0,
        "order": "sequential",
        "stride": 1
      },
      "raw_score": 0.88,
      "ml_score": 0.93,
      "validation_score": 1.0,
      "final_score": 0.94,
      "status": "VALID",
      "extracted_type": "text/plain",
      "printable_ratio": 0.98
    }
  ]
  ```

### 3.5 Get Evidence Hierarchy Tree
- **`GET /api/v1/analyses/{id}/evidence`**
- **Response**: `200 OK`
  ```json
  [
    {
      "id": "evid_01",
      "analysis_id": "3fa85f64...",
      "parent_id": null,
      "name": "sample.png",
      "sha256": "e3b0c442...",
      "size": 1048576,
      "detected_type": "image/png",
      "extraction_method": "ORIGINAL_UPLOAD",
      "source_offset": 0,
      "recursion_depth": 0,
      "children": [
        {
          "id": "evid_02",
          "analysis_id": "3fa85f64...",
          "parent_id": "evid_01",
          "name": "extracted_payload_0.zip",
          "sha256": "a4f89d...",
          "size": 4096,
          "detected_type": "application/zip",
          "extraction_method": "LSB_RGB_P0",
          "source_offset": 0,
          "recursion_depth": 1,
          "children": []
        }
      ]
    }
  ]
  ```

### 3.6 Get Forensic Report
- **`GET /api/v1/analyses/{id}/report?format=markdown|json`**
- **Response**: Returns structured JSON or rendered Markdown document with full audit attribution.
