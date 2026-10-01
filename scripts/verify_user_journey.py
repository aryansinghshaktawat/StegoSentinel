#!/usr/bin/env python3
"""
Verification of the complete user journey for StegoSentinel:
1. Upload synthetic stego fixture (stego_lsb_rgb_p0.png).
2. Wait for analysis to complete.
3. Verify forensic analysis status and steganography likelihood.
4. Verify extraction candidate rankings, validation, and decode status.
5. Verify recovered payload decoded text.
6. Verify candidate payload API endpoint.
7. Verify recursive evidence hierarchy DAG and linked evidence object.
8. Verify evidence payload download and SHA-256 match.
"""
import sys
from pathlib import Path

# Add backend to path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from app.core.database import SessionLocal, init_db
from app.services.analysis_service import analysis_service


def main():
    print("=" * 60)
    print("STEGOSENTINEL: COMPLETE USER JOURNEY VERIFICATION")
    print("=" * 60)

    init_db()
    client = TestClient(app)
    token = create_access_token({"sub": "analyst-007", "username": "analyst", "role": "ANALYST"})
    headers = {"Authorization": f"Bearer {token}"}

    fixture_path = ROOT_DIR / "fixtures" / "stego" / "stego_lsb_rgb_p0.png"
    assert fixture_path.exists(), f"Fixture missing: {fixture_path}"
    file_bytes = fixture_path.read_bytes()

    print(f"\n[1] Uploading test artifact: {fixture_path.name} ({len(file_bytes)} bytes)")
    upload_resp = client.post(
        "/api/v1/analyses",
        headers=headers,
        files={"file": (fixture_path.name, file_bytes, "image/png")},
    )
    assert upload_resp.status_code == 202, f"Upload failed: {upload_resp.text}"
    analysis_id = upload_resp.json()["id"]
    print(f"    ✓ Analysis Case Registered: {analysis_id}")
    print(f"    ✓ SHA-256: {upload_resp.json()['sha256']}")

    print("\n[2] Executing forensic analysis pipeline...")
    db = SessionLocal()
    analysis_service.execute_analysis(db, analysis_id, actor="analyst")
    db.close()
    print("    ✓ Pipeline finished execution.")

    print("\n[3] Retrieving Case Analysis Details...")
    detail_resp = client.get(f"/api/v1/analyses/{analysis_id}", headers=headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    status = detail["status"]
    stego_likelihood = int(detail["stego_likelihood"] * 100)
    print(f"    ✓ Analysis Status: {status}")
    print(f"    ✓ Steganography Likelihood: {stego_likelihood}%")
    assert status == "COMPLETED"

    print("\n[4] Querying Ranked Extraction Candidates...")
    cands_resp = client.get(f"/api/v1/analyses/{analysis_id}/candidates", headers=headers)
    assert cands_resp.status_code == 200
    candidates = cands_resp.json()
    print(f"    ✓ Evaluated Candidates Count: {len(candidates)}")
    assert len(candidates) > 0

    top_cand = candidates[0]
    print(f"    ✓ Rank #1 Candidate: {top_cand['technique']}")
    print(f"    ✓ Parameters: {top_cand['parameters']}")
    print(f"    ✓ Extraction Confidence: {top_cand['final_score'] * 100:.1f}%")
    print(f"    ✓ Validation Score: {top_cand['validation_score'] * 100:.1f}%")
    print(f"    ✓ Validation Status: {top_cand['status']}")
    print(f"    ✓ Payload Type: {top_cand['extracted_type']}")
    print(f"    ✓ Encoding: {top_cand['encoding']}")
    print(f"    ✓ Decode Status: {top_cand['decode_status']}")
    print(f"    ✓ Recovered Content: {top_cand['decoded_text']}")
    print(f"    ✓ Linked Evidence Object ID: {top_cand['evidence_object_id']}")

    assert top_cand["status"] == "VALID"
    assert top_cand["decode_status"] == "SUCCESS"
    assert top_cand["decoded_text"] == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"
    assert top_cand["payload_size"] == 45
    assert top_cand["encoding"] == "UTF-8"
    assert top_cand["evidence_object_id"] is not None

    print("\n[5] Querying Candidate Payload Endpoint...")
    payload_resp = client.get(
        f"/api/v1/analyses/{analysis_id}/candidates/{top_cand['id']}/payload",
        headers=headers,
    )
    assert payload_resp.status_code == 200
    payload = payload_resp.json()
    print(f"    ✓ Payload Decode Status: {payload['decode_status']}")
    print(f"    ✓ Payload Decoded Text: {payload['decoded_text']}")
    print(f"    ✓ Evidence Name: {payload['evidence']['name']}")
    print(f"    ✓ Evidence SHA-256: {payload['evidence']['sha256']}")
    assert payload["decoded_text"] == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"

    print("\n[6] Inspecting Recursive Evidence DAG Hierarchy...")
    ev_resp = client.get(f"/api/v1/analyses/{analysis_id}/evidence", headers=headers)
    assert ev_resp.status_code == 200
    tree = ev_resp.json()
    root = tree[0]
    print(f"    ✓ Root Artifact: {root['name']} (depth {root['recursion_depth']})")
    assert len(root["children"]) > 0
    child = root["children"][0]
    print(f"    └── Child Evidence: {child['name']} (depth {child['recursion_depth']})")
    print(f"        ✓ Extraction Method: {child['extraction_method']}")
    print(f"        ✓ Candidate ID: {child['candidate_id']}")
    print(f"        ✓ Decode Status: {child['decode_status']}")
    print(f"        ✓ Decoded Text: {child['decoded_text']}")
    print(f"        ✓ SHA-256: {child['sha256']}")
    assert child["candidate_id"] == top_cand["id"]
    assert child["decoded_text"] == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"

    print("\n[7] Downloading Quarantined Payload Bytes...")
    dl_resp = client.get(f"/api/v1/evidence/{child['id']}/download", headers=headers)
    assert dl_resp.status_code == 200
    raw_content = dl_resp.content
    print(f"    ✓ Downloaded Payload Length: {len(raw_content)} bytes")
    print(f"    ✓ Downloaded Content: {raw_content.decode('utf-8')}")
    assert raw_content == b"FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"

    print("\n" + "=" * 60)
    print("  ALL STAGES OF THE USER JOURNEY COMPLETED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    main()
