"""
End-to-End integration tests for StegoSentinel analysis pipeline.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from app.services.analysis_service import analysis_service


def test_full_analysis_pipeline_e2e(
    client: TestClient, db_session, analyst_headers, fixtures_path: Path
):
    stego_png = fixtures_path / "stego" / "stego_lsb_rgb_p0.png"
    file_bytes = stego_png.read_bytes()

    # 1. Upload File
    upload_resp = client.post(
        "/api/v1/analyses",
        headers=analyst_headers,
        files={"file": (stego_png.name, file_bytes, "image/png")},
    )
    assert upload_resp.status_code == 202
    analysis_data = upload_resp.json()
    analysis_id = analysis_data["id"]
    assert analysis_data["status"] == "PENDING"
    assert analysis_data["sha256"] != ""

    # 2. Run Analysis Service directly synchronously
    analysis_service.execute_analysis(db_session, analysis_id, actor="test_analyst")

    # 3. Retrieve Analysis Details
    detail_resp = client.get(f"/api/v1/analyses/{analysis_id}", headers=analyst_headers)
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["status"] == "COMPLETED"
    assert detail["stego_likelihood"] is not None
    assert detail["stego_likelihood"] >= 0.70  # Elevated likelihood for stego artifact

    # 4. Check Findings
    findings_resp = client.get(f"/api/v1/analyses/{analysis_id}/findings", headers=analyst_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) > 0
    assert any("ENTROPY" in f["type"] or "BIT_PLANE" in f["type"] for f in findings)

    # 5. Check Candidates
    candidates_resp = client.get(
        f"/api/v1/analyses/{analysis_id}/candidates", headers=analyst_headers
    )
    assert candidates_resp.status_code == 200
    candidates = candidates_resp.json()
    assert len(candidates) > 0
    top_cand = candidates[0]
    assert top_cand["final_score"] > 0.60
    assert top_cand["status"] == "VALID"
    assert top_cand["extracted_type"] == "text/plain"
    assert top_cand["decode_status"] == "SUCCESS"
    assert top_cand["decoded_text"] == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"
    assert top_cand["payload_size"] == 45
    assert top_cand["encoding"] == "UTF-8"
    assert top_cand["evidence_object_id"] is not None

    # 5b. Check Candidate Payload Endpoint
    payload_resp = client.get(
        f"/api/v1/analyses/{analysis_id}/candidates/{top_cand['id']}/payload",
        headers=analyst_headers,
    )
    assert payload_resp.status_code == 200
    payload_data = payload_resp.json()
    assert payload_data["decode_status"] == "SUCCESS"
    assert payload_data["decoded_text"] == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"
    assert payload_data["type"] == "text/plain"
    assert payload_data["payload_size"] == 45
    assert payload_data["evidence_object_id"] == top_cand["evidence_object_id"]
    assert payload_data["evidence"] is not None
    assert payload_data["evidence"]["detected_type"] == "text/plain"
    assert payload_data["evidence"]["size"] == 45

    # 6. Check Evidence Hierarchy Tree
    evidence_resp = client.get(f"/api/v1/analyses/{analysis_id}/evidence", headers=analyst_headers)
    assert evidence_resp.status_code == 200
    evidence_tree = evidence_resp.json()
    assert len(evidence_tree) > 0
    root_node = evidence_tree[0]
    assert root_node["recursion_depth"] == 0
    # Child payload node should exist in tree and link to the winning candidate
    assert len(root_node["children"]) > 0
    child_node = root_node["children"][0]
    assert child_node["id"] == top_cand["evidence_object_id"]
    assert child_node["candidate_id"] == top_cand["id"]
    assert child_node["decode_status"] == "SUCCESS"
    assert child_node["decoded_text"] == "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"

    # 6b. Download evidence payload and confirm contents
    dl_resp = client.get(
        f"/api/v1/evidence/{child_node['id']}/download", headers=analyst_headers
    )
    assert dl_resp.status_code == 200
    assert dl_resp.content == b"FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}"

    # 7. Check JSON Report
    report_json_resp = client.get(
        f"/api/v1/analyses/{analysis_id}/report?format=json", headers=analyst_headers
    )
    assert report_json_resp.status_code == 200
    report_json = report_json_resp.json()
    assert "result" in report_json
    assert "executive_summary" in report_json["result"]

    # 8. Check Markdown Report
    report_md_resp = client.get(
        f"/api/v1/analyses/{analysis_id}/report?format=markdown", headers=analyst_headers
    )
    assert report_md_resp.status_code == 200
    assert "# StegoSentinel Forensic Analysis Report" in report_md_resp.text
    assert "FLAG{STEGOSENTINEL_FORENSIC_LSB_EXTRACTED_OK}" in report_md_resp.text


    # 9. Check Audit Events
    events_resp = client.get(f"/api/v1/analyses/{analysis_id}/events", headers=analyst_headers)
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 3
    action_names = [e["action"] for e in events]
    assert "FILE_UPLOAD_QUARANTINED" in action_names
    assert "ANALYSIS_STARTED" in action_names
    assert "ANALYSIS_COMPLETED" in action_names
