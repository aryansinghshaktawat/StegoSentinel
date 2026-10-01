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

    # 6. Check Evidence Hierarchy Tree
    evidence_resp = client.get(f"/api/v1/analyses/{analysis_id}/evidence", headers=analyst_headers)
    assert evidence_resp.status_code == 200
    evidence_tree = evidence_resp.json()
    assert len(evidence_tree) > 0
    root_node = evidence_tree[0]
    assert root_node["recursion_depth"] == 0
    # Child payload node should exist in tree
    assert len(root_node["children"]) > 0

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

    # 9. Check Audit Events
    events_resp = client.get(f"/api/v1/analyses/{analysis_id}/events", headers=analyst_headers)
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 3
    action_names = [e["action"] for e in events]
    assert "FILE_UPLOAD_QUARANTINED" in action_names
    assert "ANALYSIS_STARTED" in action_names
    assert "ANALYSIS_COMPLETED" in action_names
