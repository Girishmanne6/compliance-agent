from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_code"


def test_full_scan_pipeline_detects_vulnerable_python(client: TestClient) -> None:
    code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
    response = client.post("/scan", json={"code": code, "language": "python"})
    assert response.status_code == 200
    report = response.json()

    assert report["total_violations"] > 0
    assert report["critical"] > 0
    assert report["scan_type"] == "paste"
    assert "report_id" in report
    assert "ai_summary" in report
    assert "step_timings_ms" in report
    assert isinstance(report["violations"], list)

    rule_ids = {v["rule_id"] for v in report["violations"]}
    assert len(rule_ids) > 0


def test_scan_secure_python_has_fewer_critical_than_vulnerable(client: TestClient) -> None:
    vuln_code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
    secure_code = (SAMPLE_DIR / "secure.py").read_text(encoding="utf-8")

    vuln_resp = client.post("/scan", json={"code": vuln_code, "language": "python"})
    secure_resp = client.post("/scan", json={"code": secure_code, "language": "python"})

    assert vuln_resp.json()["critical"] > secure_resp.json()["critical"]


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_stats_endpoint_returns_metrics(client: TestClient) -> None:
    code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
    client.post("/scan", json={"code": code, "language": "python"})
    response = client.get("/stats")
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_scans"] >= 1
    assert "violations_by_severity" in stats
    assert "average_scan_time_ms" in stats


def test_report_retrieval_after_scan(client: TestClient) -> None:
    code = 'password = "test"\n'
    scan_resp = client.post("/scan", json={"code": code, "language": "python"})
    report_id = scan_resp.json()["report_id"]

    get_resp = client.get(f"/report/{report_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["report_id"] == report_id

    html_resp = client.get(f"/report/{report_id}/html")
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["content-type"]
