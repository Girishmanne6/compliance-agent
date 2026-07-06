from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from agent.github_scanner import GitHubAccessDeniedError

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_code"


class TestScanEndpoint:
    def test_scan_requires_api_key_when_configured(
        self, client: TestClient, api_key: str, vulnerable_python: str
    ) -> None:
        response = client.post("/scan", json={"code": vulnerable_python, "language": "python"})
        assert response.status_code == 401

        response = client.post(
            "/scan",
            json={"code": vulnerable_python, "language": "python"},
            headers={"X-API-Key": api_key},
        )
        assert response.status_code == 200

    def test_scan_without_api_key_when_unconfigured(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, vulnerable_python: str
    ) -> None:
        monkeypatch.delenv("API_KEY", raising=False)
        response = client.post("/scan", json={"code": vulnerable_python, "language": "python"})
        assert response.status_code == 200

    def test_scan_empty_code_rejected(self, client: TestClient, auth_headers: dict) -> None:
        response = client.post("/scan", json={"code": "", "language": "python"}, headers=auth_headers)
        assert response.status_code == 422

    def test_scan_returns_step_timings(
        self, client: TestClient, auth_headers: dict, vulnerable_python: str
    ) -> None:
        response = client.post(
            "/scan",
            json={"code": vulnerable_python, "language": "python"},
            headers=auth_headers,
        )
        report = response.json()
        assert "step_timings_ms" in report
        assert "semgrep" in report["step_timings_ms"]


class TestScanRepoEndpoint:
    def test_scan_repo_invalid_url(self, client: TestClient, auth_headers: dict) -> None:
        response = client.post(
            "/scan-repo",
            json={"repo_url": "https://not-github.com/x/y", "language": "all"},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_scan_repo_private_repo(self, client: TestClient, auth_headers: dict) -> None:
        with patch("app.fetch_repo_files", side_effect=GitHubAccessDeniedError("private repo — access denied")):
            response = client.post(
                "/scan-repo",
                json={"repo_url": "https://github.com/private/repo", "language": "all"},
                headers=auth_headers,
            )
        assert response.status_code == 403

    def test_scan_repo_no_matching_files(self, client: TestClient, auth_headers: dict) -> None:
        with patch("app.fetch_repo_files", return_value={"files": [], "total_candidates": 0, "truncated": False, "max_files": 25}):
            response = client.post(
                "/scan-repo",
                json={"repo_url": "https://github.com/user/empty", "language": "python"},
                headers=auth_headers,
            )
        assert response.status_code == 400

    def test_scan_repo_success_with_truncation_metadata(self, client: TestClient, auth_headers: dict) -> None:
        code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
        mock_result = {
            "files": [{"path": "sample_code/vulnerable.py", "language": "python", "content": code}],
            "total_candidates": 50,
            "scanned_files": 1,
            "truncated": True,
            "max_files": 25,
        }
        with patch("app.fetch_repo_files", return_value=mock_result):
            response = client.post(
                "/scan-repo",
                json={"repo_url": "https://github.com/user/repo", "language": "python"},
                headers=auth_headers,
            )
        assert response.status_code == 200
        report = response.json()
        assert report["scan_metadata"]["truncated"] is True
        assert report["scan_metadata"]["total_candidates"] == 50

    def test_scan_repo_rate_limited(self, client: TestClient, auth_headers: dict, monkeypatch: pytest.MonkeyPatch) -> None:
        from agent.rate_limit import TokenBucketLimiter

        limiter = TokenBucketLimiter(max_requests=1, window_seconds=60)
        monkeypatch.setattr("agent.rate_limit.repo_scan_limiter", limiter)

        mock_result = {
            "files": [{"path": "a.py", "language": "python", "content": "x=1"}],
            "total_candidates": 1,
            "scanned_files": 1,
            "truncated": False,
            "max_files": 25,
        }
        with patch("app.fetch_repo_files", return_value=mock_result):
            r1 = client.post(
                "/scan-repo",
                json={"repo_url": "https://github.com/user/repo", "language": "python"},
                headers=auth_headers,
            )
            r2 = client.post(
                "/scan-repo",
                json={"repo_url": "https://github.com/user/repo", "language": "python"},
                headers=auth_headers,
            )
        assert r1.status_code == 200
        assert r2.status_code == 429


class TestPublicEndpoints:
    def test_health_is_public(self, client: TestClient) -> None:
        assert client.get("/health").status_code == 200

    def test_index_is_public(self, client: TestClient) -> None:
        assert client.get("/").status_code == 200

    def test_stats_is_public(self, client: TestClient, auth_headers: dict, vulnerable_python: str) -> None:
        client.post(
            "/scan",
            json={"code": vulnerable_python, "language": "python"},
            headers=auth_headers,
        )
        response = client.get("/stats")
        assert response.status_code == 200
        assert response.json()["total_scans"] >= 1

    def test_history_returns_list(self, client: TestClient, auth_headers: dict, vulnerable_python: str) -> None:
        client.post(
            "/scan",
            json={"code": vulnerable_python, "language": "python"},
            headers=auth_headers,
        )
        response = client.get("/history")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        assert len(response.json()) >= 1

    def test_report_not_found(self, client: TestClient) -> None:
        assert client.get("/report/does-not-exist").status_code == 404
        assert client.get("/report/does-not-exist/html").status_code == 404
