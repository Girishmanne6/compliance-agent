from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import app

SAMPLE_DIR = ROOT / "sample_code"


@pytest.fixture
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "test.db"
    monkeypatch.setattr("agent.database.DB_PATH", path)
    monkeypatch.setattr("agent.reporter.REPORTS_DIR", tmp_path / "reports")
    return path


@pytest.fixture
def client(db_path: Path) -> TestClient:
    return TestClient(app)


@pytest.fixture
def api_key(monkeypatch: pytest.MonkeyPatch) -> str:
    key = "test-secret-key"
    monkeypatch.setenv("API_KEY", key)
    return key


@pytest.fixture
def auth_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


@pytest.fixture
def vulnerable_python() -> str:
    return (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")


@pytest.fixture
def vulnerable_terraform() -> str:
    return (SAMPLE_DIR / "infra.tf").read_text(encoding="utf-8")


@pytest.fixture
def mock_github_tree() -> list[dict]:
    return [
        {"type": "blob", "path": "deep/nested/file.py"},
        {"type": "blob", "path": "sample_code/vulnerable.py"},
        {"type": "blob", "path": "app.py"},
        {"type": "blob", "path": "infra.tf"},
    ]
