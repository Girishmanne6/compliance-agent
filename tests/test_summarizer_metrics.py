from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.metrics import get_stats, record_scan
from agent.summarizer import _deterministic_summary, generate_summary


def test_deterministic_summary_with_violations() -> None:
    violations = [
        {"rule_id": "OPA_EVAL", "severity": "critical", "message": "eval risk", "line_number": 5},
        {"rule_id": "LOW_RULE", "severity": "low", "message": "minor", "line_number": 10},
    ]
    summary = _deterministic_summary(violations)
    assert "Executive Summary" in summary
    assert "Critical Issues" in summary
    assert "OPA_EVAL" in summary
    assert "Recommended Actions" in summary


def test_deterministic_summary_no_violations() -> None:
    summary = _deterministic_summary([])
    assert "No security" in summary


def test_generate_summary_without_api_key_uses_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    violations = [{"rule_id": "R1", "severity": "critical", "message": "bad", "line_number": 1}]
    summary = generate_summary(violations)
    assert "Executive Summary" in summary
    assert "⚠️" not in summary


def test_record_scan_and_get_stats(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.database.DB_PATH", tmp_path / "metrics.db")

    violations = [
        {"severity": "critical"},
        {"severity": "medium"},
    ]
    record_scan(violations, 500, {"semgrep": 300, "opa": 100, "ai_summary": 100})
    stats = get_stats()
    assert stats["total_scans"] == 1
    assert stats["total_violations"] == 2
    assert stats["violations_by_severity"]["critical"] == 1
    assert stats["average_scan_time_ms"] == 500
    assert stats["average_step_time_ms"]["semgrep"] == 300
