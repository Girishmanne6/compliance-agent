from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.reporter import (
    REPORTS_DIR,
    build_report,
    get_html_report_path,
    list_recent_reports,
    load_report,
    save_report,
)


@pytest.fixture(autouse=True)
def _isolate_reports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.database.DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("agent.reporter.REPORTS_DIR", tmp_path)


def test_build_report_counts_severities() -> None:
    violations = [
        {"rule_id": "R1", "severity": "critical", "message": "bad", "line_number": 1},
        {"rule_id": "R2", "severity": "medium", "message": "warn", "line_number": 2},
        {"rule_id": "R3", "severity": "low", "message": "info", "line_number": 3},
    ]
    report = build_report(violations, "summary", 100)
    assert report["total_violations"] == 3
    assert report["critical"] == 1
    assert report["medium"] == 1
    assert report["low"] == 1
    assert report["scan_duration_ms"] == 100
    assert "report_id" in report
    assert "timestamp" in report


def test_build_report_includes_step_timings() -> None:
    report = build_report([], "summary", 50, step_timings={"semgrep": 30, "opa": 10})
    assert report["step_timings_ms"] == {"semgrep": 30, "opa": 10}


def test_save_and_load_report(tmp_path: Path) -> None:
    report = build_report([], "test summary", 42)
    save_report(report)
    loaded = load_report(report["report_id"])
    assert loaded["report_id"] == report["report_id"]
    assert loaded["ai_summary"] == "test summary"
    assert (tmp_path / f"{report['report_id']}.html").exists()


def test_get_html_report_path(tmp_path: Path) -> None:
    report = build_report([], "summary", 10)
    save_report(report)
    html_path = get_html_report_path(report["report_id"])
    assert html_path.exists()
    assert html_path.suffix == ".html"


def test_load_report_raises_for_missing() -> None:
    with pytest.raises(FileNotFoundError):
        load_report("nonexistent-id")


def test_list_recent_reports(tmp_path: Path) -> None:
    for i in range(3):
        save_report(build_report([], f"summary {i}", i * 10))
    recent = list_recent_reports(limit=2)
    assert len(recent) == 2
    assert all("report_id" in r for r in recent)
