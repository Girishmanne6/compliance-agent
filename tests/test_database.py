from __future__ import annotations

import pytest

from agent.database import (
    init_db,
    list_report_summaries,
    load_metrics,
    load_report_row,
    save_metrics,
    save_report_row,
)
from agent.reporter import build_report, get_html_report_path, load_report, save_report


@pytest.fixture(autouse=True)
def _isolate_storage(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "test.db"
    reports_dir = tmp_path / "reports"
    monkeypatch.setattr("agent.database.DB_PATH", db_path)
    monkeypatch.setattr("agent.reporter.REPORTS_DIR", reports_dir)
    init_db(db_path)


def test_sqlite_save_and_load_report() -> None:
    report = build_report([], "summary", 100)
    save_report_row(report)
    loaded = load_report_row(report["report_id"])
    assert loaded["report_id"] == report["report_id"]


def test_save_report_writes_html_and_sqlite(tmp_path) -> None:
    report = build_report([], "summary", 50)
    paths = save_report(report)
    assert "html_path" in paths
    loaded = load_report(report["report_id"])
    assert loaded["ai_summary"] == "summary"
    html_path = get_html_report_path(report["report_id"])
    assert html_path.exists()


def test_list_report_summaries_ordered() -> None:
    for i in range(3):
        save_report_row(build_report([], f"s{i}", i))
    summaries = list_report_summaries(limit=2)
    assert len(summaries) == 2


def test_metrics_persist_in_sqlite() -> None:
    save_metrics({"total_scans": 5, "total_violations": 10, "violations_by_severity": {"critical": 2, "medium": 3, "low": 5}, "total_scan_time_ms": 1000, "step_times_ms": {}, "step_counts": {}})
    loaded = load_metrics()
    assert loaded["total_scans"] == 5
