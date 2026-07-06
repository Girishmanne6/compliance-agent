from __future__ import annotations

from pathlib import Path

from agent.scanner import _normalize_severity, scan_code

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_code"


def test_normalize_severity_maps_high_to_critical() -> None:
    assert _normalize_severity("high") == "critical"
    assert _normalize_severity("error") == "critical"


def test_normalize_severity_maps_warning_to_medium() -> None:
    assert _normalize_severity("warning") == "medium"


def test_normalize_severity_defaults_to_low() -> None:
    assert _normalize_severity(None) == "low"
    assert _normalize_severity("info") == "low"


def test_scan_vulnerable_python_finds_violations() -> None:
    code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
    violations = scan_code(code, "python")
    assert isinstance(violations, list)
    assert len(violations) > 0
    assert all("rule_id" in v for v in violations)
    assert all("severity" in v for v in violations)
    assert all(v["source"] == "semgrep" for v in violations)


def test_scan_returns_semgrep_unavailable_fallback_when_not_installed() -> None:
    violations = scan_code("x = 1\n", "python")
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "SemgrepUnavailable"
    assert violations[0]["source"] == "semgrep"


def test_scan_returns_structured_violation() -> None:
    code = 'password = "secret"\n'
    violations = scan_code(code, "python")
    assert len(violations) >= 1
    violation = violations[0]
    assert "rule_id" in violation
    assert "message" in violation
    assert "line_number" in violation
    assert "code_snippet" in violation
