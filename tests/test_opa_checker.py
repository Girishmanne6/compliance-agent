from __future__ import annotations

from pathlib import Path

from agent.opa_checker import check_policies

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_code"


def test_check_vulnerable_python_detects_hardcoded_secrets() -> None:
    code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
    violations = check_policies(code, "python")
    rule_ids = {v["rule_id"] for v in violations}
    assert "OPA_HARDCODED_PASSWORD" in rule_ids
    assert "OPA_HARDCODED_SECRET" in rule_ids


def test_check_vulnerable_python_detects_eval_and_pickle() -> None:
    code = (SAMPLE_DIR / "vulnerable.py").read_text(encoding="utf-8")
    violations = check_policies(code, "python")
    rule_ids = {v["rule_id"] for v in violations}
    assert "OPA_EVAL" in rule_ids
    assert "OPA_PICKLE" in rule_ids


def test_check_infra_tf_detects_open_cidr_and_iam() -> None:
    code = (SAMPLE_DIR / "infra.tf").read_text(encoding="utf-8")
    violations = check_policies(code, "terraform")
    rule_ids = {v["rule_id"] for v in violations}
    assert "OPA_OPEN_CIDR" in rule_ids
    assert "OPA_IAM_WILDCARD" in rule_ids
    assert "OPA_S3_ENCRYPTION" in rule_ids


def test_check_secure_python_has_no_critical_violations() -> None:
    code = (SAMPLE_DIR / "secure.py").read_text(encoding="utf-8")
    violations = check_policies(code, "python")
    critical = [v for v in violations if v["severity"] == "critical"]
    assert len(critical) == 0


def test_violation_structure() -> None:
    violations = check_policies('password = "x"\n', "python")
    assert len(violations) >= 1
    v = violations[0]
    assert v["source"] in {"opa", "opa-fallback"}
    assert v["severity"] == "critical"
    assert v["line_number"] >= 1
