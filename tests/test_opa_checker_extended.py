from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent.opa_checker import (
    MESSAGE_RULE_MAP,
    _extract_line,
    _find_line_number,
    _manual_policy_fallback,
    _run_opa_eval,
    check_policies,
)


def test_find_line_number_returns_first_match() -> None:
    code = "line1\npassword = 'x'\nline3\n"
    assert _find_line_number(code, "password =") == 2


def test_find_line_number_defaults_to_one() -> None:
    assert _find_line_number("clean code", "missing") == 1


def test_extract_line_empty_marker() -> None:
    assert _extract_line("any code", "") == ""


def test_manual_fallback_detects_exec() -> None:
    messages = _manual_policy_fallback("result = exec(cmd)")
    assert "Use of exec() is a security risk" in messages


def test_manual_fallback_detects_secret_token() -> None:
    messages = _manual_policy_fallback('token = "abc"')
    assert "Hardcoded secret detected" in messages


def test_manual_fallback_clean_code() -> None:
    messages = _manual_policy_fallback("x = 1\n")
    assert messages == []


def test_check_policies_uses_fallback_when_opa_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.opa_checker.shutil.which", lambda _: None)
    violations = check_policies('password = "x"\n', "python")
    assert len(violations) >= 1
    assert violations[0]["source"] == "opa-fallback"
    assert violations[0]["rule_id"] == "OPA_HARDCODED_PASSWORD"


def test_check_policies_uses_fallback_on_opa_eval_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.opa_checker.shutil.which", lambda _: "/usr/bin/opa")
    monkeypatch.setattr(
        "agent.opa_checker._run_opa_eval",
        lambda _: (_ for _ in ()).throw(RuntimeError("OPA evaluation failed")),
    )
    violations = check_policies('eval("1")', "python")
    assert any(v["source"] == "opa-fallback" for v in violations)


def test_check_policies_unknown_message_uses_default_rule() -> None:
    with patch("agent.opa_checker._run_opa_eval", return_value=["Some unknown policy message"]):
        violations = check_policies("code", "python")
    assert len(violations) == 1
    assert violations[0]["rule_id"] == "OPA_POLICY"
    assert violations[0]["severity"] == "medium"


def test_run_opa_eval_raises_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.opa_checker.shutil.which", lambda _: None)
    with pytest.raises(FileNotFoundError):
        _run_opa_eval("/tmp/input.json")


def test_run_opa_eval_raises_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.opa_checker.shutil.which", lambda _: "/usr/bin/opa")

    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = "malformed rego input"

    monkeypatch.setattr("agent.opa_checker.subprocess.run", lambda *a, **k: FakeResult())
    with pytest.raises(RuntimeError, match="malformed rego input"):
        _run_opa_eval("/tmp/input.json")


def test_run_opa_eval_parses_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.opa_checker.shutil.which", lambda _: "/usr/bin/opa")

    class FakeResult:
        returncode = 0
        stdout = json.dumps({"result": [{"expressions": [{"value": ["Hardcoded password detected"]}]}]})
        stderr = ""

    monkeypatch.setattr("agent.opa_checker.subprocess.run", lambda *a, **k: FakeResult())
    messages = _run_opa_eval("/tmp/input.json")
    assert messages == ["Hardcoded password detected"]


def test_run_opa_eval_empty_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agent.opa_checker.shutil.which", lambda _: "/usr/bin/opa")

    class FakeResult:
        returncode = 0
        stdout = json.dumps({"result": []})
        stderr = ""

    monkeypatch.setattr("agent.opa_checker.subprocess.run", lambda *a, **k: FakeResult())
    assert _run_opa_eval("/tmp/input.json") == []


def test_message_rule_map_covers_all_fallback_messages() -> None:
    code_samples = {
        "Hardcoded password detected": 'password = "x"',
        "Hardcoded secret detected": "api_key = 1",
        "Use of eval() is a security risk": "eval(1)",
        "Use of exec() is a security risk": "exec(1)",
        "Open security group detected in IaC": "0.0.0.0/0",
        "Unsafe deserialization with pickle detected": "pickle.loads(b)",
        "S3 bucket encryption is missing": 'resource "aws_s3_bucket" "x" {}',
        "Wildcard IAM permissions detected": 'actions = ["*"]',
    }
    for message, code in code_samples.items():
        assert message in MESSAGE_RULE_MAP or message in _manual_policy_fallback(code)
