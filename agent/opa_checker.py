from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "security.rego"

MESSAGE_RULE_MAP = {
    "Hardcoded password detected": ("OPA_HARDCODED_PASSWORD", "critical", "password ="),
    "Hardcoded secret detected": ("OPA_HARDCODED_SECRET", "critical", "api_key"),
    "Use of eval() is a security risk": ("OPA_EVAL", "critical", "return eval("),
    "Use of exec() is a security risk": ("OPA_EXEC", "critical", "exec("),
    "Open security group detected in IaC": ("OPA_OPEN_CIDR", "critical", "0.0.0.0/0"),
    "Unsafe deserialization with pickle detected": ("OPA_PICKLE", "critical", "pickle.loads"),
    "S3 bucket encryption is missing": ("OPA_S3_ENCRYPTION", "medium", "aws_s3_bucket"),
    "Wildcard IAM permissions detected": ("OPA_IAM_WILDCARD", "critical", "*"),
}



def _find_line_number(code: str, marker: str) -> int:
    for index, line in enumerate(code.splitlines(), start=1):
        if marker in line:
            return index
    return 1



def _manual_policy_fallback(code: str) -> list[str]:
    messages: list[str] = []
    if "password =" in code:
        messages.append("Hardcoded password detected")
    if any(token in code for token in ["api_key =", "token =", "secret =", "sk-"]):
        messages.append("Hardcoded secret detected")
    if "eval(" in code:
        messages.append("Use of eval() is a security risk")
    if "exec(" in code:
        messages.append("Use of exec() is a security risk")
    if "0.0.0.0/0" in code:
        messages.append("Open security group detected in IaC")
    if "pickle.loads" in code:
        messages.append("Unsafe deserialization with pickle detected")
    if 'resource "aws_s3_bucket"' in code and "server_side_encryption_configuration" not in code:
        messages.append("S3 bucket encryption is missing")
    if "actions" in code and '"*"' in code:
        messages.append("Wildcard IAM permissions detected")
    return messages



def _run_opa_eval(input_path: str) -> list[str]:
    opa_binary = shutil.which("opa")
    if not opa_binary:
        raise FileNotFoundError("OPA binary not found")

    command = [
        opa_binary,
        "eval",
        "--format=json",
        "--data",
        str(POLICY_PATH),
        "--input",
        input_path,
        "data.security.deny",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "OPA evaluation failed")

    payload = json.loads(completed.stdout)
    results = payload.get("result", [])
    if not results:
        return []

    expressions = results[0].get("expressions", [])
    if not expressions:
        return []

    value = expressions[0].get("value", [])
    if isinstance(value, list):
        return [str(item) for item in value]
    return []



def check_policies(code: str, language: str) -> list[dict[str, Any]]:
    del language
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as temp_file:
        json.dump({"code": code}, temp_file)
        temp_path = temp_file.name

    try:
        try:
            messages = _run_opa_eval(temp_path)
            source = "opa"
        except Exception:
            messages = _manual_policy_fallback(code)
            source = "opa-fallback"
    finally:
        Path(temp_path).unlink(missing_ok=True)

    violations: list[dict[str, Any]] = []
    for message in messages:
        rule_id, severity, marker = MESSAGE_RULE_MAP.get(
            message,
            ("OPA_POLICY", "medium", ""),
        )
        violations.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "line_number": _find_line_number(code, marker),
                "code_snippet": _extract_line(code, marker),
                "source": source,
            }
        )
    return violations



def _extract_line(code: str, marker: str) -> str:
    if not marker:
        return ""
    for line in code.splitlines():
        if marker in line:
            return line.rstrip()
    return ""
