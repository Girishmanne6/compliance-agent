from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SEMGRP_RULESETS = {
    "python": ["p/python", "p/owasp-top-ten", "p/secrets"],
    "terraform": ["p/terraform", "p/owasp-top-ten", "p/secrets"],
    "javascript": ["p/owasp-top-ten", "p/secrets"],
}

EXTENSIONS = {
    "python": ".py",
    "terraform": ".tf",
    "javascript": ".js",
}


def _normalize_severity(raw_severity: str | None) -> str:
    value = (raw_severity or "low").strip().lower()
    if value in {"critical", "high", "error"}:
        return "critical"
    if value in {"medium", "warning"}:
        return "medium"
    return "low"



def _build_semgrep_args(configs: list[str], target_path: str) -> list[str]:
    args = ["scan", "--json", "--quiet", "--error", "--metrics=off"]
    for config in configs:
        args.extend(["--config", config])
    args.append(target_path)
    return args



def _run_semgrep_in_process(args: list[str]) -> str | None:
    try:
        from semgrep.__main__ import main as semgrep_main
    except Exception:
        return None

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    original_argv = sys.argv[:]

    try:
        sys.argv = ["semgrep", *args]
        with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(stderr_buffer):
            try:
                semgrep_main()
            except SystemExit:
                pass
    finally:
        sys.argv = original_argv

    output = stdout_buffer.getvalue().strip()
    return output or None



def _run_semgrep_subprocess(args: list[str]) -> str:
    semgrep_binary = Path(sys.executable).with_name("semgrep")
    if semgrep_binary.exists():
        command = [os.fspath(semgrep_binary), *args]
    else:
        resolved_binary = shutil.which("semgrep")
        if not resolved_binary:
            raise FileNotFoundError("Semgrep binary not found")
        command = [resolved_binary, *args]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.stdout.strip():
        return completed.stdout
    if completed.stderr.strip():
        raise RuntimeError(completed.stderr.strip())
    raise RuntimeError("Semgrep produced no output.")



def _extract_snippet(result: dict[str, Any], source_code: str) -> str:
    extra = result.get("extra", {})
    snippet = extra.get("lines")
    if isinstance(snippet, str) and snippet.strip():
        return snippet.rstrip()

    start_line = ((result.get("start") or {}).get("line"))
    if isinstance(start_line, int) and start_line > 0:
        lines = source_code.splitlines()
        index = start_line - 1
        if index < len(lines):
            return lines[index].rstrip()
    return ""



def scan_code(code: str, language: str) -> list[dict[str, Any]]:
    normalized_language = language.strip().lower()
    configs = SEMGRP_RULESETS.get(normalized_language, ["p/owasp-top-ten", "p/secrets"])
    suffix = EXTENSIONS.get(normalized_language, ".txt")

    with tempfile.TemporaryDirectory() as temp_dir:
        target_path = Path(temp_dir) / f"scan_target{suffix}"
        target_path.write_text(code, encoding="utf-8")
        args = _build_semgrep_args(configs, os.fspath(target_path))

        try:
            output = _run_semgrep_in_process(args)
            if output is None:
                output = _run_semgrep_subprocess(args)
            payload = json.loads(output)
        except FileNotFoundError:
            return [
                {
                    "rule_id": "SemgrepUnavailable",
                    "severity": "low",
                    "message": "Semgrep is not installed in the runtime environment.",
                    "line_number": 1,
                    "code_snippet": "",
                    "source": "semgrep",
                }
            ]
        except Exception as exc:
            return [
                {
                    "rule_id": "SemgrepExecutionError",
                    "severity": "low",
                    "message": f"Semgrep scan could not be completed: {exc}",
                    "line_number": 1,
                    "code_snippet": "",
                    "source": "semgrep",
                }
            ]

    violations: list[dict[str, Any]] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        line_number = ((result.get("start") or {}).get("line")) or 1
        violations.append(
            {
                "rule_id": result.get("check_id", "unknown-rule"),
                "severity": _normalize_severity(extra.get("severity")),
                "message": extra.get("message", "Semgrep reported a violation."),
                "line_number": line_number,
                "code_snippet": _extract_snippet(result, code),
                "source": "semgrep",
            }
        )
    return violations
