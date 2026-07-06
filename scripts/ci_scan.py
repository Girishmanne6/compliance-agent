#!/usr/bin/env python3
"""CI scanner: scan changed files and fail on critical violations."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.opa_checker import check_policies
from agent.scanner import scan_code

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".tf": "terraform",
    ".js": "javascript",
}

SCANNABLE_EXTENSIONS = set(EXTENSION_TO_LANGUAGE)


def _detect_language(path: str) -> str | None:
    ext = Path(path).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext)


def _get_changed_files(base_ref: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRT", f"{base_ref}...HEAD"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRT", base_ref, "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        )
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return [f for f in files if _detect_language(f) is not None]


def _scan_file(file_path: str) -> list[dict]:
    full_path = ROOT / file_path
    if not full_path.exists():
        return []
    language = _detect_language(file_path)
    if not language:
        return []
    code = full_path.read_text(encoding="utf-8", errors="ignore")
    violations = [*scan_code(code, language), *check_policies(code, language)]
    for violation in violations:
        violation["file_path"] = file_path
    return violations


def _build_markdown(files_scanned: list[str], all_violations: list[dict]) -> str:
    critical = [v for v in all_violations if v.get("severity") == "critical"]
    medium = [v for v in all_violations if v.get("severity") == "medium"]
    low = [v for v in all_violations if v.get("severity") == "low"]

    status = "[BLOCKED] Critical violations found" if critical else "[PASSED] No critical violations"
    lines = [
        "## Compliance Agent Scan Results",
        "",
        status,
        "",
        f"**Files scanned:** {len(files_scanned)}",
        f"**Total violations:** {len(all_violations)} "
        f"(critical: {len(critical)}, medium: {len(medium)}, low: {len(low)})",
        "",
    ]

    if not files_scanned:
        lines.append("No scannable files (.py, .tf, .js) changed in this PR.")
        return "\n".join(lines)

    if all_violations:
        lines.append("| Severity | Rule | File | Line | Message |")
        lines.append("|----------|------|------|------|---------|")
        for v in sorted(all_violations, key=lambda x: (x.get("severity", ""), x.get("file_path", ""))):
            sev = v.get("severity", "low")
            lines.append(
                f"| {sev} | `{v.get('rule_id', '?')}` | `{v.get('file_path', '-')}` "
                f"| {v.get('line_number', '?')} | {v.get('message', '')} |"
            )
    else:
        lines.append("No violations detected in changed files.")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan changed files for compliance violations.")
    parser.add_argument("--base", default="origin/main", help="Base ref for git diff")
    parser.add_argument("--files", nargs="*", help="Explicit file list (overrides git diff)")
    parser.add_argument("--output-json", help="Write results JSON to this path")
    parser.add_argument("--output-markdown", help="Write PR comment markdown to this path")
    args = parser.parse_args()

    files = args.files if args.files else _get_changed_files(args.base)
    all_violations: list[dict] = []
    for file_path in files:
        all_violations.extend(_scan_file(file_path))

    critical_count = sum(1 for v in all_violations if v.get("severity") == "critical")
    result = {
        "files_scanned": files,
        "total_violations": len(all_violations),
        "critical": critical_count,
        "medium": sum(1 for v in all_violations if v.get("severity") == "medium"),
        "low": sum(1 for v in all_violations if v.get("severity") == "low"),
        "violations": all_violations,
        "passed": critical_count == 0,
    }

    markdown = _build_markdown(files, all_violations)
    print(markdown)

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.output_markdown:
        Path(args.output_markdown).write_text(markdown, encoding="utf-8")

    # Also write to GITHUB_OUTPUT if available
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(f"passed={'true' if result['passed'] else 'false'}\n")
            fh.write(f"critical_count={critical_count}\n")
            fh.write("comment<<EOF\n")
            fh.write(markdown)
            fh.write("\nEOF\n")

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
