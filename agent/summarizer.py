from __future__ import annotations

import os
from typing import Any

from openai import OpenAI


def _deterministic_summary(violations: list[dict[str, Any]]) -> str:
    if not violations:
        return (
            "## Executive Summary\n\n"
            "No security or compliance violations were detected in the scanned code.\n\n"
            "## Recommended Actions\n\n"
            "1. Continue following secure coding practices.\n"
            "2. Re-scan after significant code changes."
        )

    critical = [v for v in violations if v.get("severity") == "critical"]
    medium = [v for v in violations if v.get("severity") == "medium"]
    low = [v for v in violations if v.get("severity") == "low"]

    lines = [
        "## Executive Summary",
        "",
        f"Scan detected **{len(violations)} violation(s)**: "
        f"{len(critical)} critical, {len(medium)} medium, {len(low)} low.",
        "",
    ]

    if critical:
        lines += ["## Critical Issues", ""]
        for v in critical:
            lines.append(
                f"- **{v.get('rule_id', 'unknown')}** (line {v.get('line_number', '?')}): "
                f"{v.get('message', '')}"
            )
        lines.append("")

    if medium:
        lines += ["## Medium Issues", ""]
        for v in medium:
            lines.append(
                f"- **{v.get('rule_id', 'unknown')}** (line {v.get('line_number', '?')}): "
                f"{v.get('message', '')}"
            )
        lines.append("")

    if low:
        lines += ["## Low Issues", ""]
        for v in low:
            lines.append(
                f"- **{v.get('rule_id', 'unknown')}** (line {v.get('line_number', '?')}): "
                f"{v.get('message', '')}"
            )
        lines.append("")

    lines += [
        "## Recommended Actions",
        "",
        "1. Address all critical issues before merging or deploying.",
        "2. Review medium-severity findings and remediate within the current sprint.",
        "3. Schedule low-severity items for backlog cleanup.",
    ]
    return "\n".join(lines)


def generate_summary(violations: list[dict[str, Any]]) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return _deterministic_summary(violations)

    violations_text = "\n".join(
        [
            f"- [{violation.get('severity', 'UNKNOWN')}] {violation.get('rule_id')}: "
            f"{violation.get('message')} (line {violation.get('line_number', 'N/A')})"
            for violation in violations
        ]
    )

    if not violations_text:
        violations_text = "No violations found."

    client = OpenAI(api_key=api_key)
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.3,
            max_tokens=800,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior security auditor. Given a list of code violations\n"
                        "found by static analysis tools, generate a clear professional audit summary with:\n"
                        "1. Executive Summary (2-3 sentences)\n"
                        "2. Critical Issues (must fix immediately)\n"
                        "3. Medium Issues (should fix soon)\n"
                        "4. Low Issues (nice to fix)\n"
                        "5. Recommended Actions (numbered list)\n"
                        "Format in clean markdown."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Here are the violations found:\n\n{violations_text}\n\nGenerate the audit summary.",
                },
            ],
        )
        message = response.choices[0].message.content
        if message:
            return message
    except Exception as exc:
        return _deterministic_summary(violations) + f"\n\n> AI summary unavailable: {exc}"

    return _deterministic_summary(violations)


def generate_audit_summary(violations: list[dict[str, Any]]) -> str:
    return generate_summary(violations)
