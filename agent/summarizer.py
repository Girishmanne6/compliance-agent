from __future__ import annotations

import os
from typing import Any

from openai import OpenAI

def generate_summary(violations: list[dict[str, Any]]) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return "⚠️ OPENAI_API_KEY not set. Configure it to enable AI summaries."

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
        return f"⚠️ AI summary generation failed: {exc}"

    return "⚠️ AI summary generation failed: empty response"


def generate_audit_summary(violations: list[dict[str, Any]]) -> str:
    return generate_summary(violations)
