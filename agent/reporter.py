from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import markdown

from agent.database import (
    init_db,
    list_report_summaries,
    load_report_row,
    save_report_row,
)

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _severity_rank(severity: str) -> int:
    return {"critical": 0, "medium": 1, "low": 2}.get(severity, 3)


def _count_by_severity(violations: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "medium": 0, "low": 0}
    for violation in violations:
        severity = violation.get("severity", "low")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def build_report(
    violations: list[dict[str, Any]],
    ai_summary: str,
    scan_duration_ms: int,
    scan_type: str = "paste",
    source: str = "pasted-code",
    scanned_files: int = 1,
    file_breakdown: list[dict[str, Any]] | None = None,
    step_timings: dict[str, int] | None = None,
) -> dict[str, Any]:
    ordered_violations = sorted(
        violations,
        key=lambda violation: (
            _severity_rank(violation.get("severity", "low")),
            violation.get("file_path", ""),
            violation.get("line_number", 0),
        ),
    )
    counts = _count_by_severity(ordered_violations)
    return {
        "report_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        "source": source,
        "scanned_files": scanned_files,
        "total_violations": len(ordered_violations),
        "critical": counts.get("critical", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "violations": ordered_violations,
        "file_breakdown": file_breakdown or [],
        "ai_summary": ai_summary,
        "scan_duration_ms": scan_duration_ms,
        "step_timings_ms": step_timings or {},
    }


def _render_html(report: dict[str, Any]) -> str:
    summary_html = markdown.markdown(report["ai_summary"], extensions=["fenced_code", "tables"])
    rows = []
    for violation in report["violations"]:
        severity = violation.get("severity", "low")
        file_path = violation.get("file_path", "-")
        rows.append(
            """
            <tr>
                <td>{rule_id}</td>
                <td><span class=\"badge {severity}\">{severity}</span></td>
                <td>{message}</td>
                <td>{file_path}</td>
                <td>{line_number}</td>
                <td><pre>{code_snippet}</pre></td>
            </tr>
            """.format(
                rule_id=violation.get("rule_id", "unknown"),
                severity=severity,
                message=violation.get("message", ""),
                file_path=file_path,
                line_number=violation.get("line_number", 1),
                code_snippet=violation.get("code_snippet", ""),
            )
        )

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />
  <title>Compliance Report {report['report_id']}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --green: #238636;
      --critical: #f85149;
      --medium: #d29922;
      --low: #388bfd;
    }}
    body {{
      margin: 0;
      background: radial-gradient(circle at top, rgba(35, 134, 54, 0.15), transparent 30%), var(--bg);
      color: var(--text);
      font-family: Inter, sans-serif;
      padding: 32px;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.25);
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
    }}
    .stat {{
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      border-bottom: 1px solid var(--border);
      padding: 12px;
      text-align: left;
      vertical-align: top;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
    }}
    .critical {{ background: rgba(248, 81, 73, 0.18); color: var(--critical); }}
    .medium {{ background: rgba(210, 153, 34, 0.18); color: var(--medium); }}
    .low {{ background: rgba(56, 139, 253, 0.18); color: var(--low); }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      font-family: \"JetBrains Mono\", monospace;
      color: #c9d1d9;
    }}
    .summary :is(h1, h2, h3) {{ margin-top: 0; }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 860px) {{
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      body {{ padding: 16px; }}
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <div class=\"card\">
      <h1>Compliance Audit Report</h1>
      <p class=\"muted\">Report ID: {report['report_id']}<br/>Generated: {report['timestamp']}<br/>Scan type: {report.get('scan_type', 'paste')}<br/>Source: {report.get('source', 'pasted-code')}<br/>Scanned files: {report.get('scanned_files', 1)}<br/>Scan duration: {report['scan_duration_ms']} ms</p>
      <div class=\"stats\">
        <div class=\"stat\"><strong>Total</strong><div>{report['total_violations']}</div></div>
        <div class=\"stat\"><strong style=\"color: var(--critical)\">Critical</strong><div>{report['critical']}</div></div>
        <div class=\"stat\"><strong style=\"color: var(--medium)\">Medium</strong><div>{report['medium']}</div></div>
        <div class=\"stat\"><strong style=\"color: var(--low)\">Low</strong><div>{report['low']}</div></div>
      </div>
    </div>
    <div class=\"card\">
      <h2>Violations</h2>
      <table>
        <thead>
          <tr>
            <th>Rule ID</th>
            <th>Severity</th>
            <th>Message</th>
            <th>File</th>
            <th>Line</th>
            <th>Code Snippet</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
    <div class=\"card summary\">
      <h2>AI Audit Summary</h2>
      {summary_html}
    </div>
  </div>
</body>
</html>
"""


def save_report(report: dict[str, Any]) -> dict[str, str]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_id = report["report_id"]
    html_path = REPORTS_DIR / f"{report_id}.html"

    init_db()
    save_report_row(report)
    html_path.write_text(_render_html(report), encoding="utf-8")
    return {"html_path": str(html_path)}


def load_report(report_id: str) -> dict[str, Any]:
    return load_report_row(report_id)


def get_html_report_path(report_id: str) -> Path:
    html_path = REPORTS_DIR / f"{report_id}.html"
    if not html_path.exists():
        raise FileNotFoundError(report_id)
    return html_path


def list_recent_reports(limit: int = 10) -> list[dict[str, Any]]:
    return list_report_summaries(limit)
