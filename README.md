# Compliance Agent

Compliance Agent is an AI-driven shift-left compliance tool that scans source code and Infrastructure-as-Code before deployment, so security and policy problems are caught earlier in the delivery lifecycle.

## What Shift-Left Means

Shift-left means moving security and compliance checks closer to where code is written and reviewed instead of waiting for a late-stage audit or production incident. In practice, that means developers, platform engineers, and security teams can identify secrets, insecure code paths, and risky Terraform settings before they become release blockers.

## Architecture

The application has four major layers:

1. FastAPI API in `app.py` receives scan requests, runs the pipeline, persists reports, and serves the frontend.
2. Semgrep integration in `agent/scanner.py` performs static analysis against submitted code using language-aware and security-focused rulesets.
3. OPA policy evaluation in `agent/opa_checker.py` evaluates custom Rego policies for secrets, dangerous functions, open CIDR ranges, missing S3 encryption, and wildcard IAM permissions.
4. AI summarization and reporting in `agent/summarizer.py` and `agent/reporter.py` convert raw violations into markdown audit summaries and downloadable JSON or HTML reports.

Persistent storage uses **SQLite** (`compliance_agent.db`) for reports and metrics. HTML reports are still written to the `reports/` directory.

## Project Structure

```text
compliance-agent/
├── .github/workflows/
│   ├── scan.yml              # PR compliance gate (blocks on critical violations)
│   └── test.yml              # pytest + coverage on push/PR
├── agent/
│   ├── auth.py               # X-API-Key protection for scan endpoints
│   ├── database.py           # SQLite persistence layer
│   ├── rate_limit.py         # Token-bucket rate limiting for /scan-repo
│   └── metrics.py            # Scan timing + aggregate stats
├── frontend/
├── policies/
├── reports/                  # HTML reports (gitignored)
├── sample_code/
├── scripts/
│   └── ci_scan.py            # CI scanner for changed files
├── tests/                    # 80 tests, 87% coverage
├── app.py
├── render.yaml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Features

- POST `/scan` accepts code plus language and runs Semgrep, OPA checks, and AI summarization.
- POST `/scan-repo` accepts a GitHub repo URL plus language filter (`python`, `terraform`, `javascript`, `all`), scans up to `MAX_REPO_FILES` matching files (default 25, priority-ordered), and returns one combined report with per-file violations.
- GET `/report/{report_id}` returns a saved JSON report.
- GET `/report/{report_id}/html` returns a downloadable HTML report.
- GET `/history` returns the latest 10 saved reports with source and severity counts for persistent history.
- GET `/stats` returns aggregate scan metrics (total scans, violations by severity, average scan time).
- GET `/health` returns a simple health check.
- Dark DevSecOps dashboard with mode tabs (Paste Code / Scan GitHub Repo), filename-aware violation table, markdown summary rendering, downloadable reports, and persisted history view.
- GitHub Actions CI gate that scans changed `.py`, `.tf`, and `.js` files on every PR and blocks merge on critical violations.
- API key auth (`X-API-Key` header) on `/scan` and `/scan-repo` when `API_KEY` env var is set.
- Rate limiting on `/scan-repo` (default `10/minute` per IP, configurable via `SCAN_REPO_RATE_LIMIT`).

## Local Run

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000` after the server starts.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

**Current coverage: 87%** (80 tests). Report generated in terminal and as `htmlcov/index.html`.

| Module | Coverage |
|--------|----------|
| agent/database.py | 100% |
| agent/auth.py | 100% |
| agent/metrics.py | 100% |
| agent/reporter.py | 100% |
| agent/opa_checker.py | 97% |
| agent/rate_limit.py | 95% |
| app.py | 95% |
| agent/github_scanner.py | 82% |

## CI/CD

Two GitHub Actions workflows run automatically:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `test.yml` | push / PR to `main` | Runs pytest with coverage |
| `scan.yml` | PR to `main` (on code changes) | Scans changed files, posts PR comment, **blocks merge on critical violations** |

The compliance scan can also be run locally:

```bash
python scripts/ci_scan.py --base origin/main
```

## Environment Variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `OPENAI_API_KEY` | Optional | — | GPT-4o-mini AI summaries |
| `GITHUB_TOKEN` | Optional | — | Higher GitHub API rate limits |
| `API_KEY` | Optional | — | Protects `/scan` and `/scan-repo` |
| `SCAN_REPO_RATE_LIMIT` | Optional | `10/minute` | Rate limit for repo scanning |
| `MAX_REPO_FILES` | Optional | `25` | Max files scanned per repo request |

## Notes

- Set `OPENAI_API_KEY` to enable GPT-4o-mini summaries. Without it, the app produces a **deterministic rule-based summary** from the real scan findings.
- Set optional `GITHUB_TOKEN` to increase GitHub API rate limits when using `/scan-repo`.
- If the `opa` binary is unavailable, the OPA checker falls back to equivalent Python-side policy checks so scans still complete gracefully.
- Semgrep is attempted in-process first, then via the installed Semgrep binary in the active environment as a fallback when needed.
- Scan metrics and reports are persisted in SQLite (`compliance_agent.db`, gitignored).

## Sample Inputs

- `sample_code/vulnerable.py` contains hardcoded secrets, SQL injection, `eval`, and unsafe `pickle.loads`.
- `sample_code/vulnerable.js` contains hardcoded secrets, SQL injection patterns, and `eval`.
- `sample_code/infra.tf` contains open ingress, missing S3 encryption, and wildcard IAM permissions.
- `sample_code/secure.py` shows a cleaner Python example.

## Deployment

`render.yaml` is included for Render deployment with `OPENAI_API_KEY` configured as an external secret.
