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

## Project Structure

```text
compliance-agent/
├── agent/
├── frontend/
├── policies/
├── reports/
├── sample_code/
├── app.py
├── render.yaml
├── requirements.txt
└── README.md
```

## Features

- POST `/scan` accepts code plus language and runs Semgrep, OPA checks, and AI summarization.
- POST `/scan-repo` accepts a GitHub repo URL plus language filter (`python`, `terraform`, `all`), scans up to 10 matching files, and returns one combined report with per-file violations.
- GET `/report/{report_id}` returns a saved JSON report.
- GET `/report/{report_id}/html` returns a downloadable HTML report.
- GET `/history` returns the latest 10 saved reports with source and severity counts for persistent history.
- GET `/health` returns a simple health check.
- Dark DevSecOps dashboard with mode tabs (Paste Code / Scan GitHub Repo), filename-aware violation table, markdown summary rendering, downloadable reports, and persisted history view.

## Local Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000` after the server starts.

## Notes

- Set `OPENAI_API_KEY` to enable GPT-4o-mini summaries. Without it, the app produces a deterministic summary from the real scan findings.
- Set optional `GITHUB_TOKEN` to increase GitHub API rate limits when using `/scan-repo`.
- If the `opa` binary is unavailable, the OPA checker falls back to equivalent Python-side policy checks so scans still complete gracefully.
- Semgrep is attempted in-process first, then via the installed Semgrep binary in the active environment as a fallback when needed.

## Sample Inputs

- `sample_code/vulnerable.py` contains hardcoded secrets, SQL injection, `eval`, and unsafe `pickle.loads`.
- `sample_code/infra.tf` contains open ingress, missing S3 encryption, and wildcard IAM permissions.
- `sample_code/secure.py` shows a cleaner Python example.

## Deployment

`render.yaml` is included for Render deployment with `OPENAI_API_KEY` configured as an external secret.
