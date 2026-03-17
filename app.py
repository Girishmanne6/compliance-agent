from __future__ import annotations

import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from agent.github_scanner import (
    GitHubAccessDeniedError,
    GitHubRepoNotFoundError,
    GitHubScannerError,
    fetch_repo_files,
)
from agent.opa_checker import check_policies
from agent.reporter import (
    build_report,
    get_html_report_path,
    list_recent_reports,
    load_report,
    save_report,
)
from agent.scanner import scan_code
from agent.summarizer import generate_summary

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
SAMPLE_DIR = BASE_DIR / "sample_code"

load_dotenv(BASE_DIR / ".env")

app = FastAPI(title="Compliance Agent", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")
app.mount("/sample_code", StaticFiles(directory=SAMPLE_DIR), name="sample_code")


class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1)
    language: str = Field(..., min_length=1)


class RepoScanRequest(BaseModel):
    repo_url: str = Field(..., min_length=1)
    language: str = Field(default="all", min_length=1)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
def scan(payload: ScanRequest) -> dict:
    started_at = time.perf_counter()
    try:
        semgrep_violations = scan_code(payload.code, payload.language)
        opa_violations = check_policies(payload.code, payload.language)
        violations = [*semgrep_violations, *opa_violations]
        summary = generate_summary(violations)
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        report = build_report(
            violations,
            summary,
            duration_ms,
            scan_type="paste",
            source="pasted-code",
            scanned_files=1,
        )
        save_report(report)
        return report
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@app.post("/scan-repo")
def scan_repo(payload: RepoScanRequest) -> dict:
    started_at = time.perf_counter()
    try:
        repo_files = fetch_repo_files(payload.repo_url, payload.language, max_files=10)
    except GitHubAccessDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except GitHubRepoNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except GitHubScannerError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub scan setup failed: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"GitHub scan failed: {exc}") from exc

    if not repo_files:
        raise HTTPException(
            status_code=400,
            detail="No matching files found for selected language filter.",
        )

    all_violations: list[dict] = []
    file_breakdown: list[dict] = []
    for file_entry in repo_files:
        file_path = file_entry["path"]
        language = file_entry["language"]
        content = file_entry["content"]
        semgrep_violations = scan_code(content, language)
        opa_violations = check_policies(content, language)
        combined = [*semgrep_violations, *opa_violations]
        for violation in combined:
            violation["file_path"] = file_path
        all_violations.extend(combined)

        file_breakdown.append(
            {
                "file_path": file_path,
                "language": language,
                "total_violations": len(combined),
                "critical": sum(1 for item in combined if item.get("severity") == "critical"),
                "medium": sum(1 for item in combined if item.get("severity") == "medium"),
                "low": sum(1 for item in combined if item.get("severity") == "low"),
            }
        )

    summary = generate_summary(all_violations)
    summary = f"Scanned {len(repo_files)} files, found {len(all_violations)} violations.\n\n{summary}"
    duration_ms = int((time.perf_counter() - started_at) * 1000)
    report = build_report(
        all_violations,
        summary,
        duration_ms,
        scan_type="github",
        source=payload.repo_url,
        scanned_files=len(repo_files),
        file_breakdown=file_breakdown,
    )
    save_report(report)
    return report


@app.get("/report/{report_id}")
def get_report(report_id: str) -> dict:
    try:
        return load_report(report_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Report not found") from exc


@app.get("/report/{report_id}/html")
def get_report_html(report_id: str) -> FileResponse:
    try:
        html_path = get_html_report_path(report_id)
        return FileResponse(html_path, media_type="text/html", filename=html_path.name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="HTML report not found") from exc


@app.get("/history")
def get_history() -> list[dict]:
    return list_recent_reports(limit=10)
