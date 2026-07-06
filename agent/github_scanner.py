from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any

import requests

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
DEFAULT_MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "25"))
PRIORITY_PREFIXES = ("sample_code/", "src/", "app/", "lib/", "api/", "agent/")
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".tf": "terraform",
    ".js": "javascript",
}
LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "terraform": {".tf"},
    "javascript": {".js"},
    "all": {".py", ".tf", ".js"},
}


class GitHubScannerError(Exception):
    """Raised when repo scanning setup or network calls fail."""


class GitHubAccessDeniedError(GitHubScannerError):
    """Raised for private or inaccessible repositories."""


class GitHubRepoNotFoundError(GitHubScannerError):
    """Raised when repository URL is invalid or missing."""


def _build_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "compliance-agent",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def _parse_repo_url(repo_url: str) -> tuple[str, str]:
    pattern = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+)")
    match = pattern.match(repo_url.strip())
    if not match:
        raise GitHubRepoNotFoundError("Invalid GitHub repo URL.")
    owner = match.group(1)
    repo = match.group(2).replace(".git", "")
    if not owner or not repo:
        raise GitHubRepoNotFoundError("Invalid GitHub repo URL.")
    return owner, repo


def _github_get(url: str) -> requests.Response:
    try:
        response = requests.get(url, headers=_build_headers(), timeout=15)
    except requests.RequestException as exc:
        raise GitHubScannerError(f"GitHub request failed: {exc}") from exc
    if response.status_code == 403 and "rate limit" in response.text.lower():
        raise GitHubScannerError("GitHub API rate limit exceeded. Set GITHUB_TOKEN or retry later.")
    return response


def _get_default_branch(owner: str, repo: str) -> str:
    url = f"{GITHUB_API}/repos/{owner}/{repo}"
    response = _github_get(url)
    if response.status_code in {401, 403, 404}:
        raise GitHubAccessDeniedError("private repo — access denied")
    if response.status_code >= 400:
        raise GitHubScannerError(f"GitHub API returned {response.status_code} while reading repo metadata.")
    payload = response.json()
    return payload.get("default_branch") or "main"


def _load_tree(owner: str, repo: str, branch: str) -> list[dict[str, Any]]:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    response = _github_get(url)
    if response.status_code in {401, 403}:
        raise GitHubAccessDeniedError("private repo — access denied")
    if response.status_code == 404:
        return []
    if response.status_code >= 400:
        raise GitHubScannerError(f"GitHub API returned {response.status_code} while listing files.")
    payload = response.json()
    return payload.get("tree", [])


def _decode_content(content: str) -> str:
    if not content:
        return ""
    compact = content.replace("\n", "")
    return base64.b64decode(compact).decode("utf-8", errors="ignore")


def _fetch_file_content(owner: str, repo: str, path: str) -> str:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    response = _github_get(url)
    if response.status_code in {401, 403, 404}:
        raise GitHubAccessDeniedError("private repo — access denied")
    if response.status_code >= 400:
        raise GitHubScannerError(f"GitHub API returned {response.status_code} while fetching {path}.")

    payload = response.json()
    if payload.get("encoding") != "base64":
        return ""
    return _decode_content(payload.get("content", ""))


def _allowed_extensions(language_filter: str) -> set[str]:
    normalized = language_filter.strip().lower()
    if normalized not in LANGUAGE_EXTENSIONS:
        raise GitHubScannerError("language must be one of: python, terraform, javascript, all")
    return LANGUAGE_EXTENSIONS[normalized]


def _priority_key(path: str) -> tuple[int, int, str]:
    """Prefer shallow paths and known source directories."""
    depth = path.count("/")
    in_priority = any(path.startswith(prefix) for prefix in PRIORITY_PREFIXES)
    return (0 if in_priority else 1, depth, path)


def _select_candidates(candidates: list[dict[str, str]], max_files: int) -> tuple[list[dict[str, str]], bool]:
    candidates.sort(key=lambda item: _priority_key(item["path"]))
    truncated = len(candidates) > max_files
    if truncated:
        logger.warning(
            "Repo scan truncated: %d candidate files, scanning first %d by priority.",
            len(candidates),
            max_files,
        )
    return candidates[:max_files], truncated


def fetch_repo_files(
    repo_url: str,
    language_filter: str,
    max_files: int | None = None,
) -> dict[str, Any]:
    limit = max_files if max_files is not None else DEFAULT_MAX_REPO_FILES
    owner, repo = _parse_repo_url(repo_url)
    allowed_extensions = _allowed_extensions(language_filter)

    tree = _load_tree(owner, repo, "main")
    if not tree:
        branch = _get_default_branch(owner, repo)
        tree = _load_tree(owner, repo, branch)

    candidates: list[dict[str, str]] = []
    for node in tree:
        if node.get("type") != "blob":
            continue
        path = str(node.get("path", ""))
        extension = os.path.splitext(path)[1].lower()
        if extension not in allowed_extensions:
            continue
        language = EXTENSION_TO_LANGUAGE.get(extension)
        if not language:
            continue
        candidates.append({"path": path, "language": language})

    selected, truncated = _select_candidates(candidates, limit)
    files: list[dict[str, str]] = []
    for item in selected:
        content = _fetch_file_content(owner, repo, item["path"])
        files.append(
            {
                "path": item["path"],
                "language": item["language"],
                "content": content,
            }
        )
    return {
        "files": files,
        "total_candidates": len(candidates),
        "scanned_files": len(files),
        "truncated": truncated,
        "max_files": limit,
    }
