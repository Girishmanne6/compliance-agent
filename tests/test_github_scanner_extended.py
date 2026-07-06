from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
import requests

from agent.github_scanner import (
    GitHubAccessDeniedError,
    GitHubRepoNotFoundError,
    GitHubScannerError,
    _decode_content,
    _parse_repo_url,
    _priority_key,
    _select_candidates,
    fetch_repo_files,
)


def test_parse_repo_url_valid() -> None:
    owner, repo = _parse_repo_url("https://github.com/user/my-repo")
    assert owner == "user"
    assert repo == "my-repo"


def test_parse_repo_url_strips_git_suffix() -> None:
    owner, repo = _parse_repo_url("https://github.com/user/my-repo.git")
    assert repo == "my-repo"


def test_parse_repo_url_invalid_raises() -> None:
    with pytest.raises(GitHubRepoNotFoundError):
        _parse_repo_url("https://gitlab.com/user/repo")


def test_decode_content_roundtrip() -> None:
    raw = base64.b64encode(b"hello world").decode()
    assert _decode_content(raw) == "hello world"


def test_decode_content_empty() -> None:
    assert _decode_content("") == ""


def test_priority_key_prefers_sample_code() -> None:
    assert _priority_key("sample_code/vuln.py") < _priority_key("deep/nested/file.py")


def test_select_candidates_truncates_and_flags() -> None:
    candidates = [{"path": f"file{i}.py", "language": "python"} for i in range(5)]
    selected, truncated = _select_candidates(candidates, max_files=2)
    assert len(selected) == 2
    assert truncated is True


def test_select_candidates_no_truncation() -> None:
    candidates = [{"path": "a.py", "language": "python"}]
    selected, truncated = _select_candidates(candidates, max_files=10)
    assert len(selected) == 1
    assert truncated is False


def test_github_get_rate_limit_raises() -> None:
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "API rate limit exceeded"
    with patch("agent.github_scanner.requests.get", return_value=mock_response):
        with pytest.raises(GitHubScannerError, match="rate limit"):
            from agent.github_scanner import _github_get

            _github_get("https://api.github.com/test")


def test_github_get_network_error() -> None:
    with patch(
        "agent.github_scanner.requests.get",
        side_effect=requests.RequestException("timeout"),
    ):
        with pytest.raises(GitHubScannerError, match="GitHub request failed"):
            from agent.github_scanner import _github_get

            _github_get("https://api.github.com/test")


def test_fetch_repo_files_private_repo_denied() -> None:
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "Not Found"
    with patch("agent.github_scanner._github_get", return_value=mock_response):
        with pytest.raises(GitHubAccessDeniedError):
            fetch_repo_files("https://github.com/private/repo", "python")


def test_fetch_repo_files_returns_truncation_metadata() -> None:
    tree = [{"type": "blob", "path": f"src/file{i}.py"} for i in range(5)]

    def fake_get(url: str) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        if "git/trees" in url:
            resp.json.return_value = {"tree": tree}
        elif "contents/" in url:
            encoded = base64.b64encode(b"x = 1").decode()
            resp.json.return_value = {"encoding": "base64", "content": encoded}
        else:
            resp.json.return_value = {"default_branch": "main"}
        return resp

    with patch("agent.github_scanner._github_get", side_effect=fake_get):
        result = fetch_repo_files("https://github.com/user/repo", "python", max_files=2)

    assert result["truncated"] is True
    assert result["total_candidates"] == 5
    assert result["scanned_files"] == 2
    assert len(result["files"]) == 2


def test_fetch_repo_files_invalid_url() -> None:
    with pytest.raises(GitHubRepoNotFoundError):
        fetch_repo_files("not-a-url", "all")
