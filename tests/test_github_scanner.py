from __future__ import annotations

import pytest

from agent.github_scanner import GitHubScannerError, _allowed_extensions


def test_allowed_extensions_includes_javascript() -> None:
    assert ".js" in _allowed_extensions("javascript")
    assert ".js" in _allowed_extensions("all")


def test_allowed_extensions_python_only() -> None:
    exts = _allowed_extensions("python")
    assert ".py" in exts
    assert ".js" not in exts


def test_invalid_language_raises() -> None:
    with pytest.raises(GitHubScannerError):
        _allowed_extensions("ruby")
