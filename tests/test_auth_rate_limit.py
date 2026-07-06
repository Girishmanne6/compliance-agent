from __future__ import annotations

import pytest

from agent.auth import require_api_key
from agent.rate_limit import TokenBucketLimiter, _parse_limit


def test_require_api_key_passes_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_KEY", raising=False)
    require_api_key(None)


def test_require_api_key_passes_with_valid_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "secret")
    require_api_key("secret")


def test_require_api_key_rejects_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import HTTPException

    monkeypatch.setenv("API_KEY", "secret")
    with pytest.raises(HTTPException) as exc:
        require_api_key("wrong")
    assert exc.value.status_code == 401


def test_parse_limit_minute() -> None:
    assert _parse_limit("10/minute") == (10, 60)


def test_parse_limit_numeric_seconds() -> None:
    assert _parse_limit("5/30") == (5, 30)


def test_token_bucket_blocks_after_max() -> None:
    from fastapi import HTTPException

    limiter = TokenBucketLimiter(max_requests=2, window_seconds=60)

    class FakeRequest:
        headers: dict = {}
        client = type("C", (), {"host": "127.0.0.1"})()

    req = FakeRequest()
    limiter.check(req)
    limiter.check(req)
    with pytest.raises(HTTPException) as exc:
        limiter.check(req)
    assert exc.value.status_code == 429
