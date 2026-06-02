"""Reliability tests for CippClient.get — CIPP cold-start endpoints
(ListInactiveAccounts, ListMFAUsers, ListBasicAuth) intermittently exceed the
read timeout; a single timeout must not silently drop a whole data domain."""
import time

import httpx
import pytest

from cipp_client import CippClient, CippError


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._p = payload
        self.text = ""

    def json(self):
        return self._p


class _FlakyHttp:
    """Raises ReadTimeout `fail_times` times, then returns 200."""
    def __init__(self, fail_times, payload=None):
        self.fail_times = fail_times
        self.payload = payload if payload is not None else {"ok": True}
        self.calls = 0

    def get(self, url, params=None, headers=None):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise httpx.ReadTimeout("timed out")
        return _Resp(200, self.payload)


def _client():
    c = CippClient(api_url="http://x", token_url="http://t", client_id="i", client_secret="s")
    c._token = "tok"
    c._token_expires = time.time() + 9999   # skip the token POST
    c._retry_backoff = 0                      # no sleep in tests
    return c


def test_get_retries_then_succeeds_on_transient_timeout():
    c = _client()
    c._http = _FlakyHttp(fail_times=2, payload={"data": 1})
    assert c.get("/api/ListMFAUsers") == {"data": 1}
    assert c._http.calls == 3   # 2 failures + 1 success


def test_get_raises_cipperror_after_exhausting_retries():
    c = _client()
    c._http = _FlakyHttp(fail_times=99)
    with pytest.raises(CippError):
        c.get("/api/ListInactiveAccounts")
    assert c._http.calls == c._max_retries + 1
