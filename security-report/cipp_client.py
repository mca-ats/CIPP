"""
CIPP API client for security posture reporting.
Reuses the existing .env credentials from cipp-local/.env
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import httpx

DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
DEFAULT_TIMEOUT = 60.0


class CippError(RuntimeError):
    pass


def parse_env_file(path: Path = DEFAULT_ENV_PATH) -> dict[str, str]:
    if not path.exists():
        raise CippError(f"Missing env file: {path}")
    env: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if value and value[0] in ("'", '"') and value[-1] == value[0]:
            value = value[1:-1]
        env[key] = value
    return env


@dataclass
class CippClient:
    api_url: str
    token_url: str
    client_id: str
    client_secret: str
    _token: str | None = field(default=None, repr=False)
    _token_expires: float = field(default=0.0, repr=False)
    _http: httpx.Client = field(default=None, repr=False)

    def __post_init__(self):
        self.api_url = self.api_url.rstrip("/")
        if self._http is None:
            self._http = httpx.Client(timeout=DEFAULT_TIMEOUT)

    @classmethod
    def from_env(cls, env_path: Path = DEFAULT_ENV_PATH) -> CippClient:
        env = parse_env_file(env_path)

        def get(key: str) -> str:
            val = env.get(key) or os.environ.get(key)
            if not val:
                raise CippError(f"Missing required env var: {key}")
            return val

        token_url = env.get("CIPP_TOKEN_URL")
        tenant_id = env.get("CIPP_TENANT_ID") or os.environ.get("CIPP_TENANT_ID")
        if not token_url:
            if not tenant_id:
                raise CippError("Missing CIPP_TOKEN_URL or CIPP_TENANT_ID")
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        return cls(
            api_url=get("CIPP_API_URL"),
            token_url=token_url,
            client_id=get("CIPP_CLIENT_ID"),
            client_secret=get("CIPP_API_Secret"),
        )

    def _ensure_token(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token

        resp = self._http.post(
            self.token_url,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": f"api://{self.client_id}/.default",
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        payload = resp.json()
        if "access_token" not in payload:
            raise CippError("Token response missing access_token")

        self._token = payload["access_token"]
        self._token_expires = time.time() + payload.get("expires_in", 3600)
        return self._token

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        token = self._ensure_token()
        url = f"{self.api_url}/{path.lstrip('/')}"
        resp = self._http.get(
            url,
            params=params,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if resp.status_code >= 400:
            raise CippError(f"CIPP API error {resp.status_code} on GET {path}: {resp.text[:500]}")
        return resp.json()

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        token = self._ensure_token()
        url = f"{self.api_url}/{path.lstrip('/')}"
        resp = self._http.post(
            url,
            json=body,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        if resp.status_code >= 400:
            raise CippError(f"CIPP API error {resp.status_code} on POST {path}: {resp.text[:500]}")
        return resp.json()

    def list_tenants(self) -> list[dict[str, Any]]:
        result = self.get("/api/ListTenants")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("value", "Value", "tenants", "Results"):
                if isinstance(result.get(key), list):
                    return result[key]
        return [result] if result else []

    def close(self):
        if self._http:
            self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
