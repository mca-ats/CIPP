#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


class CippError(RuntimeError):
    pass


def _parse_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise CippError(f"Missing env file: {path}")

    env: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if value and value[0] in ("'", '"') and value[-1] == value[0]:
            value = value[1:-1]
        env[key] = value
    return env


def _env_get(env: Mapping[str, str], key: str) -> str:
    value = env.get(key) or os.environ.get(key)
    if not value:
        raise CippError(f"Missing required env var: {key}")
    return value


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: bytes
    content_type: str | None


def _http_request(
    *,
    url: str,
    method: str,
    headers: Mapping[str, str] | None = None,
    form: Mapping[str, str] | None = None,
    timeout_s: float = 30.0,
) -> HttpResult:
    request_headers = {"User-Agent": "cipp-scripts/list_tenants.py"}
    if headers:
        request_headers.update(dict(headers))

    data: bytes | None = None
    if form is not None:
        data = urllib.parse.urlencode(dict(form)).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    req = urllib.request.Request(url, data=data, headers=request_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return HttpResult(
                status=int(resp.status),
                body=resp.read(),
                content_type=resp.headers.get("Content-Type"),
            )
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return HttpResult(status=int(e.code), body=body, content_type=e.headers.get("Content-Type"))
    except urllib.error.URLError as e:
        raise CippError(f"Network error calling {url}: {e}") from e


def _http_json(
    *,
    url: str,
    method: str,
    headers: Mapping[str, str] | None = None,
    form: Mapping[str, str] | None = None,
    timeout_s: float = 30.0,
) -> Any:
    res = _http_request(url=url, method=method, headers=headers, form=form, timeout_s=timeout_s)
    try:
        payload = json.loads(res.body.decode("utf-8")) if res.body else None
    except Exception:
        payload = None

    if res.status < 200 or res.status >= 300:
        error_hint = ""
        if isinstance(payload, dict):
            if "error_description" in payload:
                error_hint = f" ({payload['error_description']})"
            elif "error" in payload and isinstance(payload["error"], str):
                error_hint = f" ({payload['error']})"
        raise CippError(f"HTTP {res.status} calling {url}{error_hint}")
    return payload


def _get_access_token(*, env: Mapping[str, str]) -> str:
    token_url = env.get("CIPP_TOKEN_URL")
    tenant_id = env.get("CIPP_TENANT_ID") or os.environ.get("CIPP_TENANT_ID")
    if not token_url:
        if not tenant_id:
            raise CippError("Missing CIPP_TOKEN_URL or CIPP_TENANT_ID")
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    client_id = _env_get(env, "CIPP_CLIENT_ID")
    client_secret = _env_get(env, "CIPP_API_Secret")
    scope = f"api://{client_id}/.default"

    token_payload = _http_json(
        url=token_url,
        method="POST",
        form={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        },
        timeout_s=30.0,
    )
    if not isinstance(token_payload, dict) or "access_token" not in token_payload:
        raise CippError("Token response missing access_token")
    return str(token_payload["access_token"])


def _discover_tenant_get_paths(*, swagger: Mapping[str, Any]) -> list[str]:
    paths = swagger.get("paths")
    if not isinstance(paths, dict):
        return []

    candidates: list[str] = []
    for path, ops in paths.items():
        if not isinstance(path, str) or "tenant" not in path.lower():
            continue
        if "{" in path or "}" in path:
            continue
        if not isinstance(ops, dict):
            continue
        get_op = ops.get("get")
        if not isinstance(get_op, dict):
            continue

        required_params: list[str] = []
        params = get_op.get("parameters")
        if isinstance(params, list):
            for p in params:
                if not isinstance(p, dict):
                    continue
                if p.get("required") is True and isinstance(p.get("name"), str):
                    required_params.append(p["name"])
        if required_params:
            continue

        candidates.append(path)

    return sorted(set(candidates))


def _iter_tenants_from_payload(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, list) and all(isinstance(x, Mapping) for x in payload):
        return list(payload)
    if isinstance(payload, Mapping):
        for key in ("value", "Value", "tenants", "Tenants", "results", "Results"):
            inner = payload.get(key)
            if isinstance(inner, list) and all(isinstance(x, Mapping) for x in inner):
                return list(inner)
    return []


def _ci_get(d: Mapping[str, Any], *keys: str) -> Any:
    lowered = {str(k).lower(): k for k in d.keys()}
    for k in keys:
        orig = lowered.get(k.lower())
        if orig is not None:
            return d.get(orig)
    return None


def _format_tenant(t: Mapping[str, Any]) -> str:
    display = _ci_get(t, "displayName", "tenantName", "name", "customerName")
    domain = _ci_get(t, "defaultDomainName", "domain", "defaultDomain", "tenantDomain")
    tenant_id = _ci_get(t, "tenantId", "tenantID", "tenant", "customerTenantId")

    parts: list[str] = []
    if isinstance(display, str) and display.strip():
        parts.append(display.strip())
    if isinstance(domain, str) and domain.strip():
        parts.append(domain.strip())
    if isinstance(tenant_id, str) and tenant_id.strip():
        parts.append(f"({tenant_id.strip()})")

    if parts:
        return " — ".join(parts[:2]) + (f" {parts[2]}" if len(parts) >= 3 else "")

    # Last resort: stable-ish compact JSON of known-ish keys only
    subset_keys = [
        "displayName",
        "tenantName",
        "name",
        "defaultDomainName",
        "domain",
        "tenantId",
        "customerId",
    ]
    subset = {k: _ci_get(t, k) for k in subset_keys if _ci_get(t, k) is not None}
    if subset:
        return json.dumps(subset, ensure_ascii=False)
    return json.dumps(dict(t), ensure_ascii=False)


def _fetch_tenants(*, env: Mapping[str, str], verbose: bool, endpoint_override: str | None) -> list[Mapping[str, Any]]:
    api_url = _env_get(env, "CIPP_API_URL").rstrip("/")
    token = _get_access_token(env=env)

    headers = {"Authorization": f"Bearer {token}"}

    endpoints: list[str] = []
    if endpoint_override:
        endpoints.append(endpoint_override)
    endpoints.extend(
        [
            "/api/ListTenants",
            "/api/ListTenantsAll",
            "/api/ListAllTenants",
            "/api/GetTenants",
        ]
    )

    last_error: Exception | None = None
    for ep in endpoints:
        url = f"{api_url}{ep}" if ep.startswith("/") else f"{api_url}/{ep}"
        try:
            payload = _http_json(url=url, method="GET", headers=headers, timeout_s=30.0)
            tenants = _iter_tenants_from_payload(payload)
            if tenants:
                if verbose:
                    print(f"Using endpoint: {ep}", file=sys.stderr)
                return tenants
        except Exception as e:
            last_error = e
            continue

    swagger_candidates = [
        "/swagger/v1/swagger.json",
        "/swagger.json",
        "/api/swagger/v1/swagger.json",
        "/api/swagger.json",
    ]
    for swagger_path in swagger_candidates:
        swagger_url = f"{api_url}{swagger_path}"
        try:
            swagger = _http_json(url=swagger_url, method="GET", headers=headers, timeout_s=30.0)
            if not isinstance(swagger, Mapping):
                continue
            for path in _discover_tenant_get_paths(swagger=swagger):
                url = f"{api_url}{path}"
                try:
                    payload = _http_json(url=url, method="GET", headers=headers, timeout_s=30.0)
                    tenants = _iter_tenants_from_payload(payload)
                    if tenants:
                        if verbose:
                            print(f"Using swagger endpoint: {path}", file=sys.stderr)
                        return tenants
                except Exception as e:
                    last_error = e
                    continue
        except Exception as e:
            last_error = e
            continue

    raise CippError(
        "Unable to find a tenant-list endpoint on the CIPP API."
        + (f" Last error: {last_error}" if last_error else "")
    )


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="List tenants accessible via the CIPP API (using .env creds).")
    parser.add_argument("--env", default=".env", help="Path to .env file (default: ./.env)")
    parser.add_argument("--endpoint", help="Override API path (e.g. /api/ListTenants)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON array")
    parser.add_argument("--verbose", action="store_true", help="Verbose diagnostics to stderr")
    args = parser.parse_args(list(argv))

    try:
        env = _parse_env_file(Path(args.env))
        tenants = _fetch_tenants(env=env, verbose=bool(args.verbose), endpoint_override=args.endpoint)
    except CippError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    # Sort for readability if we can
    def sort_key(t: Mapping[str, Any]) -> str:
        val = _ci_get(t, "displayName", "tenantName", "name", "defaultDomainName", "domain")
        return str(val or "").lower()

    tenants_sorted = sorted(tenants, key=sort_key)

    if args.json:
        print(json.dumps(tenants_sorted, indent=2, ensure_ascii=False))
        return 0

    print(f"Tenants found: {len(tenants_sorted)}")
    for t in tenants_sorted:
        print(f"- {_format_tenant(t)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

