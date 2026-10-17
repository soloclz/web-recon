"""Optional lookups in public CT and web archive indexes.

These requests go only to crt.sh and the Wayback CDX endpoint. Returned names
and URLs are evidence candidates; this module never contacts those targets.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES_PER_SOURCE = 500
_NON_PUBLIC_SUFFIXES = {
    "arpa", "example", "htb", "internal", "invalid", "lan", "local",
    "localhost", "onion", "test",
}
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class PublicSourceError(Exception):
    """A public index could not be queried or parsed."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, new_url):  # noqa: ARG002
        return None


def _fetch(url: str) -> bytes:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "web-recon/0.1"})
    with build_opener(_NoRedirect()).open(request, timeout=TIMEOUT_SECONDS) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise PublicSourceError(f"response exceeds {MAX_RESPONSE_BYTES} bytes")
    return data


def _normalize_host(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if len(value) > 253 or not value or any(not _LABEL.fullmatch(label) for label in value.split(".")):
        return None
    return value


def _is_public_host(host: str) -> bool:
    if host.count(".") < 1 or host.split(".")[-1] in _NON_PUBLIC_SUFFIXES:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def _in_scope(candidate: str, host: str) -> bool:
    return candidate == host or candidate.endswith("." + host)


def _crt_candidates(data: object, host: str) -> list[dict[str, str]]:
    if not isinstance(data, list):
        raise PublicSourceError("crt.sh JSON is not an array")
    found: set[tuple[str, str]] = set()
    for row in data:
        if not isinstance(row, dict) or not isinstance(row.get("name_value"), str):
            continue
        for raw_name in row["name_value"].splitlines():
            is_pattern = raw_name.strip().startswith("*.")
            name = _normalize_host(raw_name.strip()[2:] if is_pattern else raw_name)
            if not name or not _in_scope(name, host) or (name == host and not is_pattern):
                continue
            if is_pattern:
                found.add(("hostname_pattern", "*." + name))
            else:
                found.add(("hostname", name))
            if len(found) >= MAX_CANDIDATES_PER_SOURCE:
                break
        if len(found) >= MAX_CANDIDATES_PER_SOURCE:
            break
    return [{"kind": kind, "name": name, "source": "crt.sh"} for kind, name in sorted(found)]


def _wayback_candidates(data: object, host: str) -> list[dict[str, str]]:
    if not isinstance(data, list) or not data or not isinstance(data[0], list):
        raise PublicSourceError("Wayback CDX JSON has no column header")
    try:
        original_index = data[0].index("original")
    except ValueError as exc:
        raise PublicSourceError("Wayback CDX JSON lacks original column") from exc

    found_urls: set[str] = set()
    found_hosts: set[str] = set()
    for row in data[1:]:
        if not isinstance(row, list) or len(row) <= original_index:
            continue
        original = row[original_index]
        if not isinstance(original, str) or len(original) > 2048:
            continue
        try:
            parsed = urlsplit(original)
            candidate_host = _normalize_host(parsed.hostname or "")
        except ValueError:
            continue
        if parsed.scheme.lower() not in {"http", "https"} or not candidate_host or not _in_scope(candidate_host, host):
            continue
        found_urls.add(original)
        if candidate_host != host:
            found_hosts.add(candidate_host)
        if len(found_urls) >= MAX_CANDIDATES_PER_SOURCE:
            break
    candidates = [{"kind": "hostname", "name": name, "source": "wayback_cdx"} for name in sorted(found_hosts)]
    candidates.extend({"kind": "url", "url": url, "source": "wayback_cdx"} for url in sorted(found_urls))
    return candidates


def run_public_sources(host: str, out_dir: Path,
                       on_candidate: Callable[[dict], None] | None = None) -> dict:
    """Collect bounded public-index candidates for the exact input host.

    ``status`` is completed if both indexes were read, error if either query
    failed, and unavailable for an address/name unsuitable for public indexes.
    Per-source states in ``sources`` distinguish a partial result from no data.
    """
    normalized = _normalize_host(host)
    result: dict = {
        "status": "unavailable",
        "candidates": [],
        "artifacts": [],
        "diagnostics": [],
        "sources": {},
    }
    if not normalized or not _is_public_host(normalized):
        result["diagnostics"].append("public indexes skipped for this host")
        return result

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    queries = (
        (
            "crt.sh",
            "https://crt.sh/?" + urlencode({"q": "%." + normalized, "output": "json"}),
            "crtsh.json",
            _crt_candidates,
        ),
        (
            "wayback_cdx",
            "https://web.archive.org/cdx/search/cdx?"
            + urlencode({
                "url": normalized,
                "matchType": "domain",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": str(MAX_CANDIDATES_PER_SOURCE + 1),
            }),
            "wayback-cdx.json",
            _wayback_candidates,
        ),
    )

    failed = False
    for source, url, filename, parser in queries:
        item: dict = {"status": "error", "query_url": url, "count": 0}
        result["sources"][source] = item
        try:
            raw = _fetch(url)
            artifact = out_dir / filename
            artifact.write_bytes(raw)
            item["artifact"] = str(artifact)
            result["artifacts"].append(str(artifact))
            parsed = json.loads(raw)
            candidates = parser(parsed, normalized)
            item["status"] = "completed"
            item["count"] = len(candidates)
            result["candidates"].extend(candidates)
            if on_candidate is not None:
                for candidate in candidates:
                    on_candidate(candidate)
            if source == "crt.sh" and len(candidates) >= MAX_CANDIDATES_PER_SOURCE:
                item["truncated"] = True
                result["diagnostics"].append("crt.sh candidate limit reached; more names may exist")
            if source == "wayback_cdx" and isinstance(parsed, list) and len(parsed) - 1 > MAX_CANDIDATES_PER_SOURCE:
                item["truncated"] = True
                result["diagnostics"].append("Wayback CDX result limit reached; more archived URLs may exist")
        except (OSError, ValueError, TypeError, PublicSourceError) as exc:
            failed = True
            item["error"] = f"{type(exc).__name__}: {exc}"
            result["diagnostics"].append(f"{source}: {item['error']}")
    result["status"] = "error" if failed else "completed"
    return result
