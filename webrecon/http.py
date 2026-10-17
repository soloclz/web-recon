"""Bounded HTTP discovery with saved curl evidence."""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from .extract import LinkParser, clean_url, empty_inventory, parse_html

MAX_PAGES = 100
MAX_DEPTH = 99
MAX_BODY = 1024 * 1024
FIXED_PATHS = (
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association", "/apple-app-site-association",
    "/.well-known/change-password", "/.git/HEAD", "/.env", "/openapi.json",
    "/swagger.json", "/swagger/v1/swagger.json", "/v3/api-docs", "/api-docs",
    "/README.md", "/CHANGELOG.md", "/package.json", "/composer.json",
)
PROTOCOL_ERRORS = (
    b"plain http request was sent to https port", b"this combination of host and port requires tls",
    b"ssl mode is required", b"running in ssl mode",
    b"speaking plain http to an ssl-enabled server",
)


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, list[str]]
    body: bytes
    prefix: str
    exit_code: int
    remote_ip: str = ""
    redirect_url: str = ""
    truncated: bool = False

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or [""])[-1].split(";", 1)[0].lower()

    @property
    def location(self) -> str:
        return (self.headers.get("location") or [""])[-1]

    def public(self) -> dict:
        return {"url": self.url, "status": self.status, "content_type": self.content_type,
                "size": len(self.body), "prefix": self.prefix, "exit_code": self.exit_code,
                "remote_ip": self.remote_ip, "location": self.location, "truncated": self.truncated,
                "sha256": hashlib.sha256(self.body).hexdigest(),
                "server": (self.headers.get("server") or [""])[-1],
                "x_powered_by": (self.headers.get("x-powered-by") or [""])[-1],
                "cookie_names": [item.split("=", 1)[0].strip() for item in self.headers.get("set-cookie", [])
                                 if "=" in item]}


class BudgetExceeded(RuntimeError):
    pass


def parse_headers(raw: bytes) -> dict[str, list[str]]:
    current: dict[str, list[str]] = {}
    for line in raw.decode("iso-8859-1", "replace").splitlines():
        if line.startswith("HTTP/"):
            current = {}
        elif ":" in line:
            key, val = line.split(":", 1)
            current.setdefault(key.strip().lower(), []).append(val.strip())
    return current


def _write_summary(prefix: Path, script: Path) -> None:
    if not script.exists():
        return
    result = subprocess.run([sys.executable, str(script), str(prefix), "--jsonl"],
                            capture_output=True, text=True, timeout=10, check=False)
    Path(str(prefix) + ".jsonl").write_text(result.stdout, encoding="utf-8")
    if result.stderr:
        Path(str(prefix) + ".summary-errors").write_text(result.stderr, encoding="utf-8")


class HttpClient:
    def __init__(self, out_dir: Path, summary_script: Path, max_body: int = MAX_BODY,
                 max_requests: int = 200):
        self.out_dir = out_dir
        self.summary_script = summary_script
        self.max_body = max_body
        self.max_requests = max_requests
        self.request_count = 0
        self.responses: list[Response] = []
        out_dir.mkdir(parents=True, exist_ok=True)

    def fetch(self, url: str, label: str = "response") -> Response:
        if self.request_count >= self.max_requests:
            raise BudgetExceeded(f"HTTP request limit {self.max_requests} reached")
        self.request_count += 1
        prefix = self.out_dir / f"{self.request_count:03d}-{re.sub(r'[^a-zA-Z0-9_-]', '-', label)[:48]}"
        header_path = Path(str(prefix) + ".headers")
        body_path = Path(str(prefix) + ".body")
        cmd = ["curl", "-q", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "20",
               "--max-filesize", str(self.max_body), "--path-as-is", "-sS", "-D", str(header_path),
               "-o", str(body_path), "-w", "url=%{url_effective}\\nhttp_code=%{http_code}\\n"
               "remote_ip=%{remote_ip}\\nredirect_url=%{redirect_url}\\n"]
        if urlsplit(url).scheme == "https":
            cmd.append("--insecure")
        cmd.extend(["--", url])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25, check=False)
            code, output, errors = proc.returncode, proc.stdout, proc.stderr
        except FileNotFoundError as exc:
            code, output, errors = 127, "", str(exc)
        except subprocess.TimeoutExpired as exc:
            code, output, errors = 124, (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""), "curl process timeout"
        meta = output + f"curl_exit={code}\n"
        Path(str(prefix) + ".meta").write_text(meta, encoding="utf-8")
        Path(str(prefix) + ".errors").write_text(errors, encoding="utf-8")
        if not header_path.exists():
            header_path.write_bytes(b"")
        if not body_path.exists():
            body_path.write_bytes(b"")
        values = dict(line.split("=", 1) for line in meta.splitlines() if "=" in line)
        response = Response(url=url, status=int(values.get("http_code") or 0),
                            headers=parse_headers(header_path.read_bytes()), body=body_path.read_bytes(),
                            prefix=str(prefix), exit_code=code, remote_ip=values.get("remote_ip", ""),
                            redirect_url=values.get("redirect_url", ""), truncated=code == 63)
        self.responses.append(response)
        try:
            _write_summary(prefix, self.summary_script)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return response


def _normalized_body(resp: Response) -> str:
    text = resp.body[:65536].decode("utf-8", "replace").lower()
    path = urlsplit(resp.url).path
    if path and path != "/":
        text = text.replace(path.lower(), "<requested-path>")
    return re.sub(r"web-recon-missing-[0-9a-f]+", "<missing-path>", text[:8192])


def compare_baseline(response: Response, baselines: list[Response]) -> dict:
    if response.exit_code or not response.status:
        return {"assessment": "request_error", "baseline_similarity": None}
    if not baselines or any(x.exit_code for x in baselines):
        return {"assessment": "uncertain", "baseline_similarity": None}
    if any(response.status != x.status for x in baselines):
        return {"assessment": "candidate", "baseline_similarity": 0.0}
    if response.status in (301, 302, 303, 307, 308):
        locations = {x.location for x in baselines}
        if len(locations) == 1 and response.location in locations:
            return {"assessment": "baseline_match", "baseline_similarity": 1.0}
    similarities = [difflib.SequenceMatcher(None, _normalized_body(response), _normalized_body(x),
                                             autojunk=True).ratio() for x in baselines]
    score = min(similarities)
    stable = difflib.SequenceMatcher(None, _normalized_body(baselines[0]),
                                     _normalized_body(baselines[-1]), autojunk=True).ratio() >= .90
    if stable and score >= .94:
        result = "baseline_match"
    elif stable and score < .94:
        result = "candidate"
    else:
        result = "uncertain"
    return {"assessment": result, "baseline_similarity": round(score, 3)}


def same_origin(url: str, origin: str) -> bool:
    try:
        a, b = urlsplit(url), urlsplit(origin)
        return (a.scheme == b.scheme and a.hostname == b.hostname
                and (a.port or (443 if a.scheme == "https" else 80))
                == (b.port or (443 if b.scheme == "https" else 80)))
    except ValueError:
        return False


def parse_certificate_sans(certificate_text: str) -> list[str]:
    inside = False
    found = set()
    for line in certificate_text.splitlines():
        if "Subject Alternative Name" in line:
            inside = True
            continue
        if not inside:
            continue
        if "X509v3 " in line or re.match(r"\s*Signature Algorithm:", line):
            break
        for dns_name, ip_address in re.findall(r"DNS:([^,\s]+)|IP Address:([^,\s]+)", line):
            found.add(dns_name or ip_address)
    return sorted(found)


def get_tls_certificate(host: str, port: int, out_dir: Path,
                        on_candidate: Callable[[dict], None] | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                protocol, cipher = tls.version(), tls.cipher()
        if not der:
            raise ValueError("server did not return a certificate")
        pem = ssl.DER_cert_to_PEM_cert(der)
        pem_path = out_dir / "certificate.pem"
        pem_path.write_text(pem, encoding="ascii")
        proc = subprocess.run(["openssl", "x509", "-noout", "-text"], input=pem,
                              capture_output=True, text=True, timeout=5, check=False)
        text_path = out_dir / "certificate.txt"
        text_path.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        if proc.returncode != 0:
            raise ValueError(f"openssl x509 exited with status {proc.returncode}")
        sans = parse_certificate_sans(proc.stdout)
        if on_candidate is not None:
            for name in sans:
                on_candidate({"kind": "hostname", "source": "tls_san", "name": name})
        return {"status": "completed", "san": sans, "certificate_verified": False,
                "protocol": protocol,
                "cipher": cipher[0] if cipher else None,
                "artifacts": [str(pem_path), str(text_path)]}
    except (OSError, ValueError, ssl.SSLError, subprocess.TimeoutExpired) as exc:
        (out_dir / "certificate.errors").write_text(str(exc), encoding="utf-8")
        return {"status": "unavailable", "san": [], "diagnostics": [str(exc)],
                "artifacts": [str(out_dir / "certificate.errors")]}


def probe_origins(host: str, port: int, client: HttpClient,
                  on_candidate: Callable[[dict], None] | None = None) -> dict:
    probes = {}
    origins = []
    for scheme in ("http", "https"):
        origin = f"{scheme}://{host}:{port}"
        try:
            response = client.fetch(origin + "/", f"probe-{scheme}")
            protocol_error = scheme == "http" and any(marker in response.body.lower() for marker in PROTOCOL_ERRORS)
            usable = response.exit_code == 0 and response.status > 0 and not protocol_error
            probes[scheme] = {**response.public(), "usable": usable,
                              "protocol_error": protocol_error}
            if usable:
                origins.append((origin, response))
                if on_candidate is not None:
                    on_candidate({"kind": "origin", "source": "scheme_probe", "url": origin,
                                  "status_code": response.status, "remote_ip": response.remote_ip})
        except BudgetExceeded as exc:
            probes[scheme] = {"status": "error", "diagnostics": [str(exc)]}
    return {"status": "completed" if origins else "unavailable", "probes": probes,
            "origins": origins}


def _robots_urls(body: bytes, base: str) -> tuple[list[str], list[tuple[str, str]]]:
    sitemaps: list[str] = []
    paths: list[tuple[str, str]] = []
    for raw in body.decode("utf-8", "replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        key, sep, value = line.partition(":")
        if not sep or not value.strip():
            continue
        value = value.strip()
        if key.lower() == "sitemap":
            found = clean_url(value, base)
            if found:
                sitemaps.append(found)
        elif (key.lower() in ("allow", "disallow") and value.startswith("/")
              and "*" not in value and "$" not in value):
            found = clean_url(value, base)
            if found:
                paths.append((found, "robots_" + key.lower()))
    return sitemaps[:30], paths[:30]


def _redirect_target(location: str, requested_url: str, origin: str) -> str | None:
    target = clean_url(location, requested_url)
    if target is None or same_origin(target, origin):
        return target
    # Apache DirectorySlash may omit the service's nondefault port from an
    # absolute redirect. Keep that port only for a same-host slash redirect.
    requested, redirected = urlsplit(requested_url), urlsplit(target)
    try:
        no_port = requested.port is not None and redirected.port is None
    except ValueError:
        return target
    if (requested.scheme == redirected.scheme and requested.hostname == redirected.hostname
            and requested.path not in ("", "/") and not requested.path.endswith("/")
            and no_port and redirected.path == requested.path + "/"):
        return urlunsplit((requested.scheme, requested.netloc, redirected.path,
                           redirected.query, ""))
    return target


def _sitemap_locs(body: bytes, base: str) -> tuple[list[str], bool]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return [], False
    is_index = root.tag.rsplit("}", 1)[-1].lower() == "sitemapindex"
    found = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1].lower() == "loc" and node.text:
            url = clean_url(node.text, base)
            if url:
                found.append(url)
            if len(found) >= 1000:
                break
    return found, is_index


def _map_urls(origin: str, url: str, source: str, found_hosts: list[dict],
              candidate_urls: list[dict],
              on_candidate: Callable[[dict], None] | None = None) -> bool:
    if same_origin(url, origin):
        candidate_urls.append({"url": url, "source": source})
        if on_candidate is not None:
            on_candidate({"kind": "url", "url": url, "source": source})
        return True
    hostname = urlsplit(url).hostname
    if hostname:
        found_hosts.append({"name": hostname, "source": source})
        if on_candidate is not None:
            on_candidate({"kind": "hostname", "name": hostname, "source": source})
    return False


def _html_response(response: Response) -> bool:
    return (response.content_type in ("text/html", "application/xhtml+xml")
            or response.body[:1024].lstrip().lower().startswith((b"<!doctype html", b"<html")))


def _emit_inventory(inventory: dict[str, list[dict]],
                    on_candidate: Callable[[dict], None] | None) -> None:
    if on_candidate is None:
        return
    for category in ("emails", "external_files", "images", "videos", "audio"):
        for entry in inventory[category]:
            on_candidate({"kind": "inventory", "category": category, **entry})


def _map_external_asset_hosts(origin: str, inventory: dict[str, list[dict]],
                              found_hosts: list[dict],
                              on_candidate: Callable[[dict], None] | None) -> None:
    source_names = {"external_files": "external_file_reference", "images": "image_reference",
                    "videos": "video_reference", "audio": "audio_reference"}
    observed = {(item["name"], item["source"]) for item in found_hosts}
    for category, source in source_names.items():
        for item in inventory.get(category, []):
            url = item.get("value", "")
            if same_origin(url, origin):
                continue
            hostname = urlsplit(url).hostname
            if hostname and (hostname, source) not in observed:
                observed.add((hostname, source))
                found_hosts.append({"name": hostname, "source": source})
                if on_candidate is not None:
                    on_candidate({"kind": "hostname", "name": hostname, "source": source})


def _announce_root(origin: str, root: Response, parsed: LinkParser | None,
                   inventory: dict[str, list[dict]],
                   on_candidate: Callable[[dict], None] | None) -> None:
    """Show clues already available from the scheme probe before fixed checks."""
    if on_candidate is None or root.exit_code or root.truncated:
        return
    public = root.public()
    observed = {"kind": "page", "source": "crawl", "url": root.url,
                "status_code": root.status}
    for key in ("server", "x_powered_by", "cookie_names"):
        if public[key]:
            observed[key] = public[key]
    on_candidate(observed)
    if root.location:
        target = _redirect_target(root.location, root.url, origin)
        if target:
            _map_urls(origin, target, "redirect", [], [], on_candidate)
    if parsed is None:
        return
    _emit_inventory(inventory, on_candidate)
    reference_base = parsed.reference_base(root.url)
    if parsed.title:
        on_candidate({"kind": "title", "source": "html_title", "url": root.url,
                      "title": parsed.title[:500]})
    for field in parsed.fields[:100]:
        on_candidate({"kind": "field", "source": "html_field", "url": root.url,
                      **field})
    for comment in parsed.comments[:100]:
        if comment.strip():
            on_candidate({"kind": "comment", "source": "html_comment", "url": root.url,
                          "text": comment[:2000]})
    for form in parsed.forms:
        action = (clean_url(form["action"], reference_base)
                  if form.get("action") else root.url)
        if action:
            if same_origin(action, origin):
                on_candidate({"kind": "url", "url": action, "source": "form_action",
                              "method": (form.get("method") or "get").lower()})
            else:
                _map_urls(origin, action, "form_action", [], [], on_candidate)
    for raw, kind in parsed.links:
        target = clean_url(raw, reference_base)
        if target:
            _map_urls(origin, target, kind + "_link", [], [], on_candidate)
    for raw in parsed.scripts:
        target = clean_url(raw, reference_base)
        if target:
            _map_urls(origin, target, "script_src", [], [], on_candidate)
    for comment in parsed.comments:
        for match in re.findall(r"https?://[^\s<>\"']+", comment):
            target = clean_url(match, root.url)
            if target:
                _map_urls(origin, target, "html_comment", [], [], on_candidate)


def inspect_origin(origin: str, root: Response, client: HttpClient,
                   max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH,
                   on_candidate: Callable[[dict], None] | None = None) -> dict:
    """Inspect one usable origin. Every fetched response has raw and JSONL evidence."""
    found_hosts: list[dict] = []
    candidate_urls: list[dict] = []
    fixed: list[dict] = []
    diagnostics: list[str] = []
    partial = False
    partial_reasons: set[str] = set()
    root_parser = (parse_html(root.body) if not root.exit_code and not root.truncated
                   and _html_response(root) else None)
    inventory = (root_parser.inventory(root.url, root.prefix) if root_parser
                 else empty_inventory())
    _announce_root(origin, root, root_parser, inventory, on_candidate)
    _map_external_asset_hosts(origin, inventory, found_hosts, on_candidate)
    try:
        baselines = [client.fetch(origin + "/web-recon-missing-" + uuid.uuid4().hex, "missing-control")
                     for _ in range(2)]
    except BudgetExceeded as exc:
        return {"status": "error", "diagnostics": [str(exc)], "found_hosts": found_hosts,
                "candidate_urls": [], "fixed": [], "pages": [], "scripts": [],
                "source_maps": [], "inventory": inventory}
    baseline_public = [x.public() for x in baselines]
    for response in baselines:
        if response.exit_code or response.truncated:
            partial = True
            partial_reasons.add("incomplete_body")
            candidate_urls.append({"url": response.url, "source": "incomplete_body"})
    fetched_fixed: dict[str, Response] = {}
    sitemap_queue: deque[tuple[str, int]] = deque()
    robots_pages: list[str] = []
    for path in FIXED_PATHS:
        url = origin + path
        try:
            response = client.fetch(url, "fixed-" + path.strip("/").replace("/", "-"))
        except BudgetExceeded as exc:
            diagnostics.append(str(exc))
            partial = True
            partial_reasons.add("request_limit")
            candidate_urls.append({"url": url, "source": "request_limit"})
            continue
        result = {**response.public(), **compare_baseline(response, baselines)}
        fixed.append(result)
        if result["assessment"] == "candidate" and on_candidate is not None:
            on_candidate({"kind": "fixed_path", "source": "fixed_path", "url": url,
                          "status_code": response.status, "assessment": result["assessment"]})
        if response.exit_code or response.truncated:
            partial = True
            partial_reasons.add("incomplete_body")
            candidate_urls.append({"url": url, "source": "incomplete_body"})
        fetched_fixed[url] = response
        if path.startswith("/sitemap") and result["assessment"] == "candidate":
            sitemap_queue.append((url, 0))
        if path == "/robots.txt" and result["assessment"] == "candidate":
            sitemaps, paths = _robots_urls(response.body, url)
            for item in sitemaps:
                if _map_urls(origin, item, "robots_sitemap", found_hosts, candidate_urls,
                             on_candidate):
                    sitemap_queue.append((item, 0))
            for item, source in paths:
                if _map_urls(origin, item, source, found_hosts, candidate_urls,
                             on_candidate):
                    robots_pages.append(item)
    sitemap_results = []
    seen_sitemaps = set()
    while sitemap_queue and len(seen_sitemaps) < 10:
        url, depth = sitemap_queue.popleft()
        if url in seen_sitemaps or not same_origin(url, origin):
            continue
        seen_sitemaps.add(url)
        response = fetched_fixed.get(url)
        if response is None:
            try:
                response = client.fetch(url, "sitemap")
            except BudgetExceeded as exc:
                diagnostics.append(str(exc))
                partial = True
                partial_reasons.add("request_limit")
                candidate_urls.append({"url": url, "source": "request_limit"})
                continue
        if response.exit_code or response.truncated:
            partial = True
            partial_reasons.add("incomplete_body")
            candidate_urls.append({"url": url, "source": "incomplete_body"})
        assessment = compare_baseline(response, baselines)
        locs, is_index = _sitemap_locs(response.body, url) if assessment["assessment"] == "candidate" else ([], False)
        sitemap_results.append({"url": url, "assessment": assessment, "is_index": is_index,
                                "loc_count_saved": len(locs), "prefix": response.prefix})
        for item in locs:
            if _map_urls(origin, item, "sitemap", found_hosts, candidate_urls,
                         on_candidate) and is_index and depth < 2:
                sitemap_queue.append((item, depth + 1))
    pages = []
    scripts = []
    source_maps = []
    page_queue: deque[tuple[str, int, Response | None]] = deque([(origin + "/", 0, root)])
    unique_robots_pages = [url for url in dict.fromkeys(robots_pages)
                           if url != origin + "/"]
    seen_pages = set()
    depth_limited = set()

    def defer_at_depth(url: str) -> None:
        nonlocal partial
        if (url in seen_pages or url in depth_limited or
                any(pending_url == url for pending_url, _, _ in page_queue)):
            return
        depth_limited.add(url)
        partial = True
        partial_reasons.add("depth_limit")
        candidate_urls.append({"url": url, "source": "depth_limit"})

    def queue_robots_after_root(url: str) -> None:
        if url != origin + "/":
            return
        if max_depth >= 1:
            page_queue.extend((item, 1, None) for item in unique_robots_pages)
        else:
            for item in unique_robots_pages:
                defer_at_depth(item)

    seen_scripts = set()
    while page_queue and len(pages) < max_pages:
        url, depth, cached = page_queue.popleft()
        if url in seen_pages or not same_origin(url, origin):
            continue
        seen_pages.add(url)
        try:
            response = cached or client.fetch(url, "crawl")
        except BudgetExceeded as exc:
            diagnostics.append(str(exc))
            partial = True
            partial_reasons.add("request_limit")
            candidate_urls.append({"url": url, "source": "request_limit"})
            continue
        if response.exit_code or response.truncated:
            partial = True
            partial_reasons.add("incomplete_body")
            candidate_urls.append({"url": url, "source": "incomplete_body"})
            queue_robots_after_root(url)
            continue
        page = {"url": url, "depth": depth, **response.public()}
        pages.append(page)
        if on_candidate is not None:
            observed = {"kind": "page", "source": "crawl", "url": url,
                        "status_code": response.status}
            if page["server"]:
                observed["server"] = page["server"]
            if page["x_powered_by"]:
                observed["x_powered_by"] = page["x_powered_by"]
            if page["cookie_names"]:
                observed["cookie_names"] = page["cookie_names"]
            on_candidate(observed)
        if response.location:
            target = _redirect_target(response.location, url, origin)
            if target and _map_urls(origin, target, "redirect", found_hosts,
                                    candidate_urls, on_candidate):
                if depth < max_depth:
                    page_queue.append((target, depth + 1, None))
                else:
                    defer_at_depth(target)
        if not _html_response(response):
            queue_robots_after_root(url)
            continue
        parsed = root_parser if response is root and root_parser is not None else parse_html(response.body)
        page_inventory = parsed.inventory(url, response.prefix)
        reference_base = parsed.reference_base(url)
        if url != root.url:
            for category, entries in page_inventory.items():
                inventory[category].extend(entries)
            _emit_inventory(page_inventory, on_candidate)
            _map_external_asset_hosts(origin, page_inventory, found_hosts, on_candidate)
        page["title"] = parsed.title[:500]
        page["forms"] = parsed.forms[:100]
        page["fields"] = parsed.fields[:100]
        page["comments"] = [comment[:2000] for comment in parsed.comments[:100]]
        if page["title"] and on_candidate is not None:
            on_candidate({"kind": "title", "source": "html_title", "url": url,
                          "title": page["title"]})
        if on_candidate is not None:
            for field in page["fields"]:
                on_candidate({"kind": "field", "source": "html_field", "url": url,
                              **field})
            for comment in page["comments"]:
                if comment.strip():
                    on_candidate({"kind": "comment", "source": "html_comment",
                                  "url": url, "text": comment})
        for form in parsed.forms:
            action = (clean_url(form["action"], reference_base)
                      if form.get("action") else url)
            if action:
                if same_origin(action, origin):
                    entry = {"url": action, "source": "form_action",
                             "method": (form.get("method") or "get").lower()}
                    candidate_urls.append(entry)
                    if on_candidate is not None:
                        on_candidate({"kind": "url", **entry})
                else:
                    _map_urls(origin, action, "form_action", found_hosts, candidate_urls,
                              on_candidate)
        for raw, kind in parsed.links:
            target = clean_url(raw, reference_base)
            if not target:
                continue
            if _map_urls(origin, target, kind + "_link", found_hosts, candidate_urls,
                         on_candidate):
                if depth < max_depth:
                    page_queue.append((target, depth + 1, None))
                else:
                    defer_at_depth(target)
        for raw in parsed.scripts:
            target = clean_url(raw, reference_base)
            if not target:
                continue
            if _map_urls(origin, target, "script_src", found_hosts, candidate_urls,
                         on_candidate):
                seen_scripts.add(target)
        for comment in parsed.comments:
            for match in re.findall(r"https?://[^\s<>\"']+", comment):
                target = clean_url(match, url)
                if target:
                    _map_urls(origin, target, "html_comment", found_hosts, candidate_urls,
                              on_candidate)
        queue_robots_after_root(url)
    pending_pages = [item for item in page_queue if item[0] not in seen_pages]
    if pending_pages:
        partial = True
        partial_reasons.add("crawl_limit")
    for pending_url, _, _ in pending_pages:
        candidate_urls.append({"url": pending_url, "source": "crawl_limit"})
    for script_url in sorted(seen_scripts)[:20]:
        try:
            response = client.fetch(script_url, "javascript")
        except BudgetExceeded as exc:
            diagnostics.append(str(exc))
            partial = True
            partial_reasons.add("request_limit")
            candidate_urls.append({"url": script_url, "source": "request_limit"})
            continue
        scripts.append(response.public())
        if response.exit_code or response.truncated:
            partial = True
            partial_reasons.add("incomplete_body")
            candidate_urls.append({"url": script_url, "source": "incomplete_body"})
            continue
        body_text = response.body.decode("utf-8", "replace")
        matches = re.findall(r"(?:\/\/[@#]\s*sourceMappingURL=|\/\*#\s*sourceMappingURL=)([^\s*]+)", body_text)
        map_urls = [clean_url(item, script_url) for item in matches]
        if not map_urls:
            parts = urlsplit(script_url)
            map_urls = [urlunsplit((parts.scheme, parts.netloc, parts.path + ".map", "", ""))]
        for map_url in map_urls[:2]:
            if not map_url or not _map_urls(
                    origin, map_url, "javascript_source_map", found_hosts, candidate_urls,
                    on_candidate if not same_origin(map_url, origin) else None):
                continue
            try:
                map_response = client.fetch(map_url, "source-map")
            except BudgetExceeded as exc:
                diagnostics.append(str(exc))
                partial = True
                partial_reasons.add("request_limit")
                continue
            result = {**map_response.public(), **compare_baseline(map_response, baselines)}
            if map_response.exit_code or map_response.truncated:
                partial = True
                partial_reasons.add("incomplete_body")
                candidate_urls.append({"url": map_url, "source": "incomplete_body"})
            if result["assessment"] == "candidate":
                try:
                    map_data = json.loads(map_response.body)
                    result["sources"] = list(map_data.get("sources", []))[:500] if isinstance(map_data, dict) else []
                except (ValueError, TypeError):
                    result["sources"] = []
                if on_candidate is not None:
                    on_candidate({"kind": "source_map", "source": "javascript_source_map",
                                  "url": map_url, "status_code": map_response.status,
                                  "sources": result["sources"]})
            source_maps.append(result)
    if len(seen_scripts) > 20 or sitemap_queue:
        partial = True
    if len(seen_scripts) > 20:
        partial_reasons.add("script_limit")
    if sitemap_queue:
        partial_reasons.add("sitemap_limit")
    for script_url in sorted(seen_scripts)[20:]:
        candidate_urls.append({"url": script_url, "source": "script_limit"})
    return {"status": "partial" if partial else "completed", "origin": origin, "baseline": baseline_public,
            "partial_reasons": sorted(partial_reasons),
            "fixed": fixed, "sitemaps": sitemap_results, "pages": pages,
            "scripts": scripts, "source_maps": source_maps, "found_hosts": found_hosts,
            "candidate_urls": candidate_urls, "inventory": inventory,
            "diagnostics": diagnostics,
            "request_count": client.request_count}
