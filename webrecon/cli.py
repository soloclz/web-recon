"""Host and port Web first-pass reconnaissance."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .dns import run_dns
from .fuzz import run_extensions, run_paths, run_vhost
from .http import HttpClient, get_tls_certificate, inspect_origin, probe_origins
from .public import run_public_sources
from .progress import ProgressReporter

_HOST_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
WEB_LIMIT_NAMES = ("max_pages", "max_depth", "max_body_bytes", "max_requests")


def scan_settings(options: argparse.Namespace) -> dict:
    return {"web": {name: getattr(options, name) for name in WEB_LIMIT_NAMES},
            "max_extra_requests": options.max_extra_requests,
            "public_sources": options.public_sources}


def normalize_host(value: str) -> str:
    value = value.strip().rstrip(".").lower()
    if not value or "://" in value or "/" in value or ":" in value:
        raise ValueError(f"expected a hostname without scheme or port: {value!r}")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname: {value!r}") from exc
    if not _HOST_RE.fullmatch(value):
        raise ValueError(f"invalid hostname: {value!r}")
    return value


def read_hosts(host: str | None, hosts_file: Path | None) -> list[str]:
    if host is not None:
        return [normalize_host(host)]
    assert hosts_file is not None
    found = []
    for number, line in enumerate(hosts_file.read_text(encoding="utf-8").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            found.append(normalize_host(value))
        except ValueError as exc:
            raise ValueError(f"{hosts_file}:{number}: {exc}") from exc
    if not found:
        raise ValueError("hosts file contains no hostnames")
    return list(dict.fromkeys(found))


def resolve_host(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({entry[4][0] for entry in infos}, key=lambda ip: (":" in ip, ip))


def _safe_call(func, *args, **kwargs) -> dict:
    try:
        return func(*args, **kwargs)
    except Exception as exc:
        return {"status": "error", "diagnostics": [f"{type(exc).__name__}: {exc}"]}


def _run_stage(reporter: ProgressReporter | None, host: str, stage: str,
               func, *args, **kwargs) -> dict:
    if reporter is not None:
        reporter.start(host, stage)
    result = _safe_call(func, *args, **kwargs)
    if reporter is not None:
        reporter.finish(host, stage, result.get("status", "error"))
    return result


def _artifact_path(path: str, run_dir: Path) -> str:
    if not Path(path).is_absolute():
        return path
    try:
        return str(Path(path).resolve().relative_to(run_dir.resolve()))
    except (ValueError, OSError):
        return path


def _relative_artifacts(value, run_dir: Path, key: str = ""):
    if isinstance(value, list):
        item_key = "artifact" if key == "artifacts" else ""
        return [_relative_artifacts(item, run_dir, item_key) for item in value]
    if isinstance(value, dict):
        return {name: _relative_artifacts(item, run_dir, name)
                for name, item in value.items()}
    if isinstance(value, str) and key in ("prefix", "artifact", "stdout", "stderr", "meta", "summary"):
        return _artifact_path(value, run_dir)
    return value


def _add_candidates(host: str, result: dict, ips: list[str], port: int) -> list[dict]:
    found: dict[str, dict] = {}
    connected_ips = {probe.get("remote_ip", "") for probe in
                     result.get("stages", {}).get("scheme", {}).get("probes", {}).values()
                     if isinstance(probe, dict) and probe.get("usable") and probe.get("remote_ip")}
    target_ip_port = [f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
                      for ip in sorted(connected_ips)]

    def add(name: str, source: str, endpoint: list[str] | None = target_ip_port):
        try:
            name = normalize_host(name)
        except ValueError:
            return
        if name == host:
            return
        entry = found.setdefault(name, {"name": name, "sources": [], "source_ip_port": endpoint})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if endpoint and not entry["source_ip_port"]:
            entry["source_ip_port"] = endpoint

    for name in result.get("tls", {}).get("san", []):
        add(name, "tls_san")
    for candidate in result.get("dns", {}).get("candidates", []):
        if not candidate.get("wildcard_match"):
            add(candidate.get("name", ""), candidate.get("source", "dns"))
    for origin in result.get("web", {}).values():
        for candidate in origin.get("found_hosts", []):
            add(candidate.get("name", ""), candidate.get("source", "web_link"))
    for stage in result.get("scanners", {}).values():
        for candidate in stage.get("vhost", {}).get("candidates", []):
            if candidate.get("assessment") == "different_from_missing_baseline":
                add(candidate.get("name") or candidate.get("hostname") or "", "ffuf_vhost")
    for candidate in result.get("public_sources", {}).get("candidates", []):
        if candidate.get("kind") == "hostname":
            add(candidate.get("name", ""), candidate.get("source", "public"), None)
    return sorted(found.values(), key=lambda item: item["name"])


def _observed_basenames(web: dict) -> list[str]:
    names = {"index"}
    for page in web.get("pages", []):
        tail = urlsplit(page.get("url", "")).path.rsplit("/", 1)[-1]
        if tail:
            stem = tail.split(".", 1)[0]
            if re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", stem):
                names.add(stem)
    return sorted(names)[:30]


def run_host(host: str, port: int, run_dir: Path, options: argparse.Namespace,
             progress: ProgressReporter | None = None) -> dict:
    slug = hashlib.sha256(host.encode("utf-8")).hexdigest()[:10]
    host_dir = run_dir / "hosts" / f"{host[:80]}-{slug}"
    host_dir.mkdir(parents=True, exist_ok=False)
    result: dict = {"host": host, "port": port, "status": "error", "resolved_ips": [],
                    "scan_settings": scan_settings(options),
                    "stages": {}, "web": {}, "scanners": {}, "new_hosts": []}
    if progress is not None:
        progress.start(host, "resolution")
    try:
        ips = resolve_host(host, port)
    except OSError as exc:
        if progress is not None:
            progress.finish(host, "resolution", "error")
        result["stages"]["resolution"] = {"status": "error", "diagnostics": [str(exc)]}
        (host_dir / "summary.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return result
    if progress is not None:
        progress.finish(host, "resolution", "completed")
    result["resolved_ips"] = ips
    result["stages"]["resolution"] = {"status": "completed", "addresses": ips}
    summary_script = Path(__file__).resolve().parents[1] / "scripts" / "web-summary.py"
    client = HttpClient(host_dir / "responses", summary_script, options.max_body_bytes, options.max_requests)
    with ThreadPoolExecutor(max_workers=1) as dns_pool:
        dns_future = dns_pool.submit(_run_stage, progress, host, "dns", run_dns,
                                     host, ips, options.host_prefixes_wordlist, host_dir / "dns")
        scheme = _run_stage(progress, host, "scheme", probe_origins, host, port, client)
        result["stages"]["scheme"] = {key: value for key, value in scheme.items() if key != "origins"}
        result["tls"] = _run_stage(progress, host, "tls", get_tls_certificate,
                                    host, port, host_dir / "tls")
        for origin, root in scheme.get("origins", []):
            label = urlsplit(origin).scheme
            web = _run_stage(progress, host, f"web:{label}", inspect_origin,
                             origin, root, client, options.max_pages, options.max_depth)
            result["web"][label] = web
            scanner_dir = host_dir / "scanners" / label
            scanner_dir.mkdir(parents=True, exist_ok=True)
            scan_specs = [
                ("vhost", run_vhost, (origin, host, options.host_prefixes_wordlist,
                                      scanner_dir / "vhost")),
                ("paths", run_paths, (origin, options.paths_wordlist,
                                      scanner_dir / "paths")),
                ("extensions", run_extensions,
                 (origin, getattr(options, "extension_names_wordlist", None) or options.paths_wordlist,
                  options.extensions_wordlist,
                  _observed_basenames(web), scanner_dir / "extensions",
                  options.max_extra_requests)),
            ]

            def scan_one(name, function, args):
                stage = f"scanner:{label}:{name}"
                callback = (lambda scan, current, total:
                            progress.update(host, stage, scan, current, total)) if progress else None
                return _run_stage(progress, host, stage, function, *args, progress=callback)

            scanner_results = {}
            workers = getattr(options, "scanner_workers", 1)
            if workers == 1:
                for name, function, args in scan_specs:
                    scanner_results[name] = scan_one(name, function, args)
            else:
                with ThreadPoolExecutor(max_workers=workers) as scan_pool:
                    futures = {scan_pool.submit(scan_one, name, function, args): name
                               for name, function, args in scan_specs}
                    for future in as_completed(futures):
                        scanner_results[futures[future]] = future.result()
            result["scanners"][label] = {
                name: scanner_results[name] for name, _, _ in scan_specs
            }
        result["public_sources"] = (_run_stage(progress, host, "public", run_public_sources,
                                                host, host_dir / "public")
                                    if options.public_sources else {"status": "not_run"})
        result["dns"] = dns_future.result()
        result["stages"]["dns"] = {"status": result["dns"]["status"]}
    result["new_hosts"] = _add_candidates(host, result, ips, port)
    result["request_count"] = client.request_count
    if scheme.get("status") != "completed":
        result["status"] = "unavailable"
    else:
        stages = [result["dns"], result["public_sources"]]
        if "https" in result["web"]:
            stages.append(result["tls"])
        stages += list(result["web"].values())
        stages += [stage for scanner in result["scanners"].values() for stage in scanner.values()]
        result["status"] = ("partial" if any(stage.get("status") in ("error", "unavailable", "partial", "timeout")
                                             for stage in stages) else "completed")
    clean = _relative_artifacts(result, run_dir)
    (host_dir / "summary.json").write_text(json.dumps(clean, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def create_run_dir(path: Path | None) -> Path:
    if path:
        path.mkdir(parents=True, exist_ok=False)
        return path.resolve()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for suffix in range(1000):
        directory = Path.cwd() / f"web-recon-{stamp}{f'-{suffix}' if suffix else ''}"
        try:
            directory.mkdir(exist_ok=False)
        except FileExistsError:
            continue
        return directory.resolve()
    raise RuntimeError("could not allocate a run directory")


def hash_wordlists(wordlists: dict[str, str | None]) -> dict[str, str | None]:
    """Save a content fingerprint so later runs can notice an in-place edit."""
    hashes = {}
    for name, value in wordlists.items():
        if not value:
            hashes[name] = None
            continue
        digest = hashlib.sha256()
        try:
            with Path(value).open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            hashes[name] = None
        else:
            hashes[name] = digest.hexdigest()
    return hashes


def write_run_outputs(run_dir: Path, results: list[dict], port: int,
                      wordlists: dict[str, str | None], *,
                      wordlist_hashes: dict[str, str | None] | None = None,
                      settings: dict | None = None,
                      source_run: Path | None = None,
                      extended_from: Path | None = None,
                      rerun_stages: tuple[str, ...] = ()) -> None:
    """Write the batch overview and one readable report after every host finishes."""
    from .report import write_report

    new_hosts: dict[str, dict] = {}
    processed_hosts = {result["host"] for result in results}
    for result in results:
        for entry in result.get("new_hosts", []):
            if entry["name"] in processed_hosts:
                continue
            item = new_hosts.setdefault(entry["name"], {"name": entry["name"], "observations": []})
            item["observations"].append({"input_host": result["host"], "sources": entry["sources"],
                                         "source_ip_port": entry["source_ip_port"]})
    (run_dir / "new-hosts.txt").write_text("".join(name + "\n" for name in sorted(new_hosts)), encoding="utf-8")
    (run_dir / "new-hosts.jsonl").write_text("".join(json.dumps(new_hosts[name], ensure_ascii=False) + "\n"
                                                  for name in sorted(new_hosts)), encoding="utf-8")
    overview = {"created_at": datetime.now().isoformat(), "port": port, "wordlists": wordlists,
                "wordlist_hashes": wordlist_hashes if wordlist_hashes is not None else hash_wordlists(wordlists),
                "hosts": [{"host": item["host"], "status": item["status"],
                           "action": item.get("action", "scanned"),
                           "resolved_ips": item["resolved_ips"],
                           "new_host_count": len(item.get("new_hosts", []))} for item in results]}
    if settings is not None:
        overview["scan_settings"] = settings
    if source_run is not None:
        overview["source_run"] = str(source_run)
        overview["rerun_stages"] = list(rerun_stages)
        if len(rerun_stages) == 1:
            overview["only"] = rerun_stages[0]
    if extended_from is not None:
        overview["extended_from"] = str(extended_from)
    (run_dir / "run.json").write_text(json.dumps(overview, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_report(run_dir, results)


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--host", help="one hostname")
    group.add_argument("--hosts-file", type=Path, help="one hostname per line")
    ap.add_argument("--port", type=int)
    source_group = ap.add_mutually_exclusive_group()
    source_group.add_argument("--from-run", type=Path,
                              help="reuse a completed run and rerun stages selected by wordlist flags")
    source_group.add_argument("--extend-run", type=Path,
                              help="add hostnames to a completed run without rescanning finished hosts")
    ap.add_argument("--only", choices=("prefixes", "paths", "extensions"),
                    help="optional explicit single stage for legacy reruns")
    ap.add_argument("--host-prefixes-wordlist", type=Path)
    ap.add_argument("--paths-wordlist", type=Path)
    ap.add_argument("--extensions-wordlist", type=Path)
    ap.add_argument("--public-sources", action="store_true")
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--max-pages", type=int, default=50)
    ap.add_argument("--max-depth", type=int, default=2)
    ap.add_argument("--max-body-bytes", type=int, default=1024 * 1024)
    ap.add_argument("--max-requests", type=int, default=200)
    ap.add_argument("--max-extra-requests", type=int, default=100000)
    ap.add_argument("--scanner-workers", type=int, default=1,
                    help="parallel ffuf stages per origin (1-3; each keeps its own 20 req/s cap)")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = ap.parse_args(raw_argv)
    args.explicit_limits = {name for name in (*WEB_LIMIT_NAMES, "max_extra_requests")
                            if any(arg == "--" + name.replace("_", "-") or
                                   arg.startswith("--" + name.replace("_", "-") + "=")
                                   for arg in raw_argv)}
    if args.from_run is None and args.extend_run is None and (
            (args.host is None and args.hosts_file is None) or args.port is None):
        ap.error("fresh runs require --host or --hosts-file and --port")
    if args.from_run is not None:
        if args.hosts_file is not None:
            ap.error("--from-run reads the host list from the source run; omit --hosts-file")
        if args.only is None:
            args.rerun_stages = tuple(stage for stage, name in (
                ("prefixes", "host_prefixes_wordlist"),
                ("paths", "paths_wordlist"),
                ("extensions", "extensions_wordlist"),
            ) if getattr(args, name) is not None)
            if not args.rerun_stages:
                ap.error("--from-run requires at least one wordlist flag")
        else:
            args.rerun_stages = (args.only,)
        if args.only == "prefixes" and args.host_prefixes_wordlist is None:
            ap.error("--only prefixes requires --host-prefixes-wordlist")
        if args.only == "paths" and args.paths_wordlist is None:
            ap.error("--only paths requires --paths-wordlist")
        if args.only == "extensions" and args.extensions_wordlist is None:
            ap.error("--only extensions requires --extensions-wordlist")
        if args.only == "prefixes" and (args.paths_wordlist or args.extensions_wordlist):
            ap.error("prefix rerun accepts only --host-prefixes-wordlist")
        if args.only == "paths" and (args.host_prefixes_wordlist or args.extensions_wordlist):
            ap.error("path rerun accepts only --paths-wordlist")
        if args.only == "extensions" and args.host_prefixes_wordlist:
            ap.error("extension rerun does not use --host-prefixes-wordlist")
        if args.public_sources:
            ap.error("--public-sources is not a wordlist rerun stage")
    elif args.only is not None:
        ap.error("--only requires --from-run")
    if args.extend_run is not None and args.host is None and args.hosts_file is None:
        ap.error("--extend-run requires --host or --hosts-file")
    if args.port is not None and not 1 <= args.port <= 65535:
        ap.error("--port must be between 1 and 65535")
    if args.max_pages < 1 or args.max_depth < 0 or args.max_body_bytes < 1024 or args.max_requests < 4 or args.max_extra_requests < 0:
        ap.error("request and crawl limits are invalid")
    if not 1 <= args.scanner_workers <= 3:
        ap.error("--scanner-workers must be between 1 and 3")
    for name in ("host_prefixes_wordlist", "paths_wordlist", "extensions_wordlist"):
        path = getattr(args, name)
        if path is not None and not path.is_file():
            ap.error(f"--{name.replace('_', '-')} is not a file: {path}")
    if args.from_run is not None:
        from .rerun import rerun_main
        try:
            return rerun_main(args)
        except (OSError, ValueError, RuntimeError) as exc:
            ap.error(str(exc))
    if args.extend_run is not None:
        from .extend import extend_main
        try:
            return extend_main(args)
        except (OSError, ValueError, RuntimeError) as exc:
            ap.error(str(exc))
    try:
        hosts = read_hosts(args.host, args.hosts_file)
        wordlists = {name: str(getattr(args, name).resolve()) if getattr(args, name) else None
                     for name in ("host_prefixes_wordlist", "paths_wordlist", "extensions_wordlist")}
        wordlist_hashes = hash_wordlists(wordlists)
        run_dir = create_run_dir(args.out_dir)
    except (OSError, ValueError, RuntimeError) as exc:
        ap.error(str(exc))
    print(f"Output: {run_dir}", flush=True)
    results = []
    with ProgressReporter(run_dir) as progress:
        for host in hosts:
            print(f"[{host}:{args.port}]", flush=True)
            results.append(run_host(host, args.port, run_dir, args, progress))
    write_run_outputs(run_dir, results, args.port, wordlists, wordlist_hashes=wordlist_hashes,
                      settings=scan_settings(args))
    print(f"Report: {run_dir / 'report.md'}", flush=True)
    print(run_dir)
    return 0 if all(item["status"] == "completed" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
