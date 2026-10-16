"""Reuse a completed run while scanning stages selected by new wordlists."""

from __future__ import annotations

import hashlib
import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from pathlib import Path

from .cli import (_add_candidates, _observed_basenames, _relative_artifacts,
                  _run_stage, create_run_dir, normalize_host, write_run_outputs)
from .dns import rerun_dns_words
from .fuzz import run_extension_filenames, run_extensions, run_paths, run_vhost
from .progress import ProgressReporter


_EVIDENCE_KEYS = {"prefix", "artifact", "stdout", "stderr", "meta"}


def _host_dir(run_dir: Path, host: str) -> Path:
    slug = hashlib.sha256(host.encode("utf-8")).hexdigest()[:10]
    return run_dir / "hosts" / f"{host[:80]}-{slug}"


def _source_evidence_paths(value, source_run: Path, key: str = ""):
    """Keep old evidence links valid without copying response bodies."""
    if isinstance(value, dict):
        return {name: _source_evidence_paths(item, source_run, name)
                for name, item in value.items()}
    if isinstance(value, list):
        return [_source_evidence_paths(item, source_run,
                                       "artifact" if key == "artifacts" else "")
                for item in value]
    if isinstance(value, str) and key in _EVIDENCE_KEYS:
        path = Path(value)
        if not path.is_absolute():
            return str((source_run / path).resolve())
    return value


def _read_source(source_run: Path) -> tuple[dict, list[dict]]:
    if not source_run.is_dir():
        raise ValueError(f"source run is not a directory: {source_run}")
    try:
        overview = json.loads((source_run / "run.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("--from-run requires a completed run with run.json") from exc
    port = overview.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("source run has no valid port")
    hosts = overview.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise ValueError("source run has no host list")
    summaries = []
    for entry in hosts:
        try:
            host = normalize_host(entry["host"])
            source = _host_dir(source_run, host) / "summary.json"
            summary = json.loads(source.read_text(encoding="utf-8"))
        except (KeyError, TypeError, OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"source host summary is missing or invalid: {entry!r}") from exc
        if summary.get("host") != host or summary.get("port") != port:
            raise ValueError(f"source host summary does not match run.json: {host}")
        summaries.append(_source_evidence_paths(summary, source_run))
    return overview, summaries


def _source_roots(source_run: Path) -> list[Path]:
    """Allow evidence from this run and existing ancestors in its run history."""
    roots = []
    seen = set()
    current = source_run.resolve()
    while current not in seen and (current / "run.json").is_file():
        roots.append(current)
        seen.add(current)
        try:
            previous = json.loads((current / "run.json").read_text(encoding="utf-8")).get("source_run")
        except (OSError, json.JSONDecodeError):
            break
        if not isinstance(previous, str) or not previous:
            break
        pointer = Path(previous)
        current = (pointer if pointer.is_absolute() else current / pointer).resolve()
    return roots


def _bundle_evidence(result: dict, run_dir: Path, host_dir: Path,
                     source_roots: list[Path]) -> dict:
    """Copy retained raw evidence so the new run can be moved on its own."""
    host = result["host"]
    owners: dict[Path, Path] = {}

    def target_for(source: Path) -> Path:
        for root in source_roots:
            old_host = _host_dir(root, host).resolve()
            if not old_host.is_relative_to(root):
                continue
            try:
                relative = source.relative_to(old_host)
            except ValueError:
                continue
            if relative.parts and relative.parts[0] == "reused":
                return host_dir / relative
            namespace = f"{root.name[:40]}-{hashlib.sha256(str(root).encode()).hexdigest()[:10]}"
            return host_dir / "reused" / namespace / relative
        raise ValueError(f"evidence path is outside the source run history: {source}")

    def copy_file(source: Path) -> Path:
        source = source.resolve()
        if not source.is_file():
            raise ValueError(f"referenced evidence is missing: {source}")
        target = target_for(source)
        owner = owners.get(target)
        if owner is not None:
            if owner != source:
                raise ValueError(f"evidence destination collision: {target}")
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise ValueError(f"evidence destination already exists: {target}")
        shutil.copy2(source, target)
        owners[target] = source
        return target

    def rewrite(value, key: str = ""):
        if isinstance(value, dict):
            return {name: rewrite(item, name) for name, item in value.items()}
        if isinstance(value, list):
            item_key = "artifact" if key == "artifacts" else ""
            return [rewrite(item, item_key) for item in value]
        if not isinstance(value, str) or key not in _EVIDENCE_KEYS:
            return value
        source = Path(value)
        if not source.is_absolute():
            source = run_dir / source
        source = source.resolve()
        if source.is_relative_to(run_dir):
            return str(source)
        if key == "prefix":
            sidecars = sorted(source.parent.glob(source.name + ".*"))
            if not (source.parent / (source.name + ".body")).is_file():
                raise ValueError(f"referenced response body is missing: {source}.body")
            target = target_for(source)
            for sidecar in sidecars:
                if sidecar.is_file():
                    copy_file(sidecar)
            return str(target)
        return str(copy_file(source))

    return rewrite(result)


def _prune_reused_evidence(result: dict, host_dir: Path) -> None:
    """Discard copied evidence from stages replaced by this rerun."""
    reused = host_dir / "reused"
    if not reused.is_dir():
        return
    referenced: set[Path] = set()

    def collect(value, key: str = "") -> None:
        if isinstance(value, dict):
            for name, item in value.items():
                collect(item, name)
        elif isinstance(value, list):
            for item in value:
                collect(item, "artifact" if key == "artifacts" else "")
        elif isinstance(value, str) and key in _EVIDENCE_KEYS:
            path = Path(value).resolve()
            if key == "prefix":
                referenced.update(item.resolve() for item in path.parent.glob(path.name + ".*")
                            if item.is_file())
            else:
                referenced.add(path)

    collect(result)
    for path in reused.rglob("*"):
        if path.is_file() and path.resolve() not in referenced:
            path.unlink()
    for directory in sorted((path for path in reused.rglob("*") if path.is_dir()),
                            key=lambda path: len(path.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass
    try:
        reused.rmdir()
    except OSError:
        pass


def _previous_paths_wordlist(source_run: Path, overview: dict, result: dict,
                             label: str) -> Path | None:
    wordlists = overview.get("wordlists") or {}
    for name in ("extension_names_wordlist", "paths_wordlist"):
        value = wordlists.get(name)
        if value:
            path = Path(value)
            if path.is_file():
                return path
            if name == "extension_names_wordlist":
                raise ValueError("previous extension filename wordlist is unavailable; "
                                 "pass --paths-wordlist with --only extensions")
    source = _host_dir(source_run, result["host"]) / "scanners" / label / "paths" / "paths.status.json"
    previous = result.get("scanners", {}).get(label, {}).get("paths", {})
    status_files = [source]
    status_files.extend(Path(path) for path in previous.get("artifacts", [])
                        if isinstance(path, str) and path.endswith("paths.status.json"))
    for source in status_files:
        if not source.is_file():
            continue
        try:
            argv = json.loads(source.read_text(encoding="utf-8"))["argv"]
            word_arg = argv[argv.index("-w") + 1]
            path = Path(word_arg.rsplit(":FUZZ", 1)[0])
            if path.is_file():
                return path
        except (OSError, ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError):
            pass
    if previous.get("status") not in (None, "not_run"):
        raise ValueError("previous path wordlist is unavailable; pass --paths-wordlist for extension rerun")
    return None


def _status(result: dict) -> str:
    if result.get("stages", {}).get("resolution", {}).get("status") != "completed":
        return "error"
    if result.get("stages", {}).get("scheme", {}).get("status") != "completed":
        return "unavailable"
    stages = [result.get("dns", {}), result.get("public_sources", {})]
    if "https" in result.get("web", {}):
        stages.append(result.get("tls", {}))
    stages.extend(result.get("web", {}).values())
    stages.extend(stage for scanner in result.get("scanners", {}).values()
                  for stage in scanner.values() if isinstance(stage, dict))
    return "partial" if any(stage.get("status") in {"error", "unavailable", "partial", "timeout"}
                            for stage in stages) else "completed"


def _merge_filenames(previous: dict, replacement: dict) -> dict:
    merged = deepcopy(previous)
    def old_filename_item(path: str) -> bool:
        return Path(path).name.startswith(("extension-filenames-", "extension-names-"))

    old_diagnostics = [item for item in previous.get("diagnostics", [])
                       if not str(item).startswith(("extension-filenames-", "extension filename phase:"))]
    known_status = previous.get("known_basename_status")
    if known_status is None:
        known_status = ("completed" if previous.get("status") == "completed" or
                        (previous.get("diagnostics") and not old_diagnostics) else
                        previous.get("status", "error"))
    for key in ("candidates", "uncertain_hits"):
        merged[key] = ([item for item in previous.get(key, [])
                        if item.get("phase") != "known_extension"]
                       + replacement.get(key, []))
    merged["artifacts"] = ([path for path in previous.get("artifacts", [])
                             if not old_filename_item(path)] + replacement.get("artifacts", []))
    merged["diagnostics"] = old_diagnostics + replacement.get("diagnostics", [])
    merged["filename_rescan"] = replacement
    merged["extra_request_count"] = replacement.get("extra_request_count", 0)
    merged["known_basename_status"] = known_status
    if known_status not in ("completed", "not_run"):
        merged["status"] = known_status
    elif replacement.get("status") in ("completed", "not_run"):
        merged["status"] = "completed"
    else:
        merged["status"] = replacement.get("status", "error")
    return merged


def _run_one(result: dict, source_run: Path, run_dir: Path, overview: dict,
             options, progress: ProgressReporter, source_roots: list[Path]) -> dict:
    host = result["host"]
    port = result["port"]
    host_dir = _host_dir(run_dir, host)
    host_dir.mkdir(parents=True, exist_ok=False)
    result = _bundle_evidence(result, run_dir, host_dir, source_roots)
    result["reused_from"] = str(source_run)
    stages = options.rerun_stages
    result["rerun_stages"] = list(stages)
    if len(stages) == 1:
        result["rerun_only"] = stages[0]
    else:
        result.pop("rerun_only", None)
    if result.get("stages", {}).get("resolution", {}).get("status") != "completed":
        result["rerun"] = {"status": "unavailable", "stages": list(stages),
                           "diagnostics": ["source host did not resolve"]}
    else:
        stage_statuses: list[str] = []
        web_origins = 0
        if "prefixes" in stages:
            previous_dns = result.get("dns", {})
            updated_dns = _run_stage(progress, host, "dns-words", rerun_dns_words,
                                     previous_dns, host, options.host_prefixes_wordlist,
                                     host_dir / "dns")
            if "records" not in updated_dns and isinstance(previous_dns, dict):
                # A scanner start or write failure must not erase saved dig evidence.
                failure_diagnostics = updated_dns.get("diagnostics", [])
                updated_dns = deepcopy(previous_dns)
                updated_dns["candidates"] = [item for item in updated_dns.get("candidates", [])
                                             if item.get("source") != "gobuster_dns"]
                updated_dns["scanner"] = {"status": "error"}
                updated_dns["status"] = "partial"
                updated_dns.setdefault("diagnostics", []).extend(
                    ["Gobuster rerun failed", *failure_diagnostics])
            result["dns"] = updated_dns
            result.setdefault("stages", {})["dns"] = {"status": result["dns"].get("status", "error")}
            stage_statuses.append(result["dns"].get("scanner", {}).get("status", "error"))
        for label, web in result.get("web", {}).items():
            if label not in ("http", "https") or not isinstance(web, dict):
                continue
            web_origins += 1
            origin = web.get("origin") or f"{label}://{host}:{port}"
            scanner = result.setdefault("scanners", {}).setdefault(label, {})
            scan_dir = host_dir / "scanners" / label

            def scan(name, func, *args):
                stage = f"scanner:{label}:{name}"
                callback = lambda scan_name, current, total: progress.update(
                    host, stage, scan_name, current, total)
                return _run_stage(progress, host, stage, func, *args, progress=callback)

            jobs = []
            if "prefixes" in stages:
                jobs.append(("vhost", run_vhost, (origin, host,
                            options.host_prefixes_wordlist, scan_dir / "vhost")))
            if "paths" in stages:
                jobs.append(("paths", run_paths, (origin,
                            options.paths_wordlist, scan_dir / "paths")))
                if "extensions" not in stages:
                    previous_ext = scanner.get("extensions", {})
                    confirmed = previous_ext.get("confirmed_extensions", [])
                    if confirmed:
                        jobs.append(("extension-filenames", run_extension_filenames,
                                     (origin, options.paths_wordlist, confirmed,
                                      scan_dir / "extension-filenames", options.max_extra_requests)))
            if "extensions" in stages:
                paths = (options.paths_wordlist or
                         _previous_paths_wordlist(source_run, overview, result, label))
                jobs.append(("extensions", run_extensions,
                             (origin, paths, options.extensions_wordlist,
                              _observed_basenames(web), scan_dir / "extensions",
                              options.max_extra_requests)))
            scanner_results = {}
            if options.scanner_workers == 1 or len(jobs) < 2:
                for name, function, args in jobs:
                    scanner_results[name] = scan(name, function, *args)
            else:
                with ThreadPoolExecutor(max_workers=options.scanner_workers) as pool:
                    futures = {pool.submit(scan, name, function, *args): name
                               for name, function, args in jobs}
                    for future in as_completed(futures):
                        scanner_results[futures[future]] = future.result()
            for name, _, _ in jobs:
                stage = scanner_results[name]
                if name == "extension-filenames":
                    scanner["extensions"] = _merge_filenames(previous_ext, stage)
                else:
                    scanner[name] = stage
                stage_statuses.append(stage.get("status", "error"))
        rerun_status = ("unavailable" if web_origins == 0 else
                        "completed" if all(status in ("completed", "not_run")
                                           for status in stage_statuses) else "partial")
        result["rerun"] = {"status": rerun_status, "stages": list(stages)}
        if len(stages) == 1:
            result["rerun"]["stage"] = stages[0]
    result["new_hosts"] = _add_candidates(host, result, result.get("resolved_ips", []), port)
    result["status"] = _status(result)
    _prune_reused_evidence(result, host_dir)
    clean = _relative_artifacts(result, run_dir)
    (host_dir / "summary.json").write_text(
        json.dumps(clean, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def rerun_main(options) -> int:
    source_run = options.from_run.resolve()
    overview, summaries = _read_source(source_run)
    if options.host is not None:
        requested = normalize_host(options.host)
        source_hosts = [result["host"] for result in summaries]
        if source_hosts != [requested]:
            raise ValueError(f"--host must match the sole source hostname: {', '.join(source_hosts)}")
    if options.port is not None and options.port != overview["port"]:
        raise ValueError(f"--port must match the source port: {overview['port']}")
    if "extensions" in options.rerun_stages:
        for result in summaries:
            for label in result.get("web", {}):
                if label in ("http", "https") and options.paths_wordlist is None:
                    _previous_paths_wordlist(source_run, overview, result, label)
    run_dir = create_run_dir(options.out_dir)
    source_roots = _source_roots(source_run)
    print(f"Output: {run_dir}", flush=True)
    results = []
    with ProgressReporter(run_dir) as progress:
        for result in summaries:
            print(f"[{result['host']}:{result['port']}] rerun {', '.join(options.rerun_stages)}", flush=True)
            results.append(_run_one(result, source_run, run_dir, overview, options, progress,
                                    source_roots))
    wordlists = dict(overview.get("wordlists") or {})
    for name in ("host_prefixes_wordlist", "paths_wordlist", "extensions_wordlist"):
        path = getattr(options, name)
        if path is not None:
            if name == "paths_wordlist":
                if "paths" in options.rerun_stages:
                    wordlists[name] = str(path.resolve())
                wordlists["extension_names_wordlist"] = str(path.resolve())
            else:
                wordlists[name] = str(path.resolve())
    write_run_outputs(run_dir, results, overview["port"], wordlists,
                      source_run=source_run, rerun_stages=options.rerun_stages)
    print(f"Report: {run_dir / 'report.md'}", flush=True)
    print(run_dir)
    return 0 if all(item.get("rerun", {}).get("status") == "completed"
                    for item in results) else 1
