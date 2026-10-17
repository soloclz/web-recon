"""Add hostnames to a completed run while keeping prior evidence local."""

from __future__ import annotations

import json
from pathlib import Path

from . import cli, rerun
from .progress import ProgressReporter


_WORDLISTS = ("host_prefixes_wordlist", "paths_wordlist", "extensions_wordlist")
_WORDLIST_STAGES = {"host_prefixes_wordlist": "prefixes", "paths_wordlist": "paths",
                    "extensions_wordlist": "extensions"}


def _inherit_settings(options, overview: dict, summaries: list[dict]) -> None:
    saved = overview.get("scan_settings") or {}
    if not isinstance(saved, dict):
        raise ValueError("source run has invalid scan settings")
    web = saved.get("web")
    if web is not None:
        if not isinstance(web, dict) or any(not isinstance(web.get(name), int)
                                             for name in cli.WEB_LIMIT_NAMES):
            raise ValueError("source run has invalid Web limits")
        for name in cli.WEB_LIMIT_NAMES:
            if name not in options.explicit_limits:
                setattr(options, name, web[name])
    extra = saved.get("max_extra_requests")
    if extra is not None:
        if not isinstance(extra, int) or extra < 0:
            raise ValueError("source run has invalid extension request limit")
        if "max_extra_requests" not in options.explicit_limits:
            options.max_extra_requests = extra
    options.public_sources = bool(options.public_sources or saved.get("public_sources") or
                                  any((result.get("public_sources") or {}).get("status")
                                      not in (None, "not_run") for result in summaries))
    if (options.max_pages < 1 or options.max_depth < 0 or
            options.max_body_bytes < 1024 or options.max_requests < 4):
        raise ValueError("source run has invalid Web limits")


def _inherit_wordlists(options, overview: dict) -> tuple[dict, set[str]]:
    saved = overview.get("wordlists") or {}
    if not isinstance(saved, dict):
        raise ValueError("source run has invalid wordlist metadata")
    wordlists = dict(saved)
    explicit = set()
    for name in _WORDLISTS:
        old_value = saved.get(name)
        old_path = Path(old_value) if isinstance(old_value, str) and old_value else None
        requested = getattr(options, name)
        if requested is not None:
            explicit.add(name)
        selected = requested or old_path
        setattr(options, name, selected)
        wordlists[name] = str(selected.resolve()) if selected else None
    extension_names = saved.get("extension_names_wordlist")
    if extension_names is not None and not isinstance(extension_names, str):
        raise ValueError("source run has invalid extension filename wordlist metadata")
    if options.paths_wordlist is not None and "paths_wordlist" in explicit:
        # An explicit path dictionary also supplies names for extension guesses.
        extension_names = str(options.paths_wordlist.resolve())
    if extension_names:
        wordlists["extension_names_wordlist"] = extension_names
    options.extension_names_wordlist = Path(extension_names) if extension_names else options.paths_wordlist
    return wordlists, explicit


def _changed_stages(overview: dict, wordlists: dict,
                    hashes: dict, explicit: set[str]) -> tuple[str, ...]:
    previous = overview.get("wordlists") or {}
    previous_hashes = overview.get("wordlist_hashes") or {}
    if not isinstance(previous_hashes, dict):
        raise ValueError("source run has invalid wordlist hash metadata")
    changed = []
    for name in _WORDLISTS:
        old = previous.get(name)
        new = wordlists.get(name)
        old_hash = previous_hashes.get(name)
        if ((Path(old).resolve() if old else None) != (Path(new).resolve() if new else None)
                or (old_hash is not None and hashes.get(name) is not None
                    and hashes[name] != old_hash)
                or (old_hash is None and name in explicit and new is not None)):
            changed.append(_WORDLIST_STAGES[name])
    old_names = previous.get("extension_names_wordlist")
    new_names = wordlists.get("extension_names_wordlist")
    old_names_hash = previous_hashes.get("extension_names_wordlist")
    if (old_names and new_names and
            ((Path(old_names).resolve() != Path(new_names).resolve()) or
             (old_names_hash is not None and hashes.get("extension_names_wordlist") is not None
              and hashes["extension_names_wordlist"] != old_names_hash)) and
            "extensions" not in changed and "paths" not in changed):
        changed.append("extensions")
    return tuple(changed)


def _base_ready(result: dict, options) -> bool:
    """Decide whether saved non-wordlist checks can support targeted updates."""
    if result.get("status") not in {"completed", "partial"}:
        return False
    stages = result.get("stages") or {}
    if (stages.get("resolution", {}).get("status") != "completed" or
            stages.get("scheme", {}).get("status") != "completed"):
        return False
    dns = result.get("dns") or {}
    dns_status = dns.get("status")
    dns_words_retry = (dns_status == "partial" and not dns.get("required_failures")
                       and options.host_prefixes_wordlist is not None
                       and (dns.get("scanner") or {}).get("status") in {"error", "timeout", "partial"})
    if dns_status not in {"completed", "unavailable"} and not dns_words_retry:
        return False
    saved_web_limits = (result.get("scan_settings") or {}).get("web")
    current_web_limits = cli.scan_settings(options)["web"]
    if saved_web_limits is not None and saved_web_limits != current_web_limits:
        return False
    web = result.get("web") or {}
    if not web or any(not _web_ready(stage, allow_bounded=saved_web_limits == current_web_limits)
                      for stage in web.values()):
        return False
    if "https" in web and result.get("tls", {}).get("status") != "completed":
        return False
    scanner_results = result.get("scanners") or {}
    for scheme in web:
        scanner = scanner_results.get(scheme) or {}
        for name, wordlist in (("vhost", options.host_prefixes_wordlist),
                               ("paths", options.paths_wordlist),
                               ("extensions", options.extensions_wordlist)):
            status = (scanner.get(name) or {}).get("status")
            if wordlist is None and status not in {"completed", "not_run"}:
                return False
    return True


def _web_ready(stage: dict, *, allow_bounded: bool) -> bool:
    for name in ("baseline", "fixed", "pages", "scripts", "source_maps"):
        if any(isinstance(item, dict) and (item.get("exit_code") or item.get("truncated"))
               for item in stage.get(name, [])):
            return False
    if stage.get("status") == "completed":
        return True
    if stage.get("status") != "partial" or not allow_bounded:
        return False
    bounded = {"crawl_limit", "script_limit", "sitemap_limit", "request_limit"}
    reasons = stage.get("partial_reasons")
    return isinstance(reasons, list) and bool(reasons) and set(reasons) <= bounded


def _failed_wordlist_stages(result: dict, options) -> set[str]:
    failed = set()
    dns = result.get("dns") or {}
    if (options.host_prefixes_wordlist is not None and dns.get("status") != "unavailable"
            and (dns.get("scanner") or {}).get("status") != "completed"):
        failed.add("prefixes")
    for scanner in (result.get("scanners") or {}).values():
        for stage, name, wordlist in (("prefixes", "vhost", options.host_prefixes_wordlist),
                                      ("paths", "paths", options.paths_wordlist),
                                      ("extensions", "extensions", options.extensions_wordlist)):
            if wordlist is not None and (scanner.get(name) or {}).get("status") != "completed":
                failed.add(stage)
    return failed


def _prefix_components(result: dict, options, changed_stages: tuple[str, ...],
                       pending: tuple[str, ...] = ()) -> tuple[bool, bool]:
    if options.host_prefixes_wordlist is None:
        return False, False
    changed = "prefixes" in changed_stages
    dns = result.get("dns") or {}
    dns_retry = (dns.get("status") != "unavailable" and
                 (changed or "dns_words" in pending or
                  (dns.get("scanner") or {}).get("status") != "completed"))
    vhost_retry = (changed or "vhost" in pending or
                   any((scanner.get("vhost") or {}).get("status") != "completed"
                       for scanner in (result.get("scanners") or {}).values()))
    return dns_retry, vhost_retry


def _reuse_result(result: dict, source_run: Path, run_dir: Path,
                  source_roots: list[Path]) -> dict:
    host_dir = rerun._host_dir(run_dir, result["host"])
    host_dir.mkdir(parents=True, exist_ok=False)
    reused = rerun._bundle_evidence(result, run_dir, host_dir, source_roots)
    reused["action"] = "reused"
    reused["extended_from"] = str(source_run)
    clean = cli._relative_artifacts(reused, run_dir)
    (host_dir / "summary.json").write_text(
        json.dumps(clean, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return reused


def _replacement_ready(result: dict, options) -> bool:
    if not _base_ready(result, options) or _failed_wordlist_stages(result, options):
        return False
    public_status = (result.get("public_sources") or {}).get("status")
    return not options.public_sources or public_status in {"completed", "unavailable"}


def _keep_failed_attempt(previous: dict, attempt: dict, source_run: Path,
                         run_dir: Path, source_roots: list[Path], *,
                         stages: tuple[str, ...] = (), full_scan: bool = False,
                         prefix_components: tuple[str, ...] = ()) -> dict:
    """Preserve a usable prior result and keep the unsuccessful retry as evidence."""
    host = previous["host"]
    host_dir = rerun._host_dir(run_dir, host)
    temporary = run_dir / "attempts" / host_dir.name
    temporary.parent.mkdir(exist_ok=True)
    host_dir.rename(temporary)
    kept = _reuse_result(previous, source_run, run_dir, source_roots)
    attempt_dir = host_dir / "attempts" / "latest"
    attempt_dir.parent.mkdir(exist_ok=True)
    temporary.rename(attempt_dir)

    def relocate(value, key: str = ""):
        if isinstance(value, dict):
            return {name: relocate(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [relocate(item, "artifact" if key == "artifacts" else "") for item in value]
        if isinstance(value, str) and key in rerun._EVIDENCE_KEYS:
            path = Path(value)
            if path.is_absolute() and path.is_relative_to(host_dir):
                return str(attempt_dir / path.relative_to(host_dir))
        return value

    attempt = relocate(attempt)
    (attempt_dir / "summary.json").write_text(
        json.dumps(cli._relative_artifacts(attempt, attempt_dir), indent=2,
                   ensure_ascii=False) + "\n", encoding="utf-8")
    kept["action"] = "retry_failed"
    kept["retry"] = {"status": attempt.get("rerun", {}).get("status", attempt.get("status")),
                     "summary": str(attempt_dir / "summary.json"),
                     "artifacts": [str(path) for path in sorted(attempt_dir.rglob("*"))
                                   if path.is_file()],
                     "stages": list(stages), "full_scan": full_scan,
                     "prefix_components": list(prefix_components)}
    rerun._prune_reused_evidence(kept, host_dir)
    (host_dir / "summary.json").write_text(
        json.dumps(cli._relative_artifacts(kept, run_dir), indent=2,
                   ensure_ascii=False) + "\n", encoding="utf-8")
    return kept


def extend_main(options) -> int:
    source_run = options.extend_run.resolve()
    overview, summaries = rerun._read_source(source_run)
    _inherit_settings(options, overview, summaries)
    port = overview["port"]
    if options.port is not None and options.port != port:
        raise ValueError(f"--port must match the source port: {port}")
    options.port = port
    requested = cli.read_hosts(options.host, options.hosts_file)
    wordlists, explicit = _inherit_wordlists(options, overview)
    current_hashes = cli.hash_wordlists(wordlists)
    changed_stages = _changed_stages(overview, wordlists, current_hashes, explicit)
    previous_hashes = overview.get("wordlist_hashes") or {}
    if not isinstance(previous_hashes, dict):
        raise ValueError("source run has invalid wordlist hash metadata")
    wordlist_hashes = {name: previous_hashes.get(name) for name in wordlists}
    for name, stage in _WORDLIST_STAGES.items():
        if stage in changed_stages:
            wordlist_hashes[name] = current_hashes[name]
    if "paths" in changed_stages:
        wordlists["extension_names_wordlist"] = wordlists["paths_wordlist"]
        wordlist_hashes["extension_names_wordlist"] = current_hashes["paths_wordlist"]
        options.extension_names_wordlist = options.paths_wordlist
    elif "extensions" in changed_stages and "extension_names_wordlist" in wordlists:
        wordlist_hashes["extension_names_wordlist"] = current_hashes["extension_names_wordlist"]
    source_results = {result["host"]: result for result in summaries}
    new_hosts = [host for host in requested if host not in source_results]
    plans = {}
    for result in summaries:
        host = result["host"]
        retry = result.get("retry") or {}
        if retry.get("full_scan") or not _base_ready(result, options):
            plans[host] = ("scan", ())
        else:
            needed = set(changed_stages) | _failed_wordlist_stages(result, options)
            needed.update(stage for stage in retry.get("stages", ())
                          if stage in (*_WORDLIST_STAGES.values(), "public"))
            saved_extra = (result.get("scan_settings") or {}).get("max_extra_requests")
            if (saved_extra is not None and saved_extra != options.max_extra_requests and
                    options.extensions_wordlist is not None):
                needed.add("extensions")
            public_status = (result.get("public_sources") or {}).get("status")
            if options.public_sources and public_status not in {"completed", "unavailable"}:
                needed.add("public")
            stages = tuple(stage for stage in (*_WORDLIST_STAGES.values(), "public") if stage in needed)
            plans[host] = ("update", stages) if stages else ("reuse", ())
    full_scan = bool(new_hosts or any(action == "scan" for action, _ in plans.values()))
    required_wordlists = set(_WORDLISTS) if full_scan else set()
    if full_scan and options.extension_names_wordlist is not None:
        required_wordlists.add("extension_names_wordlist")
    for action, stages in plans.values():
        if action != "update":
            continue
        required_wordlists.update(name for name, stage in _WORDLIST_STAGES.items() if stage in stages)
        if "extensions" in stages:
            required_wordlists.add("extension_names_wordlist")
    for name in required_wordlists:
        path = getattr(options, name, None)
        if path is not None and not path.is_file():
            raise ValueError(f"--{name.replace('_', '-')} is unavailable: {path}")

    run_dir = cli.create_run_dir(options.out_dir)
    options.completed_run_dir = run_dir
    source_roots = rerun._source_roots(source_run)
    order = [result["host"] for result in summaries] + new_hosts
    print(f"Output: {run_dir}", flush=True)
    results = []
    with ProgressReporter(run_dir) as progress:
        for host in order:
            action, stages = plans.get(host, ("scan", ()))
            if action == "reuse":
                print(f"[{host}:{port}] reused", flush=True)
                results.append(_reuse_result(source_results[host], source_run, run_dir, source_roots))
            elif action == "update":
                print(f"[{host}:{port}] updating {', '.join(stages)}", flush=True)
                options.rerun_stages = stages
                pending = (source_results[host].get("retry") or {}).get("prefix_components") or ()
                options.rerun_dns_words, options.rerun_vhost = _prefix_components(
                    source_results[host], options, changed_stages, tuple(pending))
                updated = rerun._run_one(source_results[host], source_run, run_dir,
                                         overview, options, progress, source_roots)
                updated["action"] = "updated"
                updated["extended_from"] = str(source_run)
                host_dir = rerun._host_dir(run_dir, host)
                (host_dir / "summary.json").write_text(
                    json.dumps(cli._relative_artifacts(updated, run_dir), indent=2,
                               ensure_ascii=False) + "\n", encoding="utf-8")
                if updated.get("rerun", {}).get("status") == "completed":
                    updated.pop("retry", None)
                    rerun._prune_reused_evidence(updated, host_dir)
                    (host_dir / "summary.json").write_text(
                        json.dumps(cli._relative_artifacts(updated, run_dir), indent=2,
                                   ensure_ascii=False) + "\n", encoding="utf-8")
                    results.append(updated)
                else:
                    results.append(_keep_failed_attempt(source_results[host], updated,
                                                        source_run, run_dir, source_roots,
                                                        stages=stages,
                                                        prefix_components=tuple(
                                                            name for name, enabled in (
                                                                ("dns_words", options.rerun_dns_words),
                                                                ("vhost", options.rerun_vhost))
                                                            if enabled and "prefixes" in stages)))
            else:
                print(f"[{host}:{port}] scanning", flush=True)
                scanned = cli.run_host(host, port, run_dir, options, progress)
                if host in source_results and not _replacement_ready(scanned, options):
                    results.append(_keep_failed_attempt(source_results[host], scanned,
                                                        source_run, run_dir, source_roots,
                                                        full_scan=True))
                else:
                    results.append(scanned)
    cli.write_run_outputs(run_dir, results, port, wordlists,
                          wordlist_hashes=wordlist_hashes, settings=cli.scan_settings(options),
                          extended_from=source_run)
    cli.print_run_summary(run_dir)
    print(run_dir)
    def successful(result: dict) -> bool:
        action = result.get("action")
        if action == "reused":
            return True
        if action == "retry_failed":
            return False
        if action == "updated":
            return result.get("rerun", {}).get("status") == "completed"
        return result["status"] == "completed"

    return 0 if all(successful(result) for result in results) else 1
