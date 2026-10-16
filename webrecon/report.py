"""One readable entry point for a web-recon run.

The report points to saved evidence. It never upgrades a candidate to a finding.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path
from urllib.parse import quote

MAX_ROWS = 30


def _text(value: object) -> str:
    """Escape untrusted scanner and HTTP text in Markdown, including tables."""
    escaped = html.escape(str(value), quote=False)
    for character, entity in (("|", "&#124;"), ("[", "&#91;"), ("]", "&#93;"),
                              ("`", "&#96;"), ("*", "&#42;")):
        escaped = escaped.replace(character, entity)
    return escaped.replace("\r", " ").replace("\n", " ")


def _source_root(run_dir: Path, result: dict, source_run: Path | None) -> Path:
    # A caller combining hosts from several runs can set this per result.
    override = result.get("_source_run")
    return Path(override or source_run or run_dir).resolve()


def _link(run_dir: Path, path: str | Path | None, label: str, source_root: Path) -> str:
    if not path:
        return ""
    target = Path(path)
    if not target.is_absolute():
        target = source_root / target
    target = target.resolve()
    relative = os.path.relpath(target, run_dir)
    href = quote(Path(relative).as_posix(), safe="/.-_~")
    return f"[{_text(label)}]({href})"


def _summary_path(result: dict) -> Path:
    host = str(result.get("host", ""))
    slug = hashlib.sha256(host.encode("utf-8")).hexdigest()[:10]
    return Path("hosts") / f"{host[:80]}-{slug}" / "summary.json"


def _artifact(run_dir: Path, stage: dict, source_root: Path) -> str:
    if isinstance(stage.get("stdout"), str):
        return _link(run_dir, stage["stdout"], "raw", source_root)
    queries = stage.get("queries", [])
    if isinstance(queries, list):
        query_output = next((query.get("stdout") for query in queries
                             if isinstance(query, dict) and query.get("stdout")), None)
        if query_output:
            return _link(run_dir, query_output, "raw", source_root)
    paths = stage.get("artifacts", [])
    if not isinstance(paths, list):
        paths = []
    preferred = next((path for path in paths if isinstance(path, str)
                      and path.endswith(".json") and "control" not in Path(path).name
                      and not path.endswith(".status.json")), None)
    path = preferred or next((path for path in paths if isinstance(path, str)), None)
    return _link(run_dir, path, "raw", source_root)


def _stage_rows(result: dict) -> list[tuple[str, dict]]:
    stages = result.get("stages", {}) or {}
    rows = [("resolution", stages.get("resolution", {})),
            ("scheme", stages.get("scheme", {})),
            ("TLS certificate", result.get("tls", {})),
            ("DNS", result.get("dns", {}))]
    dns_scanner = (result.get("dns", {}) or {}).get("scanner", {})
    if dns_scanner:
        rows.append(("DNS wordlist", dns_scanner))
    for scheme, web in (result.get("web", {}) or {}).items():
        rows.append((f"Web {scheme}", web))
    for scheme, scans in (result.get("scanners", {}) or {}).items():
        for name in ("vhost", "paths", "extensions"):
            rows.append((f"{name} {scheme}", (scans or {}).get(name, {})))
        filename_rescan = (scans or {}).get("extensions", {}).get("filename_rescan")
        if isinstance(filename_rescan, dict):
            rows.append((f"extension filenames {scheme}", filename_rescan))
    rows.append(("public sources", result.get("public_sources", {})))
    return rows


def _short_diagnostics(stage: dict) -> str:
    values = stage.get("diagnostics", []) if isinstance(stage, dict) else []
    if not isinstance(values, list):
        return ""
    items = [_text(str(item)[:200]) for item in values[:2]]
    if len(values) > 2:
        items.append(f"+{len(values) - 2} more")
    return "; ".join(items)


def _table(lines: list[str], headers: tuple[str, ...], rows: list[tuple[str, ...]],
           *, total: int | None = None, summary: str = "") -> None:
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows[:MAX_ROWS]:
        lines.append("| " + " | ".join(row) + " |")
    if total is not None and total > MAX_ROWS:
        lines.append("")
        lines.append(f"Showing {MAX_ROWS} of {total}; full data: {summary}.")
    lines.append("")


def _response_link(run_dir: Path, prefix: str | None, source_root: Path) -> str:
    return _link(run_dir, f"{prefix}.body" if prefix else None, "body", source_root)


def _scanner_candidates(lines: list[str], run_dir: Path, result: dict,
                        source_root: Path, summary: str) -> None:
    for scheme, scans in (result.get("scanners", {}) or {}).items():
        grouped: dict[str, dict[str, set[str]]] = {}
        stage_counts = []
        uncertain_total = 0
        for name in ("vhost", "paths", "extensions"):
            stage = (scans or {}).get(name, {}) or {}
            candidates = stage.get("candidates", []) or []
            uncertain = stage.get("uncertain_hits", []) or []
            uncertain_total += len(uncertain)
            if candidates or uncertain:
                stage_counts.append(f"{name} {len(candidates)}")
            evidence = summary if name == "extensions" else (_artifact(run_dir, stage, source_root) or summary)
            for candidate in candidates:
                target = candidate.get("hostname") or candidate.get("url")
                if not isinstance(target, str) or not target:
                    continue
                item = grouped.setdefault(target, {"http": set(), "source": set(),
                                                   "assessment": set(), "evidence": set()})
                if candidate.get("status_code") is not None:
                    item["http"].add(str(candidate["status_code"]))
                item["source"].add(str(candidate.get("source") or name))
                item["assessment"].add(str(candidate.get("assessment") or ""))
                item["evidence"].add(evidence)
        if not grouped and not uncertain_total:
            continue
        lines.append(f"#### {_text(scheme)} scanner candidates")
        lines.append("")
        lines.append(f"Stage hits: {_text(', '.join(stage_counts))}; "
                     f"unique candidates: {len(grouped)}; uncertain hits: {uncertain_total}.")
        lines.append("")
        if grouped:
            rows = [(_text(target), _text(", ".join(sorted(item["http"]))),
                     _text(", ".join(sorted(item["source"]))),
                     _text(", ".join(sorted(item["assessment"]))),
                     ", ".join(sorted(item["evidence"])))
                    for target, item in sorted(grouped.items())]
            _table(lines, ("Target", "HTTP", "Source", "Assessment", "Evidence"), rows,
                   total=len(rows), summary=summary)


def _web_candidates(lines: list[str], run_dir: Path, result: dict,
                    source_root: Path, summary: str) -> None:
    for scheme, web in (result.get("web", {}) or {}).items():
        lines.append(f"#### {_text(scheme)} Web")
        lines.append("")
        fixed = [item for item in web.get("fixed", [])
                 if item.get("assessment") == "candidate"]
        maps = [item for item in web.get("source_maps", [])
                if item.get("assessment") == "candidate"]
        pages = web.get("pages", []) or []
        urls = web.get("candidate_urls", []) or []
        lines.append(f"Fixed-path candidates: {len(fixed)}; source maps: {len(maps)}; "
                     f"pages crawled: {len(pages)}; URLs collected: {len(urls)}.")
        lines.append("")
        if fixed or maps:
            rows = []
            for source, item in [("fixed_path", item) for item in fixed] + [("source_map", item) for item in maps]:
                rows.append((_text(item.get("url", "")), _text(item.get("status", "")),
                             _text(source),
                             _text(item.get("assessment", "")),
                             _response_link(run_dir, item.get("prefix"), source_root)))
            _table(lines, ("URL", "HTTP", "Source", "Assessment", "Response"), rows,
                   total=len(rows), summary=summary)
        clues = [page for page in pages
                 if page.get("forms") or page.get("fields") or page.get("comments")]
        if clues:
            lines.append("Pages with forms, fields, or comments:")
            lines.append("")
            rows = [(_text(page.get("url", "")), _text(page.get("title", "")),
                     str(len(page.get("forms", []))), str(len(page.get("fields", []))),
                     str(len(page.get("comments", []))),
                     _response_link(run_dir, page.get("prefix"), source_root))
                    for page in clues]
            _table(lines, ("URL", "Title", "Forms", "Fields", "Comments", "Response"),
                   rows, total=len(rows), summary=summary)
        if urls:
            lines.append("Collected URLs (not all were requested):")
            lines.append("")
            rows = [(_text(item.get("url", "")), _text(item.get("source", "")))
                    for item in urls]
            _table(lines, ("URL", "Source"), rows, total=len(rows), summary=summary)


def write_report(run_dir: Path, results: list[dict], source_run: Path | None = None) -> Path:
    """Write and return ``report.md`` for this run.

    ``results`` use the dictionaries returned by ``run_host`` or saved in each
    ``summary.json``. With ``source_run``, relative evidence paths refer to an
    earlier run, which is useful for a rerun report that reuses saved results.
    """
    run_dir = Path(run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = ["# Web recon report", "",
             "Candidates below differ from missing-path or default-vhost controls, or came from named sources. Review the linked evidence before using them.", "",
             "## Hosts", ""]
    rerun = next((result for result in results if result.get("reused_from")), None)
    if rerun:
        stages = rerun.get("rerun_stages") or ([rerun["rerun_only"]] if rerun.get("rerun_only") else [])
        lines[2:2] = [f"Rerun stages: **{_text(', '.join(stages))}**. "
                      f"Referenced reused evidence is included in this run. Source: {_text(rerun['reused_from'])}.", ""]
    overview = []
    for result in results:
        source_root = _source_root(run_dir, result, source_run)
        summary = _link(run_dir, _summary_path(result), "summary.json", source_root)
        origins = ", ".join(_text(web.get("origin", scheme))
                            for scheme, web in (result.get("web", {}) or {}).items()) or "—"
        overview.append((_text(result.get("host", "")), _text(result.get("port", "")),
                         _text(result.get("status", "")), origins,
                         str(len(result.get("new_hosts", []) or [])), summary))
    run_index = _link(run_dir, "run.json", "run.json", run_dir)
    _table(lines, ("Host", "Port", "Status", "Origins", "New hosts", "Details"), overview,
           total=len(overview), summary=run_index)

    for result in results:
        source_root = _source_root(run_dir, result, source_run)
        host = _text(result.get("host", ""))
        port = _text(result.get("port", ""))
        summary = _link(run_dir, _summary_path(result), "summary.json", source_root)
        requests_label = "Reused Web crawl requests" if result.get("reused_from") else "Saved Web requests"
        lines += [f"## {host}:{port}", "", f"Status: **{_text(result.get('status', 'unknown'))}**. "
                  f"Resolved IPs: {_text(', '.join(result.get('resolved_ips', []) or []) or 'none')}. "
                  f"{requests_label}: {_text(result.get('request_count', 0))}. Full data: {summary}.", ""]
        if result.get("rerun"):
            lines += [f"Rerun status: **{_text(result['rerun'].get('status', 'unknown'))}**.", ""]
        lines += ["### Stage status", ""]
        rows = []
        for name, stage in _stage_rows(result):
            if not isinstance(stage, dict):
                stage = {}
            rows.append((_text(name), _text(stage.get("status", "not_run")),
                         _short_diagnostics(stage), _artifact(run_dir, stage, source_root)))
        _table(lines, ("Stage", "Status", "Diagnostics", "Raw output"), rows)

        new_hosts = result.get("new_hosts", []) or []
        lines += ["### New hostnames", ""]
        if new_hosts:
            rows = [(_text(item.get("name", "")),
                     _text(", ".join(item.get("sources", []) or [])),
                     _text(", ".join(item.get("source_ip_port", []) or [])))
                    for item in new_hosts]
            _table(lines, ("Name", "Sources", "Starting IP:port"), rows,
                   total=len(rows), summary=summary)
        else:
            lines += ["None recorded.", ""]

        records = (result.get("dns", {}) or {}).get("records", {}) or {}
        populated = [(kind, value) for kind, value in records.items() if value]
        if populated:
            lines += ["### DNS records", ""]
            rows = [(_text(kind), _text(", ".join(map(str, value[:10]))),
                     "" if len(value) <= 10 else f"+{len(value) - 10} in {summary}")
                    for kind, value in populated]
            _table(lines, ("Type", "Values", "More"), rows,
                   total=len(rows), summary=summary)

        lines += ["### Web and scanner candidates", ""]
        if not result.get("web") and not result.get("scanners"):
            lines += ["No Web or scanner results recorded.", ""]
        _web_candidates(lines, run_dir, result, source_root, summary)
        _scanner_candidates(lines, run_dir, result, source_root, summary)

        public = result.get("public_sources", {}) or {}
        public_candidates = public.get("candidates", []) or []
        if public_candidates:
            lines += ["### Public-source candidates", ""]
            rows = [(_text(item.get("name") or item.get("url") or ""),
                     _text(item.get("source", "")), _text(item.get("kind", "")))
                    for item in public_candidates]
            _table(lines, ("Candidate", "Source", "Kind"), rows,
                   total=len(rows), summary=summary)

    report = run_dir / "report.md"
    report.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return report


def report_existing_run(run_dir: Path) -> Path:
    """Create a readable report from saved output without making requests."""
    run_dir = Path(run_dir).resolve()
    overview = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    hosts = overview.get("hosts", [])
    if not isinstance(hosts, list):
        raise ValueError("run.json has no hosts list")
    results = []
    for entry in hosts:
        if not isinstance(entry, dict) or not isinstance(entry.get("host"), str):
            raise ValueError("run.json contains an invalid host entry")
        summary_path = run_dir / _summary_path(entry)
        results.append(json.loads(summary_path.read_text(encoding="utf-8")))
    return write_report(run_dir, results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate report.md from an existing web-recon run")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        report = report_existing_run(args.run_dir)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
