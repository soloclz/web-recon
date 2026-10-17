"""Build a compact terminal view from the completed JSON report."""
from __future__ import annotations

from .extract import INVENTORY_CATEGORIES, empty_inventory

INVENTORY_KEYS = INVENTORY_CATEGORIES


def unscanned_hosts(hosts: list[dict]) -> list[dict]:
    """Merge discovered hostnames that were not input hosts in this run."""
    input_hosts = {item.get("host") for item in hosts}
    merged: dict[str, dict] = {}
    for host in hosts:
        for item in host.get("new_hosts", []) or []:
            name = item.get("name") if isinstance(item, dict) else None
            if not isinstance(name, str) or name in input_hosts:
                continue
            entry = merged.setdefault(name, {"name": name, "observations": []})
            observation = {"input_host": host.get("host"),
                           "sources": item.get("sources", []),
                           "source_ip_port": item.get("source_ip_port", [])}
            if item.get("dns_addresses"):
                observation["dns_addresses"] = item["dns_addresses"]
            if observation not in entry["observations"]:
                entry["observations"].append(observation)
    return [merged[name] for name in sorted(merged)]


def _safe(value: object, limit: int = 150) -> str:
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in str(value)).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _brief_items(lines: list[str], label: str, items: list, *, limit: int = 5,
                 key: str = "value") -> None:
    if not items:
        return
    values = [item.get(key, "") if isinstance(item, dict) else item for item in items]
    for value in values[:limit]:
        lines.append(f"    {label}: {_safe(value)}")
    if len(values) > limit:
        lines.append(f"    {label}: +{len(values) - limit} more in report.json")


def _stage_issue(lines: list[str], label: str, stage: dict) -> None:
    status = stage.get("status")
    if status in ("error", "unavailable", "partial", "timeout", "interrupted"):
        lines.append(f"  {label}: {_safe(status, 30)}")
        _brief_items(lines, label, stage.get("diagnostics", []) or [], limit=1)


def render_terminal(report: dict) -> str:
    """Show what was fetched and the next useful clues without dumping raw evidence."""
    hosts = report.get("hosts", []) or []
    overview = report.get("run", {}) or {}
    lines = [f"Run: {len(hosts)} hosts on port {overview.get('port', '?')}"]
    for host in hosts:
        name = _safe(host.get("host", "?"), 255)
        status = _safe(host.get("status", "?"), 30)
        action = host.get("action")
        lines.append(f"\n{name} [{status}{'; ' + _safe(action, 30) if action else ''}]")
        resolution = (host.get("stages") or {}).get("resolution") or {}
        if resolution.get("status") == "error":
            _brief_items(lines, "resolution", resolution.get("diagnostics", []), limit=2)
            continue
        for scheme, web in (host.get("web") or {}).items():
            pages = web.get("pages", []) or []
            inventory = web.get("inventory") or empty_inventory()
            counts = ", ".join(f"{key} {len(inventory.get(key, []))}" for key in INVENTORY_KEYS
                               if inventory.get(key)) or "no extracted items"
            page_label = "page" if len(pages) == 1 else "pages"
            lines.append(f"  {scheme}: {_safe(web.get('status', '?'), 30)}; "
                         f"{len(pages)} {page_label}; {counts}")
            for page in pages[:5]:
                lines.append(f"    page: HTTP {page.get('status', '?')} {_safe(page.get('url', ''))}")
            if len(pages) > 5:
                lines.append(f"    page: +{len(pages) - 5} more in report.json")
            _brief_items(lines, "email", inventory.get("emails", []))
            _brief_items(lines, "comment", inventory.get("comments", []), limit=3)
            fixed = [item for item in web.get("fixed", []) or []
                     if item.get("assessment") == "candidate"]
            if fixed:
                lines.append(f"  fixed paths: {len(fixed)} candidates")
                _brief_items(lines, "fixed path", fixed, limit=3, key="url")
            maps = [item for item in web.get("source_maps", []) or []
                    if item.get("assessment") == "candidate"]
            if maps:
                lines.append(f"  source maps: {len(maps)} candidates")
                _brief_items(lines, "source map", maps, limit=3, key="url")
            clues = [item for item in web.get("candidate_urls", []) or []
                     if str(item.get("source", "")).startswith(("robots_", "sitemap"))]
            for clue in clues[:5]:
                lines.append(f"    {_safe(clue.get('source', 'url'), 40)}: {_safe(clue.get('url', ''))}")
            if len(clues) > 5:
                lines.append(f"    robots/sitemap: +{len(clues) - 5} more in report.json")
            if web.get("partial_reasons"):
                lines.append(f"    limits: {_safe(', '.join(web['partial_reasons']))}")
            _brief_items(lines, "web diagnostic", web.get("diagnostics", []) or [], limit=1)
            scans = (host.get("scanners") or {}).get(scheme) or {}
            for scan_name in ("vhost", "paths", "extensions"):
                scan = scans.get(scan_name) or {}
                _stage_issue(lines, scan_name, scan)
                candidates = scan.get("candidates", []) or []
                if candidates:
                    lines.append(f"  {scan_name}: {len(candidates)} candidates")
                    _brief_items(lines, scan_name, candidates, limit=3,
                                 key="hostname" if scan_name == "vhost" else "url")
        _brief_items(lines, "host candidate", host.get("new_hosts", []), key="name")
        _stage_issue(lines, "scheme", (host.get("stages") or {}).get("scheme") or {})
        for label in ("dns", "tls", "public_sources"):
            _stage_issue(lines, label, host.get(label) or {})
    pending = report.get("new_hosts", []) or []
    if pending:
        lines.append(f"\nUnscanned host candidates: {len(pending)}")
        _brief_items(lines, "host", pending, key="name")
    lines.append("\nFull data: report.json")
    return "\n".join(lines)
