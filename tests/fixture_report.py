"""Build completed-run fixtures in the canonical report format."""

from __future__ import annotations

import json
from pathlib import Path


def load_report(run_dir: Path) -> dict:
    return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


def fixture_overview(run_dir: Path) -> dict:
    """Expose run metadata and host entries while editing older fixture cases."""
    data = load_report(run_dir)
    return {**data["run"], "hosts": data["hosts"]}


def save_fixture_report(run_dir: Path, overview: dict) -> None:
    """Save metadata and the selected host summaries as one completed report."""
    saved = {}
    for path in (run_dir / "hosts").glob("*/summary.json"):
        summary = json.loads(path.read_text(encoding="utf-8"))
        saved[summary["host"]] = summary
    entries = overview.get("hosts", [])
    hosts = [saved.get(entry.get("host"), entry) if isinstance(entry, dict) else entry
             for entry in entries]
    run = {key: value for key, value in overview.items() if key != "hosts"}
    (run_dir / "report.json").write_text(json.dumps({
        "schema_version": 2, "run": run, "hosts": hosts, "new_hosts": []
    }), encoding="utf-8")


def refresh_fixture_hosts(run_dir: Path) -> None:
    save_fixture_report(run_dir, fixture_overview(run_dir))
