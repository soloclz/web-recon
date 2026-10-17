"""Save and display the single completed-run report."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from .result_view import render_terminal, unscanned_hosts


SCHEMA_VERSION = 2


def _summary_path(result: dict) -> Path:
    host = str(result.get("host", ""))
    slug = hashlib.sha256(host.encode("utf-8")).hexdigest()[:10]
    return Path("hosts") / f"{host[:80]}-{slug}" / "summary.json"


def load_json_report(run_dir: Path) -> dict:
    """Read a completed run; report.json is its completion marker."""
    path = Path(run_dir) / "report.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"completed run has no readable report.json: {run_dir}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported report schema in {path}; expected version {SCHEMA_VERSION}")
    overview = data.get("run")
    hosts = data.get("hosts")
    if not isinstance(overview, dict) or not isinstance(hosts, list) or not hosts:
        raise ValueError(f"report.json has no run metadata or hosts: {path}")
    if not isinstance(data.get("new_hosts"), list):
        raise ValueError(f"report.json has no new_hosts list: {path}")
    return data


def write_json_report(run_dir: Path, results: list[dict], overview: dict) -> Path:
    """Write report.json only after every host summary and raw artifact is saved."""
    run_dir = Path(run_dir).resolve()
    hosts = []
    for result in results:
        summary = json.loads((run_dir / _summary_path(result)).read_text(encoding="utf-8"))
        if summary.get("host") != result.get("host") or summary.get("port") != overview.get("port"):
            raise ValueError(f"saved host summary does not match this run: {result.get('host')}")
        summary.setdefault("action", result.get("action", "scanned"))
        hosts.append(summary)
    data = {"schema_version": SCHEMA_VERSION, "run": overview, "hosts": hosts,
            "new_hosts": unscanned_hosts(hosts)}
    output = run_dir / "report.json"
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=run_dir,
                                     prefix=".report-", suffix=".tmp", delete=False) as temporary:
        json.dump(data, temporary, indent=2, ensure_ascii=False)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    try:
        os.replace(temporary_path, output)
    finally:
        temporary_path.unlink(missing_ok=True)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show a completed web-recon report")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        data = load_json_report(args.run_dir)
    except ValueError as exc:
        parser.error(str(exc))
    print(render_terminal(data))
    print(f"Report: {args.run_dir.resolve() / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
