"""Exercise the installed ffuf against a local Web fixture."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import mkdtemp
from threading import Thread
import json
import re
import sys
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon.cli import main
from webrecon.fuzz import run_extensions, run_paths, run_vhost
from webrecon.report import report_existing_run


class Site(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        host = self.headers.get("Host", "").split(":", 1)[0]
        if host == "admin.localhost":
            body = b"ADMIN VHOST UNIQUE PAGE"
        elif route == "/":
            body = b"HOME PAGE"
        elif route == "/admin":
            body = b"ADMIN PATH UNIQUE PAGE"
        elif route == "/index.php":
            body = b"INDEX PHP UNIQUE PAGE"
        elif route == "/admin.php":
            body = b"ADMIN PHP UNIQUE PAGE"
        elif route.endswith(".php"):
            body = b"GENERIC PHP FALLBACK"
        else:
            body = b"GENERIC SPA FALLBACK"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


root = Path(mkdtemp(prefix="web-recon-scanners-"))
prefixes = root / "prefixes.txt"
paths = root / "paths.txt"
extensions = root / "extensions.txt"
prefixes.write_text("admin\nabsent\n")
paths.write_text("admin\nabsent\n")
extensions.write_text("php\ntxt\n")
server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
Thread(target=server.serve_forever, daemon=True).start()
try:
    origin = f"http://127.0.0.1:{server.server_port}"
    scan_progress = []

    def record_progress(name, current, total):
        scan_progress.append((name, current, total))

    vhost = run_vhost(origin, "localhost", prefixes, root / "vhost", progress=record_progress)
    path_scan = run_paths(origin, paths, root / "paths", progress=record_progress)
    ext_scan = run_extensions(origin, paths, extensions, ["index"], root / "extensions", 2,
                              progress=record_progress)
    cli_out = root / "cli"
    cli_exit = main(["--host", "localhost", "--port", str(server.server_port),
                     "--host-prefixes-wordlist", str(prefixes),
                     "--paths-wordlist", str(paths),
                     "--extensions-wordlist", str(extensions),
                     "--scanner-workers", "2", "--max-extra-requests", "2",
                     "--ffuf-rate", "7",
                     "--max-pages", "5", "--max-requests", "100",
                     "--out-dir", str(cli_out)])
    cli_summary = json.loads(next(cli_out.glob("hosts/*/summary.json")).read_text())
    cli_scanners = cli_summary["scanners"]["http"]
    path_status = next((cli_out / "hosts").glob("*/scanners/http/paths/paths.status.json"))
    path_argv = json.loads(path_status.read_text())["argv"]
    assert path_argv[path_argv.index("-rate") + 1] == "7"
    assert all(not Path(path).is_absolute() for path in cli_scanners["paths"]["artifacts"])
    cli_events = [json.loads(line) for line in (cli_out / "progress.jsonl").read_text().splitlines()]
    rerun_outputs = {}
    for stage, flag, wordlist in (
        ("prefixes", "--host-prefixes-wordlist", prefixes),
        ("paths", "--paths-wordlist", paths),
        ("extensions", "--extensions-wordlist", extensions),
    ):
        out = root / f"rerun-{stage}"
        code = main(["--from-run", str(cli_out),
                     flag, str(wordlist), "--max-extra-requests", "2",
                     "--out-dir", str(out)])
        summary = json.loads(next(out.glob("hosts/*/summary.json")).read_text())
        rerun_outputs[stage] = {"exit_code": code, "status": summary["status"],
                                "rerun_status": summary["rerun"]["status"],
                                "report": str(out / "report.md")}
        if stage in ("paths", "extensions"):
            assert code == 0 and summary["rerun"]["status"] == "completed"
        assert (out / "report.md").is_file()
        assert not next(out.glob("hosts/*/responses"), None)
        if stage == "paths":
            assert summary["scanners"]["http"]["extensions"]["filename_rescan"]["status"] == "completed"
            assert summary["scanners"]["http"]["extensions"]["known_basename_status"] == "completed"
        if stage == "extensions":
            assert ".php" in summary["scanners"]["http"]["extensions"]["confirmed_extensions"]
        if stage == "prefixes":
            assert any(x["hostname"] == "admin.localhost" for x in summary["scanners"]["http"]["vhost"]["candidates"])
    combined_out = root / "rerun-paths-extensions"
    combined_code = main(["--from-run", str(cli_out),
                          "--paths-wordlist", str(paths),
                          "--extensions-wordlist", str(extensions),
                          "--scanner-workers", "2", "--max-extra-requests", "2",
                          "--out-dir", str(combined_out)])
    combined_summary = json.loads(next(combined_out.glob("hosts/*/summary.json")).read_text())
    assert combined_code == 0 and combined_summary["rerun"]["status"] == "completed"
    assert combined_summary["rerun"]["stages"] == ["paths", "extensions"]
    assert "filename_rescan" not in combined_summary["scanners"]["http"]["extensions"]
    assert (combined_out / "report.md").is_file()
    hidden_source = root / "cli-hidden"
    cli_out.rename(hidden_source)
    try:
        report_existing_run(combined_out)
        for href in re.findall(r"\]\(([^)]+)\)", (combined_out / "report.md").read_text()):
            target = (combined_out / unquote(href)).resolve()
            assert target.is_relative_to(combined_out.resolve()), href
            assert target.is_file(), href
    finally:
        hidden_source.rename(cli_out)
    rerun_outputs["paths+extensions"] = {
        "exit_code": combined_code, "status": combined_summary["status"],
        "rerun_status": combined_summary["rerun"]["status"],
        "report": str(combined_out / "report.md")}
    evidence = {
        "fixture_port": server.server_port,
        "vhost": {"status": vhost["status"], "candidates": vhost["candidates"],
                  "uncertain_hits": vhost["uncertain_hits"], "diagnostics": vhost["diagnostics"]},
        "paths": {"status": path_scan["status"], "candidates": path_scan["candidates"],
                  "uncertain_hits": path_scan["uncertain_hits"], "diagnostics": path_scan["diagnostics"]},
        "extensions": {"status": ext_scan["status"], "candidates": ext_scan["candidates"],
                       "confirmed_extensions": ext_scan["confirmed_extensions"],
                       "extra_request_count": ext_scan["extra_request_count"],
                       "diagnostics": ext_scan["diagnostics"]},
        "progress": {name: [current, total] for name, current, total in scan_progress},
        "cli": {"exit_code": cli_exit, "status": cli_summary["status"],
                "scanner_status": {name: stage["status"] for name, stage in cli_scanners.items()},
                "progress_events": len(cli_events)},
        "reruns": rerun_outputs,
    }
    (root / "verification.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(root)
    print(json.dumps(evidence, indent=2))
    assert vhost["status"] == "completed", vhost["diagnostics"]
    assert any(x["hostname"] == "admin.localhost" for x in vhost["candidates"])
    assert path_scan["status"] == "completed", path_scan["diagnostics"]
    assert any(x["url"].endswith("/admin") for x in path_scan["candidates"])
    assert ext_scan["status"] == "completed", ext_scan["diagnostics"]
    assert ".php" in ext_scan["confirmed_extensions"]
    assert any(x["url"].endswith("/admin.php") and x["phase"] == "known_extension"
               for x in ext_scan["candidates"])
    assert ext_scan["extra_request_count"] == 2
    assert {"vhost", "paths", "extension-stem-1:index", "extension-filenames-1:.php"}.issubset(
        evidence["progress"]
    )
    assert cli_exit in (0, 1) and cli_summary["dns"]["status"] in {"partial", "unavailable", "completed"}
    assert all(stage["status"] == "completed" for stage in cli_scanners.values())
    assert any(x["hostname"] == "admin.localhost" for x in cli_scanners["vhost"]["candidates"])
    assert any(x["url"].endswith("/admin") for x in cli_scanners["paths"]["candidates"])
    assert any(x["url"].endswith("/admin.php") for x in cli_scanners["extensions"]["candidates"])
    assert any(item["stage"] == "scanner:http:vhost" and item["event"] == "progress"
               for item in cli_events)
finally:
    server.shutdown()
