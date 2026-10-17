"""Check automatic host continuation and selective wordlist updates on Kali."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import mkdtemp
from threading import Thread

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon.cli import main


class Site(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        body = b"<html><title>Fixture</title></html>" if route == "/" else (
            b"FOUND" if route in {"/one", "/two"} else b"missing")
        status = 200 if route in {"/", "/one", "/two"} else 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


root = Path(mkdtemp(prefix="web-recon-extend-"))
paths = root / "paths.txt"
paths.write_text("one\n")
hosts = root / "hosts.txt"
hosts.write_text("127.0.0.1\n127.0.0.2\n")
server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
second_server = ThreadingHTTPServer(("127.0.0.2", server.server_port), Site)
Thread(target=server.serve_forever, daemon=True).start()
Thread(target=second_server.serve_forever, daemon=True).start()
try:
    first = root / "first"
    main(["--host", "127.0.0.1", "--port", str(server.server_port),
          "--paths-wordlist", str(paths), "--out-dir", str(first)])
    second = root / "second"
    main(["--hosts-file", str(hosts), "--port", str(server.server_port),
          "--out-dir", str(second)])
    actions = {item["host"]: item["action"] for item in json.loads(
        (second / "report.json").read_text())["hosts"]}
    assert actions == {"127.0.0.1": "reused", "127.0.0.2": "scanned"}, actions

    paths.write_text("two\n")
    third = root / "third"
    main(["--hosts-file", str(hosts), "--port", str(server.server_port),
          "--out-dir", str(third)])
    actions = {item["host"]: item["action"] for item in json.loads(
        (third / "report.json").read_text())["hosts"]}
    assert actions == {"127.0.0.1": "updated", "127.0.0.2": "updated"}, actions
    for summary_path in third.glob("hosts/*/summary.json"):
        summary = json.loads(summary_path.read_text())
        assert summary["rerun"]["stages"] == ["paths"], summary_path
        assert summary["scanners"]["http"]["paths"]["status"] == "completed", summary_path
        assert not (summary_path.parent / "responses").exists(), summary_path
    assert (third / "report.json").is_file()
    print(json.dumps({"directory": str(root), "second_actions": {
        "127.0.0.1": "reused", "127.0.0.2": "scanned"}, "third_actions": actions}, indent=2))
finally:
    server.shutdown()
    second_server.shutdown()
