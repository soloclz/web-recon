"""Run the real CLI against a controlled loopback Web service."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon.cli import main


class Site(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        pages = {
            "/": ("text/html", b'<html><title>Lab</title><a href="/admin">Admin</a><script src="/app.js"></script></html>'),
            "/robots.txt": ("text/plain", b"User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n"),
            "/sitemap.xml": ("application/xml", b"<urlset><url><loc>/admin</loc></url></urlset>"),
            "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
            "/admin": ("text/html", b'<html><title>Admin</title><form action="/login" method="post"><input type="hidden" name="csrf"></form></html>'),
            "/app.js": ("application/javascript", b"console.log(1);\n//# sourceMappingURL=app.js.map"),
            "/app.js.map": ("application/json", b'{"version":3,"sources":["src/app.ts"]}'),
        }
        content = pages.get(route)
        if content is None:
            status, ctype, body = 200, "text/html", b"<html><title>SPA</title>Missing route</html>"
        else:
            status, (ctype, body) = 200, content
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = ThreadingHTTPServer(("127.0.0.1", 0), Site)
Thread(target=server.serve_forever, daemon=True).start()
try:
    with TemporaryDirectory() as tmp:
        out = Path(tmp) / "run"
        code = main(["--host", "localhost", "--port", str(server.server_port),
                     "--out-dir", str(out), "--max-pages", "5", "--max-requests", "100"])
        report = json.loads((out / "report.json").read_text())
        assert report["schema_version"] == 2
        assert report["run"]["port"] == server.server_port
        summary = report["hosts"][0]
        web = summary["web"]["http"]
        git = next(item for item in web["fixed"] if item["url"].endswith("/.git/HEAD"))
        maps = web["source_maps"]
        assert summary["stages"]["scheme"]["status"] == "completed"
        assert web["status"] == "completed", web["diagnostics"]
        assert git["assessment"] == "candidate", git
        assert len(maps) == 1 and maps[0]["assessment"] == "candidate", maps
        assert maps[0]["sources"] == ["src/app.ts"]
        assert isinstance(report["new_hosts"], list)
        for redundant in ("run.json", "report.md", "new-hosts.txt", "new-hosts.jsonl"):
            assert not (out / redundant).exists(), redundant
        assert code in (0, 1) and summary["dns"]["status"] in {"completed", "unavailable", "partial"}
        print(json.dumps({"exit_code": code, "web_status": web["status"],
                          "dns_status": summary["dns"]["status"], "git": git["assessment"],
                          "source_map": maps[0]["sources"], "requests": summary["request_count"]}))
finally:
    server.shutdown()
