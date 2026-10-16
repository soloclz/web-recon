"""Exercise the installed ffuf against a local Web fixture."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import mkdtemp
from threading import Thread
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon.fuzz import run_extensions, run_paths, run_vhost


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
    vhost = run_vhost(origin, "localhost", prefixes, root / "vhost")
    path_scan = run_paths(origin, paths, root / "paths")
    ext_scan = run_extensions(origin, paths, extensions, ["index"], root / "extensions", 2)
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
finally:
    server.shutdown()
