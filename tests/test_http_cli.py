"""Core Web checks with local response and command fixtures."""

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch
from urllib.parse import urlsplit

from webrecon import cli, http


def make_response(url, status=200, body=b"", content_type="text/html", exit_code=0):
    return http.Response(
        url=url,
        status=status,
        headers={"content-type": [content_type]},
        body=body,
        prefix="fixture-response",
        exit_code=exit_code,
    )


class FakeClient:
    def __init__(self, responder, max_requests=1000):
        self.responder = responder
        self.max_requests = max_requests
        self.request_count = 0
        self.urls = []

    def fetch(self, url, label="response"):
        if self.request_count >= self.max_requests:
            raise http.BudgetExceeded("fixture request limit reached")
        self.request_count += 1
        self.urls.append(url)
        return self.responder(url, label)


class HttpCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_tls_san_parser_reads_wrapped_names(self):
        certificate = """X509v3 Subject Alternative Name:
                DNS:app.example.test, DNS:api.example.test,
                DNS:dev.example.test, IP Address:192.0.2.1
            X509v3 Key Usage: critical
                DNS:ignore.example.test
"""
        self.assertEqual(http.parse_certificate_sans(certificate), [
            "192.0.2.1", "api.example.test", "app.example.test", "dev.example.test"
        ])

    def test_scheme_probe_rejects_http_ssl_mode_page_even_with_200(self):
        def reply(url, _label):
            if url.startswith("http://"):
                return make_response(url, body=b"SSL mode is required to access this server")
            return make_response(url, status=302, body=b"", content_type="text/plain")

        client = FakeClient(reply)
        result = http.probe_origins("box.htb", 10000, client)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["probes"]["http"]["protocol_error"])
        self.assertFalse(result["probes"]["http"]["usable"])
        self.assertTrue(result["probes"]["https"]["usable"])
        self.assertEqual([origin for origin, _ in result["origins"]], ["https://box.htb:10000"])
        self.assertEqual(client.request_count, 2)

    def test_fixed_paths_compare_with_spa_missing_path_control(self):
        origin = "http://box.htb:8080"
        spa = b"<html><title>App</title><body>single page shell</body></html>"
        root = make_response(origin + "/", body=spa)

        def reply(url, _label):
            if urlsplit(url).path == "/.env":
                return make_response(url, body=b"CONFIG=fixture")
            return make_response(url, body=spa)

        result = http.inspect_origin(origin, root, FakeClient(reply), max_pages=1)
        findings = {urlsplit(entry["url"]).path: entry for entry in result["fixed"]}
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(findings), len(http.FIXED_PATHS))
        self.assertEqual(findings["/robots.txt"]["assessment"], "baseline_match")
        self.assertEqual(findings["/.git/HEAD"]["assessment"], "baseline_match")
        self.assertEqual(findings["/.env"]["assessment"], "candidate")
        self.assertEqual(len(result["baseline"]), 2)

    def test_crawl_page_bound_and_source_map_from_loaded_script(self):
        origin = "http://box.htb:8080"
        root = make_response(
            origin + "/",
            body=(b'<html><a href="/a">a</a><a href="/b">b</a>'
                  b'<a href="https://elsewhere.example.net/x">offsite</a>'
                  b'<script src="/app.js"></script></html>'),
        )

        def reply(url, _label):
            path = urlsplit(url).path
            if path == "/app.js":
                return make_response(url, body=b"//# sourceMappingURL=app.js.map\n",
                                     content_type="application/javascript")
            if path == "/app.js.map":
                return make_response(url, body=b'{"sources":["src/app.ts"]}',
                                     content_type="application/json")
            return make_response(url, status=404, body=b"missing", content_type="text/plain")

        client = FakeClient(reply)
        result = http.inspect_origin(origin, root, client, max_pages=1, max_depth=2)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["partial_reasons"], ["crawl_limit"])
        self.assertEqual([item["url"] for item in result["pages"]], [origin + "/"])
        self.assertTrue({origin + "/a", origin + "/b"}.issubset({
            item["url"] for item in result["candidate_urls"] if item["source"] == "crawl_limit"
        }))
        self.assertNotIn(origin + "/a", client.urls)
        self.assertNotIn(origin + "/b", client.urls)
        self.assertIn(origin + "/app.js", client.urls)
        self.assertIn(origin + "/app.js.map", client.urls)
        self.assertEqual(result["source_maps"][0]["sources"], ["src/app.ts"])
        self.assertIn({"name": "elsewhere.example.net", "source": "a_link"}, result["found_hosts"])

    def test_request_budget_exhaustion_marks_web_stage_partial(self):
        origin = "http://box.htb:8080"
        root = make_response(origin + "/", body=b"<html></html>")
        client = FakeClient(lambda url, _label: make_response(url, status=404, body=b"missing"),
                            max_requests=2)
        result = http.inspect_origin(origin, root, client)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(client.request_count, 2)
        self.assertEqual(result["fixed"], [])
        self.assertTrue(any(item["source"] == "request_limit" for item in result["candidate_urls"]))

    def test_curl_body_and_request_limits_leave_evidence(self):
        commands = []

        def fake_curl(command, **_kwargs):
            commands.append(command)
            header = Path(command[command.index("-D") + 1])
            body = Path(command[command.index("-o") + 1])
            header.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            body.write_bytes(b"x" * 1024)
            return subprocess.CompletedProcess(
                command, 63,
                "url=http://box.htb:8080/\nhttp_code=200\nremote_ip=192.0.2.5\nredirect_url=\n",
                "maximum file size exceeded",
            )

        client = http.HttpClient(self.root / "responses", self.root / "absent-summary.py",
                                 max_body=1024, max_requests=1)
        with patch.object(http.subprocess, "run", side_effect=fake_curl):
            response = client.fetch("http://box.htb:8080/", "root")
            with self.assertRaises(http.BudgetExceeded):
                client.fetch("http://box.htb:8080/next", "next")
        self.assertEqual(client.request_count, 1)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][commands[0].index("--max-filesize") + 1], "1024")
        self.assertTrue(response.truncated)
        self.assertEqual(response.exit_code, 63)
        self.assertEqual(response.remote_ip, "192.0.2.5")
        for suffix in (".meta", ".headers", ".body", ".errors"):
            self.assertTrue(Path(response.prefix + suffix).is_file())

    def test_batch_resolution_failure_does_not_stop_next_hostname(self):
        hosts_file = self.root / "hosts.txt"
        hosts_file.write_text("missing.htb\ngood.htb\n", encoding="utf-8")
        out_dir = self.root / "run"

        def resolve(host, _port):
            if host == "missing.htb":
                raise socket.gaierror("name not found")
            return ["192.0.2.5"]

        def probe(host, port, _client):
            origin = f"http://{host}:{port}"
            return {"status": "completed", "probes": {"http": {"usable": True}},
                    "origins": [(origin, make_response(origin + "/"))]}

        with patch.object(cli, "resolve_host", side_effect=resolve), \
             patch.object(cli, "probe_origins", side_effect=probe), \
             patch.object(cli, "get_tls_certificate", return_value={"status": "completed", "san": []}), \
             patch.object(cli, "run_dns", return_value={"status": "completed", "candidates": []}), \
             patch.object(cli, "inspect_origin", return_value={"status": "completed", "pages": []}), \
             patch.object(cli, "run_vhost", return_value={"status": "not_run"}), \
             patch.object(cli, "run_paths", return_value={"status": "not_run"}), \
             patch.object(cli, "run_extensions", return_value={"status": "not_run"}):
            exit_code = cli.main(["--hosts-file", str(hosts_file), "--port", "8080",
                                  "--out-dir", str(out_dir)])

        overview = json.loads((out_dir / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 1)
        self.assertEqual([(item["host"], item["status"]) for item in overview["hosts"]],
                         [("missing.htb", "error"), ("good.htb", "completed")])
        summaries = sorted((out_dir / "hosts").glob("*/summary.json"))
        self.assertEqual(len(summaries), 2)
        failed = next(json.loads(path.read_text(encoding="utf-8")) for path in summaries
                      if "missing.htb" in path.parent.name)
        self.assertEqual(failed["stages"]["resolution"]["status"], "error")
        self.assertTrue((out_dir / "new-hosts.txt").is_file())
        events = [json.loads(line) for line in (out_dir / "progress.jsonl").read_text().splitlines()]
        self.assertTrue(any(item["host"] == "missing.htb" and item["stage"] == "resolution"
                            and item["event"] == "finish" and item["status"] == "error"
                            for item in events))
        self.assertTrue(any(item["host"] == "good.htb" and item["stage"] == "scanner:http:paths"
                            and item["event"] == "finish" for item in events))

    def test_dns_overlaps_web_and_two_scanners_can_overlap(self):
        out_dir = self.root / "parallel-run"
        dns_started = Event()
        web_started = Event()
        vhost_started = Event()
        paths_started = Event()
        rates = []

        def dns(*_):
            dns_started.set()
            return {"status": "completed", "candidates": []} if web_started.wait(2) else {"status": "error"}

        def probe(host, port, _client):
            web_started.set()
            origin = f"http://{host}:{port}"
            return {"status": "completed", "probes": {"http": {"usable": True}},
                    "origins": [(origin, make_response(origin + "/"))]}

        def vhost(*_, progress=None, rate=None):
            rates.append(rate)
            vhost_started.set()
            if progress is not None:
                progress("vhost", 1, 2)
                progress("vhost", 2, 2)
            return {"status": "completed", "candidates": []} if paths_started.wait(2) else {"status": "error"}

        def paths(*_, progress=None, rate=None):
            rates.append(rate)
            paths_started.set()
            return {"status": "completed", "candidates": []} if vhost_started.wait(2) else {"status": "error"}

        with patch.object(cli, "resolve_host", return_value=["192.0.2.5"]), \
             patch.object(cli, "run_dns", side_effect=dns), \
             patch.object(cli, "probe_origins", side_effect=probe), \
             patch.object(cli, "get_tls_certificate", return_value={"status": "completed", "san": []}), \
             patch.object(cli, "inspect_origin", return_value={"status": "completed", "pages": []}), \
             patch.object(cli, "run_vhost", side_effect=vhost), \
             patch.object(cli, "run_paths", side_effect=paths), \
             patch.object(cli, "run_extensions", return_value={"status": "not_run"}):
            exit_code = cli.main(["--host", "box.htb", "--port", "8080",
                                  "--out-dir", str(out_dir), "--scanner-workers", "2",
                                  "--ffuf-rate", "20"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(rates, [20, 20])
        self.assertTrue(dns_started.is_set() and web_started.is_set())
        self.assertTrue(vhost_started.is_set() and paths_started.is_set())
        events = [json.loads(line) for line in (out_dir / "progress.jsonl").read_text().splitlines()]
        self.assertTrue(any(item.get("scan") == "vhost" and item.get("current") == 2
                            and item.get("total") == 2 for item in events))


    def test_malformed_link_form_action_and_query_script_map(self):
        origin = "http://box.htb:8080"
        root = make_response(origin + "/", body=(
            b'<html><a href="http://[bad">bad</a><form action="/submit" method="post"></form>'
            b'<script src="/app.js?v=1"></script></html>'))

        def reply(url, _label):
            if urlsplit(url).path == "/app.js":
                return make_response(url, body=b"console.log(1)", content_type="application/javascript")
            if urlsplit(url).path == "/app.js.map":
                return make_response(url, body=b'{"sources":["src/app.ts"]}', content_type="application/json")
            return make_response(url, status=404, body=b"missing", content_type="text/plain")

        client = FakeClient(reply)
        result = http.inspect_origin(origin, root, client, max_pages=1)
        self.assertEqual(result["status"], "completed")
        self.assertIn({"url": origin + "/submit", "source": "form_action", "method": "post"},
                      result["candidate_urls"])
        self.assertIn(origin + "/app.js.map", client.urls)
        self.assertNotIn(origin + "/app.js?v=1.map", client.urls)
        self.assertEqual(result["source_maps"][0]["sources"], ["src/app.ts"])

    def test_incomplete_crawl_body_marks_partial(self):
        origin = "http://box.htb:8080"
        root = make_response(origin + "/", body=b'<html><a href="/broken">broken</a></html>')

        def reply(url, _label):
            if urlsplit(url).path == "/broken":
                return make_response(url, body=b"partial", exit_code=63)
            return make_response(url, status=404, body=b"missing", content_type="text/plain")

        result = http.inspect_origin(origin, root, FakeClient(reply))
        self.assertEqual(result["status"], "partial")
        self.assertIn({"url": origin + "/broken", "source": "incomplete_body"},
                      result["candidate_urls"])

    def test_incomplete_script_is_distinct_from_crawl_limit(self):
        origin = "http://box.htb:8080"
        root = make_response(origin + "/", body=(
            b'<html><a href="/next">Next</a><script src="/broken.js"></script></html>'))

        def reply(url, _label):
            if urlsplit(url).path == "/broken.js":
                return make_response(url, body=b"partial", content_type="application/javascript",
                                     exit_code=63)
            return make_response(url, status=404, body=b"missing", content_type="text/plain")

        result = http.inspect_origin(origin, root, FakeClient(reply), max_pages=1)
        self.assertEqual(result["partial_reasons"], ["crawl_limit", "incomplete_body"])
        self.assertIn({"url": origin + "/broken.js", "source": "incomplete_body"},
                      result["candidate_urls"])

    def test_incomplete_missing_path_baseline_marks_web_partial(self):
        origin = "http://box.htb:8080"
        root = make_response(origin + "/", body=b"<html>Home</html>")

        def reply(url, _label):
            return make_response(url, status=404, body=b"partial", exit_code=(
                63 if "web-recon-missing" in url else 0))

        result = http.inspect_origin(origin, root, FakeClient(reply))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["partial_reasons"], ["incomplete_body"])

    def test_new_host_endpoint_uses_actual_connected_ip(self):
        result = {"stages": {"scheme": {"probes": {"http": {"usable": True,
                    "remote_ip": "192.0.2.7"}}}}, "tls": {"san": ["api.example.test"]},
                  "dns": {"candidates": []}, "web": {}, "scanners": {}, "public_sources": {}}
        found = cli._add_candidates("app.example.test", result, ["192.0.2.8"], 8080)
        self.assertEqual(found[0]["source_ip_port"], ["192.0.2.7:8080"])


if __name__ == "__main__":
    unittest.main()
