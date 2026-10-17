"""The root JSON and terminal view use the same saved observations."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from webrecon import cli, report
from webrecon.result_view import INVENTORY_KEYS, render_terminal


class ResultViewTests(unittest.TestCase):
    def test_report_keeps_saved_inventory_without_requests(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            host = "app.example.test"
            prefix = run_dir / "hosts" / "app" / "responses" / "001-root"
            prefix.parent.mkdir(parents=True)
            prefix.with_suffix(".body").write_bytes(
                b'<html><a href="/next">Next</a><img src="/logo.png">'
                b'<input name="token"><script src="/app.js"></script>'
                b'<!-- contact admin@example.test --></html>')
            inventory = {key: [] for key in INVENTORY_KEYS}
            inventory["emails"] = [{"value": "admin@example.test", "source_url": f"http://{host}:8080/",
                                    "prefix": str(prefix.relative_to(run_dir))}]
            inventory["images"] = [{"value": f"http://{host}:8080/logo.png",
                                    "source_url": f"http://{host}:8080/",
                                    "prefix": str(prefix.relative_to(run_dir))}]
            summary = {"host": host, "port": 8080, "status": "completed", "new_hosts": [],
                       "web": {"http": {"status": "completed", "pages": [
                           {"url": f"http://{host}:8080/", "content_type": "text/html",
                            "prefix": str(prefix.relative_to(run_dir))}],
                           "inventory": inventory}}}
            summary_path = run_dir / report._summary_path(summary)
            summary_path.parent.mkdir(parents=True)
            summary_path.write_text(json.dumps(summary))
            with patch.object(cli, "resolve_host", side_effect=AssertionError("network request")):
                path = report.write_json_report(run_dir, [summary], {"port": 8080})
            data = json.loads(path.read_text())
            inventory = data["hosts"][0]["web"]["http"]["inventory"]
            self.assertEqual(set(inventory), set(INVENTORY_KEYS))
            self.assertIn("admin@example.test", [item["value"] for item in inventory["emails"]])
            self.assertEqual(inventory["images"][0]["value"],
                             f"http://{host}:8080/logo.png")
            self.assertEqual(json.loads(summary_path.read_text())["web"]["http"]["inventory"],
                             inventory)

    def test_terminal_shows_all_pages_even_without_forms_or_comments(self):
        data = {"run": {"port": 8080}, "new_hosts": [], "hosts": [{
            "host": "app.example.test", "status": "completed", "stages": {},
            "web": {"http": {"pages": [{"url": "http://app.example.test:8080/"}],
                             "inventory": {key: [] for key in INVENTORY_KEYS},
                             "candidate_urls": []}}, "scanners": {}, "new_hosts": []}]}
        output = render_terminal(data)
        self.assertIn("http: ?; 1 page", output)
        self.assertIn("page: HTTP ? http://app.example.test:8080/", output)
        self.assertIn("Full data: report.json", output)

    def test_cli_report_mode_only_reads_json_and_prints_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            host = "app.example.test"
            summary_path = run_dir / report._summary_path({"host": host})
            summary_path.parent.mkdir(parents=True)
            summary_path.write_text(json.dumps({"host": host, "port": 8080,
                                                "status": "error", "stages": {
                                                    "resolution": {"status": "error",
                                                                   "diagnostics": ["unresolved"]}},
                                                "new_hosts": []}))
            report.write_json_report(run_dir, [{"host": host}], {"port": 8080})
            before = (run_dir / "report.json").read_bytes()
            buffer = io.StringIO()
            with redirect_stdout(buffer), patch.object(cli, "resolve_host",
                                                       side_effect=AssertionError("network request")):
                self.assertEqual(cli.main(["--report", str(run_dir)]), 0)
            self.assertTrue((run_dir / "report.json").is_file())
            self.assertEqual((run_dir / "report.json").read_bytes(), before)
            self.assertFalse((run_dir / "run.json").exists())
            self.assertIn("app.example.test [error; scanned]", buffer.getvalue())
            self.assertIn("unresolved", buffer.getvalue())

    def test_cli_report_rejects_scan_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main(["--report", str(run_dir), "--max-pages", "5"])
            self.assertFalse((run_dir / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
