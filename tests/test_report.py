"""Focused tests for the standalone report renderer."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from webrecon import report as report_module


class ReportTests(unittest.TestCase):
    def test_consolidates_hosts_candidates_status_and_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run"
            prefix = run_dir / "hosts" / "app" / "responses" / "001-fixed"
            scan_json = run_dir / "hosts" / "app" / "scanners" / "http" / "paths.json"
            result = {
                "host": "app.example.test", "port": 8080, "status": "partial",
                "resolved_ips": ["127.0.0.1"], "request_count": 17,
                "stages": {"resolution": {"status": "completed"},
                           "scheme": {"status": "completed"}},
                "tls": {"status": "unavailable", "diagnostics": ["no certificate"]},
                "dns": {"status": "unavailable", "diagnostics": ["no DNS zone"],
                        "records": {"A": ["127.0.0.1"]}},
                "public_sources": {"status": "not_run"},
                "new_hosts": [{"name": "admin.example.test", "sources": ["ffuf_vhost"],
                               "source_ip_port": ["127.0.0.1:8080"]}],
                "web": {"http": {"status": "completed", "origin": "http://app.example.test:8080",
                                 "fixed": [{"url": "http://app.example.test:8080/.env",
                                            "status": 200, "assessment": "candidate",
                                            "prefix": str(prefix)}],
                                 "source_maps": [], "pages": [{"url": "http://app.example.test:8080/",
                                                                   "title": "App", "forms": [{"action": "/login"}],
                                                                   "fields": [], "comments": [],
                                                                   "prefix": str(prefix)}],
                                 "candidate_urls": [{"url": "http://app.example.test:8080/login",
                                                     "source": "form_action"}]}},
                "scanners": {"http": {"paths": {"status": "completed",
                                                 "artifacts": [str(scan_json)],
                                                 "candidates": [{"url": "http://app.example.test:8080/admin",
                                                                 "source": "ffuf_path", "assessment": "different_from_missing_baseline",
                                                                 "status_code": 200}],
                                                 "uncertain_hits": []},
                                       "vhost": {"status": "not_run"},
                                       "extensions": {"status": "not_run"}}},
            }
            unresolved = {"host": "down.example.test", "port": 8080, "status": "error",
                          "resolved_ips": [], "stages": {"resolution": {"status": "error",
                                                                         "diagnostics": ["DNS failed"]}},
                          "new_hosts": []}
            path = report_module.write_report(run_dir, [result, unresolved])
            output = path.read_text()
            self.assertEqual(path, (run_dir / "report.md").resolve())
            self.assertIn("## Hosts", output)
            self.assertIn("## app.example.test:8080", output)
            self.assertIn("## down.example.test:8080", output)
            self.assertIn("no DNS zone", output)
            self.assertIn("admin.example.test", output)
            self.assertIn("fixed_path", output)
            self.assertIn("ffuf_path", output)
            self.assertIn("different_from_missing_baseline", output)
            self.assertIn("[body](hosts/app/responses/001-fixed.body)", output)
            self.assertIn("[raw](hosts/app/scanners/http/paths.json)", output)
            self.assertIn("[summary.json](hosts/app.example.test-", output)

    def test_links_old_run_and_escapes_untrusted_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "prior run"
            run_dir = root / "next run"
            source.mkdir()
            absolute = source / "hosts" / "app" / "responses" / "abc #1"
            relative = "hosts/app/responses/def #2"
            result = {
                "host": "app.example.test", "port": 443, "status": "completed",
                "resolved_ips": [], "stages": {}, "new_hosts": [],
                "web": {"https": {"status": "completed", "origin": "https://app.example.test",
                                  "fixed": [
                                      {"url": "https://app.example.test/one|[bad]",
                                       "status": 200, "assessment": "candidate", "prefix": str(absolute)},
                                      {"url": "https://app.example.test/two", "status": 200,
                                       "assessment": "candidate", "prefix": relative}],
                                  "pages": [], "source_maps": [], "candidate_urls": []}},
                "scanners": {}, "dns": {}, "public_sources": {},
            }
            output = report_module.write_report(run_dir, [result], source_run=source).read_text()
            self.assertIn("one&#124;&#91;bad&#93;", output)
            self.assertIn("[body](../prior%20run/hosts/app/responses/abc%20%231.body)", output)
            self.assertIn("[body](../prior%20run/hosts/app/responses/def%20%232.body)", output)
            self.assertIn("[summary.json](../prior%20run/hosts/app.example.test-", output)

    def test_long_candidate_list_is_bounded_and_full_summary_linked(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            candidates = [{"url": f"http://example.test/{number}", "source": "ffuf_path",
                           "status_code": 200, "assessment": "different_from_missing_baseline"}
                          for number in range(35)]
            result = {"host": "example.test", "port": 80, "status": "completed",
                      "resolved_ips": [], "new_hosts": [], "web": {}, "dns": {},
                      "scanners": {"http": {"paths": {"status": "completed",
                                                       "candidates": candidates,
                                                       "uncertain_hits": []}}}}
            output = report_module.write_report(run_dir, [result]).read_text()
            self.assertIn("Showing 30 of 35; full data:", output)
            self.assertEqual(len(re.findall(r"^\| http://example\.test/\d+ \|", output, re.M)), 30)

    def test_duplicate_scanner_urls_are_one_report_row_with_both_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run"
            url = "http://example.test/index.html"
            result = {"host": "example.test", "port": 80, "status": "completed",
                      "resolved_ips": [], "new_hosts": [], "web": {}, "dns": {},
                      "scanners": {"http": {
                          "paths": {"status": "completed", "candidates": [{
                              "url": url, "source": "ffuf_path", "status_code": 200,
                              "assessment": "different_from_missing_baseline"}]},
                          "extensions": {"status": "completed", "candidates": [{
                              "url": url, "source": "ffuf_extension", "status_code": 200,
                              "assessment": "different_from_missing_baseline"}, {
                              "url": url, "source": "ffuf_extension", "status_code": 200,
                              "assessment": "different_from_missing_baseline"}]}}}}
            output = report_module.write_report(run_dir, [result]).read_text()
            self.assertIn("unique candidates: 1", output)
            self.assertEqual(output.count(f"| {url} |"), 1)
            self.assertIn("ffuf_extension, ffuf_path", output)

    def test_existing_run_generates_report_without_scanning(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "old-run"
            host = "example.test"
            summary_path = run_dir / report_module._summary_path({"host": host})
            summary_path.parent.mkdir(parents=True)
            summary_path.write_text(json.dumps({"host": host, "port": 80,
                                                "status": "completed", "resolved_ips": [],
                                                "new_hosts": [], "web": {}, "scanners": {}}))
            (run_dir / "run.json").write_text(json.dumps({"hosts": [{"host": host}]}))
            report = report_module.report_existing_run(run_dir)
            self.assertEqual(report, (run_dir / "report.md").resolve())
            self.assertIn("## example.test:80", report.read_text())


if __name__ == "__main__":
    unittest.main()
