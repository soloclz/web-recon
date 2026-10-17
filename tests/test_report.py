"""Root report tests: complete data, provenance, and read-only loading."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from webrecon import report


class ReportTests(unittest.TestCase):
    def test_one_json_report_keeps_all_candidates_and_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            candidate_urls = [f"http://app.example.test:8080/{number}" for number in range(35)]
            host = {"host": "app.example.test", "port": 8080, "status": "completed",
                    "new_hosts": [
                        {"name": "dev.app.example.test", "sources": ["ffuf_vhost"],
                         "source_ip_port": ["192.0.2.5:8080"]},
                        {"name": "known.example.test", "sources": ["tls_san"],
                         "source_ip_port": ["192.0.2.5:8080"]}],
                    "web": {"http": {"status": "completed", "pages": [],
                                     "candidate_urls": [],
                                     "fixed": [{"url": "http://app.example.test:8080/.env",
                                                "assessment": "candidate",
                                                "prefix": "hosts/app/responses/001-fixed"}]}},
                    "scanners": {"http": {"paths": {"status": "completed", "candidates": [
                        {"url": url, "assessment": "different_from_missing_baseline"}
                        for url in candidate_urls]}}}}
            known = {"host": "known.example.test", "port": 8080, "status": "completed",
                     "new_hosts": [], "web": {}}
            for item in (host, known):
                path = run_dir / report._summary_path(item)
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(item))
            overview = {"port": 8080, "hosts": [
                {"host": host["host"]}, {"host": known["host"]}]}
            output = report.write_json_report(run_dir, [host, known], overview)
            data = json.loads(output.read_text())
            self.assertEqual(data["schema_version"], 2)
            self.assertEqual(len(data["hosts"]), 2)
            self.assertEqual(len(data["hosts"][0]["scanners"]["http"]["paths"]["candidates"]), 35)
            self.assertEqual(data["hosts"][0]["web"]["http"]["fixed"][0]["prefix"],
                             "hosts/app/responses/001-fixed")
            self.assertEqual([item["name"] for item in data["new_hosts"]],
                             ["dev.app.example.test"])
            self.assertEqual(data["new_hosts"][0]["observations"][0]["sources"],
                             ["ffuf_vhost"])
            self.assertFalse((run_dir / "report.md").exists())

    def test_saved_report_loads_without_writing_or_scanning(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            host = "example.test"
            summary_path = run_dir / report._summary_path({"host": host})
            summary_path.parent.mkdir(parents=True)
            summary_path.write_text(json.dumps({"host": host, "port": 80,
                                                "status": "completed", "new_hosts": [],
                                                "web": {}}))
            output = report.write_json_report(run_dir, [{"host": host}], {"port": 80})
            self.assertEqual(output, (run_dir / "report.json").resolve())
            before = output.read_bytes()
            data = report.load_json_report(run_dir)
            self.assertEqual(data["schema_version"], 2)
            self.assertEqual(data["hosts"][0]["host"], host)
            self.assertEqual(data["run"]["port"], 80)
            self.assertEqual(output.read_bytes(), before)
            self.assertFalse((run_dir / "run.json").exists())

    def test_missing_or_unsupported_report_is_not_a_completed_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary)
            with self.assertRaisesRegex(ValueError, "report.json"):
                report.load_json_report(run_dir)
            (run_dir / "report.json").write_text(json.dumps({"schema_version": 1}))
            with self.assertRaisesRegex(ValueError, "unsupported report schema"):
                report.load_json_report(run_dir)


if __name__ == "__main__":
    unittest.main()
