"""A changed wordlist reruns only its dependent stages."""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote
from unittest.mock import patch

from webrecon import cli, fuzz, rerun


class RerunTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.host = "box.example.test"
        slug = hashlib.sha256(self.host.encode()).hexdigest()[:10]
        self.host_dir = self.source / "hosts" / f"{self.host}-{slug}"
        self.host_dir.mkdir(parents=True)
        self.origin = f"http://{self.host}:8080"
        self.old_paths = self.root / "old-paths.txt"
        self.old_paths.write_text("old\n")
        response_dir = self.host_dir / "responses"
        response_dir.mkdir()
        (response_dir / "007-login.body").write_text("<form action='/login'></form>")
        self.result = {
            "host": self.host, "port": 8080, "status": "completed",
            "resolved_ips": ["127.0.0.1"], "request_count": 7,
            "stages": {"resolution": {"status": "completed"},
                       "scheme": {"status": "completed"},
                       "dns": {"status": "completed"}},
            "dns": {"status": "completed", "candidates": [
                {"name": "old.box.example.test", "source": "gobuster_dns"}],
                    "scanner": {"status": "completed"}},
            "tls": {"status": "unavailable", "san": []},
            "web": {"http": {"status": "completed", "origin": self.origin,
                             "pages": [{"url": self.origin + "/login.php",
                                        "prefix": str((response_dir / "007-login").relative_to(self.source)),
                                        "forms": [{"action": "/login"}]}],
                             "fixed": [], "source_maps": [], "candidate_urls": [],
                             "found_hosts": []}},
            "scanners": {"http": {
                "vhost": {"status": "completed", "candidates": [
                    {"hostname": "old.box.example.test", "assessment": "different_from_missing_baseline"}]},
                "paths": {"status": "completed", "candidates": [
                    {"url": self.origin + "/old", "assessment": "different_from_missing_baseline"}]},
                "extensions": {"status": "completed", "confirmed_extensions": [".php"],
                               "candidates": [
                                   {"url": self.origin + "/index.php", "phase": "known_basename",
                                    "assessment": "different_from_missing_baseline"},
                                   {"url": self.origin + "/old.php", "phase": "known_extension",
                                    "assessment": "different_from_missing_baseline"}],
                               "uncertain_hits": []}}},
            "public_sources": {"status": "not_run"},
            "new_hosts": [],
        }
        (self.host_dir / "summary.json").write_text(json.dumps(self.result))
        (self.source / "run.json").write_text(json.dumps({
            "port": 8080, "hosts": [{"host": self.host}],
            "wordlists": {"paths_wordlist": str(self.old_paths)}}))

    def _wordlist(self, name: str) -> Path:
        path = self.root / name
        path.write_text("new\n")
        return path

    def _run(self, stage: str, option: str, wordlist: Path) -> tuple[int, Path, dict]:
        output = self.root / f"rerun-{stage}"
        code = cli.main(["--from-run", str(self.source), "--only", stage,
                         option, str(wordlist), "--out-dir", str(output)])
        summary = json.loads((rerun._host_dir(output, self.host) / "summary.json").read_text())
        return code, output, summary

    def test_prefix_replaces_only_dns_words_and_vhost_and_keeps_old_evidence(self):
        wordlist = self._wordlist("prefixes.txt")
        original = (self.host_dir / "summary.json").read_bytes()
        dns_result = {"status": "completed", "records": {"A": ["127.0.0.1"]}, "candidates": [
            {"name": "new.box.example.test", "source": "gobuster_dns"}],
            "scanner": {"status": "completed"}}
        vhost_result = {"status": "completed", "candidates": [
            {"hostname": "new.box.example.test", "assessment": "different_from_missing_baseline"}]}
        with patch.object(rerun, "rerun_dns_words", return_value=dns_result) as dns, \
             patch.object(rerun, "run_vhost", return_value=vhost_result) as vhost, \
             patch.object(rerun, "run_paths", side_effect=AssertionError("paths reran")), \
             patch.object(rerun, "run_extensions", side_effect=AssertionError("extensions reran")):
            code, output, summary = self._run("prefixes", "--host-prefixes-wordlist", wordlist)
        self.assertEqual(code, 0)
        dns.assert_called_once()
        vhost.assert_called_once()
        self.assertEqual((self.host_dir / "summary.json").read_bytes(), original)
        self.assertEqual(summary["scanners"]["http"]["paths"], self.result["scanners"]["http"]["paths"])
        self.assertEqual([item["name"] for item in summary["new_hosts"]], ["new.box.example.test"])
        prefix = summary["web"]["http"]["pages"][0]["prefix"]
        self.assertFalse(Path(prefix).is_absolute())
        self.assertEqual((output / f"{prefix}.body").read_text(), "<form action='/login'></form>")
        report = (output / "report.md").read_text()
        self.assertIn("new.box.example.test", report)
        self.assertIn("Referenced reused evidence is included in this run", report)
        self.assertIn("[summary.json](hosts/", report)
        for href in re.findall(r"\]\(([^)]+)\)", report):
            target = (output / unquote(href)).resolve()
            self.assertTrue(target.is_relative_to(output.resolve()), href)
            self.assertTrue(target.is_file(), href)
        self.assertFalse((rerun._host_dir(output, self.host) / "responses").exists())
        self.assertTrue((rerun._host_dir(output, self.host) / "reused").is_dir())

    def test_path_replaces_path_and_only_extension_filename_phase(self):
        wordlist = self._wordlist("paths.txt")
        path_result = {"status": "completed", "candidates": [
            {"url": self.origin + "/new", "assessment": "different_from_missing_baseline"}]}
        filename_result = {"status": "completed", "candidates": [
            {"url": self.origin + "/new.php", "phase": "known_extension",
             "assessment": "different_from_missing_baseline"}],
            "uncertain_hits": [], "artifacts": [], "extra_request_count": 1}
        with patch.object(rerun, "run_paths", return_value=path_result) as paths, \
             patch.object(rerun, "run_extension_filenames", return_value=filename_result) as names, \
             patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost reran")), \
             patch.object(rerun, "run_extensions", side_effect=AssertionError("extension stems reran")), \
             patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS reran")):
            code, _, summary = self._run("paths", "--paths-wordlist", wordlist)
        self.assertEqual(code, 0)
        paths.assert_called_once()
        names.assert_called_once()
        self.assertEqual(summary["scanners"]["http"]["vhost"], self.result["scanners"]["http"]["vhost"])
        self.assertEqual([item["url"] for item in summary["scanners"]["http"]["extensions"]["candidates"]],
                         [self.origin + "/index.php", self.origin + "/new.php"])

    def test_extension_reuses_old_path_dictionary_and_saved_crawl(self):
        wordlist = self._wordlist("extensions.txt")
        def extensions(origin, paths, ext, stems, *_args, progress=None):
            self.assertEqual(origin, self.origin)
            self.assertEqual(paths, self.old_paths)
            self.assertEqual(ext, wordlist)
            self.assertIn("login", stems)
            return {"status": "completed", "candidates": [], "confirmed_extensions": []}
        with patch.object(rerun, "run_extensions", side_effect=extensions) as ext, \
             patch.object(rerun, "run_paths", side_effect=AssertionError("paths reran")), \
             patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost reran")), \
             patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS reran")):
            code, _, summary = self._run("extensions", "--extensions-wordlist", wordlist)
        self.assertEqual(code, 0)
        ext.assert_called_once()
        self.assertEqual(summary["scanners"]["http"]["paths"], self.result["scanners"]["http"]["paths"])

    def test_incomplete_source_rejected_before_creating_output(self):
        (self.source / "run.json").unlink()
        output = self.root / "unused"
        with self.assertRaises(SystemExit):
            cli.main(["--from-run", str(self.source), "--only", "paths",
                      "--paths-wordlist", str(self._wordlist("paths.txt")),
                      "--out-dir", str(output)])
        self.assertFalse(output.exists())

    def test_filename_only_scan_respects_new_path_budget(self):
        words = self.root / "names.txt"
        words.write_text("admin\nportal\nother\n")
        controls = [{"status": 404, "length": 7, "words": 1, "lines": 1}] * 2

        def fake_scan(out_dir, name, limited, url, *, progress=None):
            self.assertEqual(name, "extension-filenames-1")
            self.assertEqual(limited.read_text().splitlines(), ["admin", "portal"])
            self.assertEqual(url, self.origin + "/FUZZ.php")
            hit = {"url": self.origin + "/admin.php", "input": {"FUZZ": "admin"},
                   "status": 200, "length": 9, "words": 1, "lines": 1}
            return [hit], [], [], "completed"

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=(controls, [], [])), \
             patch.object(fuzz, "_scan", side_effect=fake_scan) as scanner:
            result = fuzz.run_extension_filenames(self.origin, words, [".php"],
                                                  self.root / "filenames", 2)
        scanner.assert_called_once()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["extra_request_count"], 2)
        self.assertEqual([item["url"] for item in result["candidates"]],
                         [self.origin + "/admin.php"])


if __name__ == "__main__":
    unittest.main()
