"""A rerun is a movable, self-contained evidence package."""

from __future__ import annotations

import json
import io
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

from webrecon import cli, report, rerun


EVIDENCE_KEYS = {"prefix", "artifact", "stdout", "stderr", "meta"}


class PortableRerunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.host = "box.example.test"
        self.port = 8080
        self.origin = f"http://{self.host}:{self.port}"
        self.host_dir = rerun._host_dir(self.source, self.host)
        self.host_dir.mkdir(parents=True)
        self.response_prefix = self.host_dir / "responses" / "007-login"
        self.response_prefix.parent.mkdir()
        for suffix, contents in {
            ".body": "old response body",
            ".headers": "HTTP/1.1 200 OK\n",
            ".meta": "http_code=200\n",
            ".errors": "",
            ".jsonl": '{"title":"Login"}\n',
        }.items():
            Path(f"{self.response_prefix}{suffix}").write_text(contents)
        self.old_dns_stdout = self._artifact(self.host_dir / "dns" / "soa.stdout.txt", "old DNS")
        self.old_dns_stderr = self._artifact(self.host_dir / "dns" / "soa.stderr.txt", "")
        self.old_vhost = self._artifact(self.host_dir / "scanners" / "http" / "vhost" / "old.json", "old vhost")
        self.old_paths = self._artifact(self.host_dir / "scanners" / "http" / "paths" / "old.json", "old path")
        self.old_extension = self._artifact(self.host_dir / "scanners" / "http" / "extensions" / "old.json", "old extension")
        self.path_words = self._wordlist("source-paths.txt")
        result = {
            "host": self.host, "port": self.port, "status": "completed",
            "resolved_ips": ["127.0.0.1"], "request_count": 7,
            "stages": {"resolution": {"status": "completed"},
                       "scheme": {"status": "completed"},
                       "dns": {"status": "completed"}},
            "dns": {"status": "completed", "records": {"A": ["127.0.0.1"]},
                    "queries": [{"stdout": str(self.old_dns_stdout.relative_to(self.source)),
                                 "stderr": str(self.old_dns_stderr.relative_to(self.source))}],
                    "scanner": {"status": "completed", "candidates": []},
                    "candidates": []},
            "tls": {"status": "unavailable", "san": []},
            "web": {"http": {"status": "completed", "origin": self.origin,
                             "pages": [{"url": self.origin + "/login",
                                        "title": "Login", "forms": [{"action": "/login"}],
                                        "prefix": str(self.response_prefix.relative_to(self.source))}],
                             "fixed": [{"url": self.origin + "/.env", "status": 200,
                                        "assessment": "candidate",
                                        "prefix": str(self.response_prefix.relative_to(self.source))}],
                             "source_maps": [], "candidate_urls": [], "found_hosts": []}},
            "scanners": {"http": {
                "vhost": {"status": "completed", "artifacts": [str(self.old_vhost.relative_to(self.source))],
                          "candidates": []},
                "paths": {"status": "completed", "artifacts": [str(self.old_paths.relative_to(self.source))],
                          "candidates": []},
                "extensions": {"status": "completed", "confirmed_extensions": [".php"],
                               "artifacts": [str(self.old_extension.relative_to(self.source))],
                               "candidates": [], "uncertain_hits": []}}},
            "public_sources": {"status": "not_run"}, "new_hosts": [],
        }
        (self.host_dir / "summary.json").write_text(json.dumps(result))
        (self.source / "run.json").write_text(json.dumps({
            "port": self.port, "hosts": [{"host": self.host}],
            "wordlists": {"paths_wordlist": str(self.path_words)},
        }))

    @staticmethod
    def _artifact(path: Path, contents: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def _wordlist(self, name: str) -> Path:
        path = self.root / name
        path.write_text("new\n")
        return path

    def _run_paths(self, *_args, progress=None):
        out_dir = _args[-1]
        artifact = self._artifact(out_dir / "new.json", "new path")
        return {"status": "completed", "artifacts": [str(artifact)], "candidates": [
            {"url": self.origin + "/new", "source": "ffuf_path", "status_code": 200,
             "assessment": "different_from_missing_baseline"}]}

    def _run_filenames(self, *_args, progress=None):
        out_dir = _args[-2]
        artifact = self._artifact(out_dir / "new.json", "new filename")
        return {"status": "completed", "artifacts": [str(artifact)],
                "candidates": [], "uncertain_hits": [], "extra_request_count": 1}

    def _run_dns(self, *_args, **_kwargs):
        out_dir = _args[-1]
        stdout = self._artifact(out_dir / "gobuster.stdout.txt", "new DNS")
        return {"status": "completed", "records": {"A": ["127.0.0.1"]},
                "queries": [{"stdout": str(stdout)}],
                "candidates": [], "scanner": {"status": "completed"}}

    def _run_vhost(self, *_args, progress=None):
        out_dir = _args[-1]
        artifact = self._artifact(out_dir / "new.json", "new vhost")
        return {"status": "completed", "artifacts": [str(artifact)], "candidates": []}

    def _assert_package(self, package: Path):
        report = (package / "report.md").read_text()
        self.assertIn("[summary.json]", report)
        self.assertIn("[body]", report)
        self.assertIn("[raw]", report)
        for href in re.findall(r"\]\(([^)]+)\)", report):
            target = (package / unquote(href)).resolve()
            self.assertTrue(target.is_relative_to(package.resolve()), href)
            self.assertTrue(target.is_file(), href)
        summary = json.loads((rerun._host_dir(package, self.host) / "summary.json").read_text())

        def inspect(value, key=""):
            if isinstance(value, dict):
                for name, child in value.items():
                    inspect(child, name)
            elif isinstance(value, list):
                for child in value:
                    inspect(child, "artifact" if key == "artifacts" else key)
            elif isinstance(value, str) and key in EVIDENCE_KEYS:
                path = Path(value)
                self.assertFalse(path.is_absolute(), value)
                target = (package / path).resolve()
                self.assertTrue(target.is_relative_to(package.resolve()), value)
                if key == "prefix":
                    for suffix in (".body", ".headers", ".meta", ".errors", ".jsonl"):
                        self.assertTrue(Path(f"{target}{suffix}").is_file(), f"{value}{suffix}")
                else:
                    self.assertTrue(target.is_file(), value)

        inspect(summary)
        return summary

    def test_rerun_survives_source_removal_and_relocation(self):
        output = self.root / "rerun"
        words = self._wordlist("new-paths.txt")
        with (patch.object(rerun, "run_paths", side_effect=self._run_paths),
              patch.object(rerun, "run_extension_filenames", side_effect=self._run_filenames)):
            code = cli.main(["--from-run", str(self.source), "--paths-wordlist", str(words),
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        original = json.loads((self.host_dir / "summary.json").read_text())
        self.assertEqual(original["scanners"]["http"]["paths"]["artifacts"],
                         [str(self.old_paths.relative_to(self.source))])
        shutil.rmtree(self.source)
        relocated = self.root / "relocated" / "rerun"
        relocated.parent.mkdir()
        output.rename(relocated)
        summary = self._assert_package(relocated)
        scanner = summary["scanners"]["http"]
        new_path = relocated / scanner["paths"]["artifacts"][0]
        old_vhost = relocated / scanner["vhost"]["artifacts"][0]
        old_extension = relocated / scanner["extensions"]["artifacts"][0]
        self.assertEqual(new_path.read_text(), "new path")
        self.assertEqual(old_vhost.read_text(), "old vhost")
        self.assertEqual(old_extension.read_text(), "old extension")
        self.assertFalse(any(path.read_text() == "old path"
                             for path in relocated.rglob("old.json")))
        report.report_existing_run(relocated)
        self._assert_package(relocated)

    def test_missing_source_evidence_fails_before_scanner_starts(self):
        Path(f"{self.response_prefix}.body").unlink()
        with patch.object(rerun, "run_paths") as scanner, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["--from-run", str(self.source),
                          "--paths-wordlist", str(self._wordlist("new-paths.txt")),
                          "--out-dir", str(self.root / "incomplete")])
        scanner.assert_not_called()

    def test_external_evidence_path_is_rejected(self):
        outside = self._artifact(self.root / "outside.txt", "unrelated local file")
        summary_path = self.host_dir / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["tls"]["artifacts"] = [str(outside)]
        summary_path.write_text(json.dumps(summary))
        with patch.object(rerun, "run_paths") as scanner, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.main(["--from-run", str(self.source),
                          "--paths-wordlist", str(self._wordlist("new-paths.txt")),
                          "--out-dir", str(self.root / "rejected")])
        scanner.assert_not_called()

    def test_chained_rerun_survives_removal_of_both_ancestors(self):
        first = self.root / "first"
        with (patch.object(rerun, "run_paths", side_effect=self._run_paths),
              patch.object(rerun, "run_extension_filenames", side_effect=self._run_filenames)):
            self.assertEqual(cli.main(["--from-run", str(self.source),
                                       "--paths-wordlist", str(self._wordlist("new-paths.txt")),
                                       "--out-dir", str(first)]), 0)
        shutil.rmtree(self.source)
        relocated_first = self.root / "relocated" / "first"
        relocated_first.parent.mkdir()
        first.rename(relocated_first)
        self._assert_package(relocated_first)
        second = self.root / "second"
        with (patch.object(rerun, "rerun_dns_words", side_effect=self._run_dns),
              patch.object(rerun, "run_vhost", side_effect=self._run_vhost)):
            self.assertEqual(cli.main(["--from-run", str(relocated_first),
                                       "--host-prefixes-wordlist", str(self._wordlist("prefixes.txt")),
                                       "--out-dir", str(second)]), 0)
        shutil.rmtree(relocated_first)
        relocated = self.root / "relocated" / "second"
        second.rename(relocated)
        summary = self._assert_package(relocated)
        scanner = summary["scanners"]["http"]
        self.assertEqual((relocated / scanner["vhost"]["artifacts"][0]).read_text(), "new vhost")
        self.assertEqual((relocated / scanner["paths"]["artifacts"][0]).read_text(), "new path")
        self.assertEqual((relocated / scanner["extensions"]["artifacts"][0]).read_text(), "old extension")
        report.report_existing_run(relocated)
        self._assert_package(relocated)


if __name__ == "__main__":
    unittest.main()
