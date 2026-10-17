"""Ordinary CLI runs continue the latest unambiguous run in one scope."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from webrecon import cli, rerun


@contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class AutoContinueTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.scope = self.root / "engagement"
        self.scope.mkdir()
        self.old = "old.example.test"
        self.new = "new.example.test"
        self.scanned: list[tuple[str, int]] = []
        self.partial_hosts: set[str] = set()

    def _scan(self, host, port, run_dir, options, _progress):
        self.scanned.append((host, port))
        host_dir = rerun._host_dir(run_dir, host)
        host_dir.mkdir(parents=True, exist_ok=False)
        dns_status = "unavailable" if host in self.partial_hosts else "completed"
        result = {
            "host": host, "port": port,
            "status": "partial" if dns_status == "unavailable" else "completed",
            "resolved_ips": ["192.0.2.10"], "request_count": 1,
            "scan_settings": cli.scan_settings(options),
            "stages": {"resolution": {"status": "completed"},
                       "scheme": {"status": "completed"},
                       "dns": {"status": dns_status}},
            "dns": {"status": dns_status, "candidates": [],
                    "scanner": {"status": "completed" if options.host_prefixes_wordlist
                                else "not_run"}},
            "tls": {"status": "not_run", "san": []},
            "web": {"http": {"status": "completed", "origin": f"http://{host}:{port}",
                             "pages": [], "fixed": [], "candidate_urls": [],
                             "source_maps": [], "found_hosts": []}},
            "scanners": {"http": {
                "vhost": {"status": "completed" if options.host_prefixes_wordlist
                          else "not_run", "candidates": []},
                "paths": {"status": "completed" if options.paths_wordlist
                          else "not_run", "candidates": []},
                "extensions": {"status": "completed" if options.extensions_wordlist
                               else "not_run", "candidates": []}}},
            "public_sources": {"status": "not_run"}, "new_hosts": [],
        }
        (host_dir / "summary.json").write_text(json.dumps(result), encoding="utf-8")
        return result

    def _invoke(self, *arguments: str) -> int:
        with patch.object(cli, "run_host", side_effect=self._scan), \
             redirect_stdout(io.StringIO()):
            return cli.main(list(arguments))

    def _actions(self, run_dir: Path) -> dict[str, str]:
        overview = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        return {item["host"]: item["action"] for item in overview["hosts"]}

    def _legacy_run(self, directory: Path, host: str, port: int = 8080) -> None:
        directory.mkdir()
        options = cli.parser().parse_args(["--host", host, "--port", str(port)])
        result = self._scan(host, port, directory, options, None)
        cli.write_run_outputs(directory, [result], port,
                              {"host_prefixes_wordlist": None,
                               "paths_wordlist": None,
                               "extensions_wordlist": None},
                              settings=cli.scan_settings(options))

    def test_ordinary_second_invocation_extends_unique_run_in_output_parent(self):
        first = self.scope / "first"
        second = self.scope / "second"
        hosts = self.root / "hosts.txt"
        hosts.write_text(f"{self.old}\n{self.new}\n", encoding="utf-8")
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(first)), 0)
        self.assertIsNone(json.loads((first / "run.json").read_text())[
            "scan_settings"]["ffuf_rate"])
        self.assertEqual(self._invoke("--hosts-file", str(hosts), "--port", "8080",
                                      "--out-dir", str(second)), 0)
        self.assertEqual(self.scanned, [(self.old, 8080), (self.new, 8080)])
        self.assertEqual(self._actions(second), {self.old: "reused", self.new: "scanned"})
        self.assertEqual(json.loads((second / "run.json").read_text())["extended_from"],
                         str(first.resolve()))

    def test_no_out_dir_uses_current_directory_as_scope(self):
        with working_directory(self.scope):
            self.assertEqual(self._invoke("--host", self.old, "--port", "8080"), 0)
            self.assertEqual(self._invoke("--host", self.old, "--port", "8080"), 0)
        runs = sorted(path for path in self.scope.glob("web-recon-*")
                      if (path / "run.json").is_file())
        self.assertEqual(len(runs), 2)
        self.assertEqual(self.scanned, [(self.old, 8080)])
        self.assertEqual(self._actions(runs[-1]), {self.old: "reused"})

    def test_fresh_starts_new_lineage_and_becomes_current(self):
        first, fresh, third = (self.scope / name for name in ("first", "fresh", "third"))
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(first)), 0)
        self.assertEqual(self._invoke("--fresh", "--host", self.new, "--port", "8080",
                                      "--out-dir", str(fresh)), 0)
        self.assertEqual(self._actions(fresh), {self.new: "scanned"})
        hosts = self.root / "hosts.txt"
        hosts.write_text(f"{self.old}\n{self.new}\n", encoding="utf-8")
        self.assertEqual(self._invoke("--hosts-file", str(hosts), "--port", "8080",
                                      "--out-dir", str(third)), 0)
        self.assertEqual(self.scanned, [(self.old, 8080), (self.new, 8080),
                                        (self.old, 8080)])
        self.assertEqual(self._actions(third), {self.new: "reused", self.old: "scanned"})

    def test_each_port_has_its_own_current_run(self):
        first, other_port, second = (self.scope / name for name in
                                     ("first", "other-port", "second"))
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(first)), 0)
        self.assertEqual(self._invoke("--host", self.new, "--port", "8443",
                                      "--out-dir", str(other_port)), 0)
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(second)), 0)
        self.assertEqual(self.scanned, [(self.old, 8080), (self.new, 8443)])
        self.assertEqual(self._actions(second), {self.old: "reused"})

    def test_changed_wordlist_contents_update_only_that_stage(self):
        first, second = self.scope / "first", self.scope / "second"
        words = self.root / "paths.txt"
        words.write_text("admin\n", encoding="utf-8")
        arguments = ("--host", self.old, "--port", "8080",
                     "--paths-wordlist", str(words))
        self.assertEqual(self._invoke(*arguments, "--out-dir", str(first)), 0)
        words.write_text("admin\nlogin\n", encoding="utf-8")
        origins = []

        def scan_paths(origin, _wordlist, _out_dir, *, progress=None):
            origins.append(origin)
            return {"status": "completed", "candidates": [], "artifacts": []}

        with patch.object(rerun, "run_paths", side_effect=scan_paths):
            self.assertEqual(self._invoke(*arguments, "--out-dir", str(second)), 0)
        self.assertEqual(self.scanned, [(self.old, 8080)])
        self.assertEqual(origins, [f"http://{self.old}:8080"])
        self.assertEqual(self._actions(second), {self.old: "updated"})

    def test_partial_but_saved_run_is_current_for_next_invocation(self):
        self.partial_hosts.add(self.old)
        first, second = self.scope / "first", self.scope / "second"
        hosts = self.root / "hosts.txt"
        hosts.write_text(f"{self.old}\n{self.new}\n", encoding="utf-8")
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(first)), 1)
        self.assertEqual(self._invoke("--hosts-file", str(hosts), "--port", "8080",
                                      "--out-dir", str(second)), 0)
        self.assertEqual(self.scanned, [(self.old, 8080), (self.new, 8080)])
        self.assertEqual(self._actions(second), {self.old: "reused", self.new: "scanned"})

    def test_stale_pointer_errors_without_starting_a_new_scan(self):
        first, second = self.scope / "first", self.scope / "second"
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(first)), 0)
        self.assertTrue((self.scope / ".web-recon" / "port-8080.json").is_file())
        first.rename(self.scope / "moved")
        with redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit):
            self._invoke("--host", self.new, "--port", "8080",
                         "--out-dir", str(second))
        self.assertIn("--extend-run", errors.getvalue())
        self.assertEqual(self.scanned, [(self.old, 8080)])
        self.assertFalse(second.exists())

    def test_failed_attempt_does_not_replace_current_run(self):
        first, failed, third = (self.scope / name for name in
                                ("first", "failed", "third"))
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(first)), 0)
        pointer = self.scope / ".web-recon" / "port-8080.json"
        before = pointer.read_bytes()
        with patch.object(cli, "run_host", side_effect=RuntimeError("simulated crash")), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit):
            cli.main(["--host", self.new, "--port", "8080",
                      "--out-dir", str(failed)])
        self.assertFalse((failed / "run.json").exists())
        self.assertEqual(pointer.read_bytes(), before)
        self.assertEqual(self._invoke("--host", self.old, "--port", "8080",
                                      "--out-dir", str(third)), 0)
        self.assertEqual(self.scanned, [(self.old, 8080)])
        self.assertEqual(self._actions(third), {self.old: "reused"})

    def test_unique_legacy_run_can_be_adopted_without_a_pointer(self):
        previous = self.scope / "web-recon-20260101-000000"
        self._legacy_run(previous, self.old)
        self.scanned.clear()
        output = self.scope / "next"
        self.assertEqual(self._invoke("--host", self.new, "--port", "8080",
                                      "--out-dir", str(output)), 0)
        self.assertEqual(self.scanned, [(self.new, 8080)])
        self.assertEqual(self._actions(output), {self.old: "reused", self.new: "scanned"})

    def test_ambiguous_legacy_histories_require_explicit_source(self):
        left = self.scope / "web-recon-20260101-000000"
        right = self.scope / "web-recon-20260102-000000"
        self._legacy_run(left, self.old)
        self._legacy_run(right, self.new)
        self.scanned.clear()
        output = self.scope / "next"
        with redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit):
            self._invoke("--host", "third.example.test", "--port", "8080",
                         "--out-dir", str(output))
        self.assertIn("--extend-run", errors.getvalue())
        self.assertEqual(self.scanned, [])
        self.assertFalse(output.exists())
        self.assertEqual(self._invoke("--extend-run", str(left),
                                      "--host", "third.example.test",
                                      "--port", "8080", "--out-dir", str(output)), 0)
        self.assertEqual(self._actions(output), {self.old: "reused",
                                                 "third.example.test": "scanned"})


if __name__ == "__main__":
    unittest.main()
