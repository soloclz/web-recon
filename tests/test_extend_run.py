"""A hosts file can extend a completed run without rescanning saved hosts."""

from __future__ import annotations

import io
import json
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

from webrecon import cli, report, rerun


class ExtendRunTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.port = 8080
        self.old = "old.example.test"
        self.dns_partial = "dns-only.example.test"
        self.failed = "failed.example.test"
        self.scanner_failed = "scanner-failed.example.test"
        self.fresh = "web1337.inlanefreight.htb"

        self._save_source_host(self.old, "completed", "completed")
        self._save_source_host(self.dns_partial, "partial", "unavailable")
        self._save_source_host(self.failed, "error", "not_run")
        self._save_source_host(self.scanner_failed, "partial", "completed",
                               scanner_status="timeout")
        (self.source / "run.json").write_text(json.dumps({
            "port": self.port,
            "wordlists": {"host_prefixes_wordlist": None,
                          "paths_wordlist": None, "extensions_wordlist": None},
            "hosts": [{"host": self.old, "status": "completed"},
                      {"host": self.dns_partial, "status": "partial"},
                      {"host": self.failed, "status": "error"},
                      {"host": self.scanner_failed, "status": "partial"}],
        }))

    def _save_source_host(self, host: str, status: str, dns_status: str,
                          scanner_status: str = "completed") -> None:
        host_dir = rerun._host_dir(self.source, host)
        host_dir.mkdir(parents=True)
        if status == "error":
            result = {"host": host, "port": self.port, "status": "error",
                      "resolved_ips": [], "request_count": 0,
                      "stages": {"resolution": {"status": "error"}},
                      "web": {}, "scanners": {}, "new_hosts": []}
        else:
            prefix = host_dir / "responses" / "001-root"
            prefix.parent.mkdir()
            for suffix, contents in {
                ".body": "saved response", ".headers": "HTTP/1.1 200 OK\n",
                ".meta": "http_code=200\n", ".errors": "", ".jsonl": "{}\n",
            }.items():
                Path(f"{prefix}{suffix}").write_text(contents)
            artifact = host_dir / "scanners" / "http" / "vhost" / "saved.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("saved scanner output")
            origin = f"http://{host}:{self.port}"
            result = {"host": host, "port": self.port, "status": status,
                      "resolved_ips": ["192.0.2.10"], "request_count": 3,
                      "stages": {"resolution": {"status": "completed"},
                                 "scheme": {"status": "completed"},
                                 "dns": {"status": dns_status}},
                      "dns": {"status": dns_status, "candidates": [],
                              "scanner": {"status": "not_run"}},
                      "tls": {"status": "not_run", "san": []},
                      "web": {"http": {"status": "completed", "origin": origin,
                                       "pages": [{"url": origin + "/", "title": "Saved",
                                                  "forms": [{"action": "/login"}],
                                                  "prefix": str(prefix.relative_to(self.source))}],
                                       "fixed": [], "source_maps": [],
                                       "candidate_urls": [], "found_hosts": []}},
                      "scanners": {"http": {
                          "vhost": {"status": scanner_status, "candidates": [],
                                    "artifacts": [str(artifact.relative_to(self.source))]},
                          "paths": {"status": "completed", "candidates": []},
                          "extensions": {"status": "completed", "candidates": []}}},
                      "public_sources": {"status": "not_run"},
                      "new_hosts": []}
        (host_dir / "summary.json").write_text(json.dumps(result))

    def _scan_host(self, host, port, run_dir, options, _progress):
        host_dir = rerun._host_dir(run_dir, host)
        host_dir.mkdir(parents=True, exist_ok=True)
        result = {"host": host, "port": port, "status": "completed",
                  "resolved_ips": ["192.0.2.20"], "request_count": 1,
                  "scan_settings": cli.scan_settings(options),
                  "stages": {"resolution": {"status": "completed"},
                             "scheme": {"status": "completed"}},
                  "dns": {"status": "completed", "candidates": [],
                          "scanner": {"status": "completed" if options.host_prefixes_wordlist
                                      else "not_run"}},
                  "tls": {"status": "not_run", "san": []},
                  "web": {"http": {"status": "completed", "origin": f"http://{host}:{port}",
                                   "pages": [], "fixed": [], "candidate_urls": []}},
                  "scanners": {"http": {
                      "vhost": {"status": "completed" if options.host_prefixes_wordlist
                                else "not_run", "candidates": []},
                      "paths": {"status": "completed" if options.paths_wordlist
                                else "not_run", "candidates": []},
                      "extensions": {"status": "completed" if options.extensions_wordlist
                                     else "not_run", "candidates": []}}},
                  "public_sources": {"status": "completed" if options.public_sources
                                     else "not_run"}, "new_hosts": []}
        (host_dir / "summary.json").write_text(json.dumps(result))
        return result

    def _keep_only_old(self):
        index = self.source / "run.json"
        overview = json.loads(index.read_text())
        overview["hosts"] = [entry for entry in overview["hosts"] if entry["host"] == self.old]
        index.write_text(json.dumps(overview))
        return overview

    def test_ffuf_rate_inherits_and_override_does_not_rescan_completed_host(self):
        overview = self._keep_only_old()
        overview["scan_settings"] = {"ffuf_rate": 7}
        (self.source / "run.json").write_text(json.dumps(overview))
        output = self.root / "rate-inherited"
        seen = []

        def scan(host, port, run_dir, options, progress):
            seen.append((host, options.ffuf_rate))
            return self._scan_host(host, port, run_dir, options, progress)

        with patch.object(cli, "run_host", side_effect=scan):
            code = cli.main(["--extend-run", str(self.source), "--host", self.fresh,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(seen, [(self.fresh, 7)])
        self.assertEqual(json.loads((output / "run.json").read_text())["scan_settings"]["ffuf_rate"], 7)

        overridden = self.root / "rate-overridden"
        with patch.object(cli, "run_host", side_effect=AssertionError("completed host rescanned")):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--ffuf-rate", "5", "--out-dir", str(overridden)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads((overridden / "run.json").read_text())["hosts"][0]["action"], "reused")
        self.assertEqual(json.loads((overridden / "run.json").read_text())["scan_settings"]["ffuf_rate"], 5)

    def test_reuses_finished_hosts_and_retries_failed_host(self):
        hosts_file = self.root / "hosts.txt"
        hosts_file.write_text(
            "OLD.EXAMPLE.TEST.\n" + self.dns_partial + "\n" + self.failed +
            "\n" + self.scanner_failed + "\n" + self.fresh + "\n" + self.fresh + "\n")
        output = self.root / "extended"
        original = (rerun._host_dir(self.source, self.old) / "summary.json").read_bytes()

        with patch.object(cli, "run_host", side_effect=self._scan_host) as scanner:
            code = cli.main(["--extend-run", str(self.source),
                             "--hosts-file", str(hosts_file), "--out-dir", str(output)])

        self.assertEqual(code, 0)
        scanned_hosts = [call.args[0] for call in scanner.call_args_list]
        self.assertCountEqual(scanned_hosts, [self.failed, self.scanner_failed, self.fresh])
        self.assertEqual((rerun._host_dir(self.source, self.old) / "summary.json").read_bytes(), original)
        overview = json.loads((output / "run.json").read_text())
        self.assertEqual(overview["port"], self.port)
        self.assertCountEqual([item["host"] for item in overview["hosts"]],
                              [self.old, self.dns_partial, self.failed,
                               self.scanner_failed, self.fresh])
        self.assertEqual(len(overview["hosts"]), 5)
        actions = {item["host"]: item["action"] for item in overview["hosts"]}
        self.assertEqual(actions, {
            self.old: "reused", self.dns_partial: "reused", self.failed: "scanned",
            self.scanner_failed: "scanned", self.fresh: "scanned",
        })
        report_text = (output / "report.md").read_text()
        for host in (self.old, self.dns_partial, self.failed,
                     self.scanner_failed, self.fresh):
            self.assertIn(host, report_text)

        shutil.rmtree(self.source)
        relocated = self.root / "moved" / "extended"
        relocated.parent.mkdir()
        output.rename(relocated)
        report.report_existing_run(relocated)
        for href in re.findall(r"\]\(([^)]+)\)", (relocated / "report.md").read_text()):
            target = (relocated / unquote(href)).resolve()
            self.assertTrue(target.is_relative_to(relocated.resolve()), href)
            self.assertTrue(target.is_file(), href)
        for host in (self.old, self.dns_partial):
            summary = json.loads((rerun._host_dir(relocated, host) / "summary.json").read_text())
            prefix = summary["web"]["http"]["pages"][0]["prefix"]
            artifact = summary["scanners"]["http"]["vhost"]["artifacts"][0]
            self.assertFalse(Path(prefix).is_absolute())
            self.assertFalse(Path(artifact).is_absolute())
            self.assertEqual((relocated / f"{prefix}.body").read_text(), "saved response")
            self.assertEqual((relocated / artifact).read_text(), "saved scanner output")

    def test_mismatched_port_rejected_before_creating_output(self):
        output = self.root / "unused"
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["--extend-run", str(self.source), "--host", self.fresh,
                      "--port", "9999", "--out-dir", str(output)])
        self.assertFalse(output.exists())

    def _scan_with_changed_paths(self, source_words: Path, output: Path,
                                 *, explicit_words: Path | None = None):
        scanned = []
        path_origins = []

        def scan(host, port, run_dir, options, progress):
            scanned.append(host)
            return self._scan_host(host, port, run_dir, options, progress)

        def paths(origin, _wordlist, _out_dir, *, progress=None):
            path_origins.append(origin)
            return {"status": "completed", "candidates": [], "artifacts": []}

        command = ["--extend-run", str(self.source), "--host", self.old,
                   "--out-dir", str(output)]
        if explicit_words is not None:
            command += ["--paths-wordlist", str(explicit_words)]
        with patch.object(cli, "run_host", side_effect=scan), \
             patch.object(rerun, "run_paths", side_effect=paths), \
             patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost reran")), \
             patch.object(rerun, "run_extensions", side_effect=AssertionError("extensions reran")), \
             patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS words reran")):
            code = cli.main(command)
        self.assertEqual(code, 0)
        self.assertNotIn(self.old, scanned)
        self.assertIn(f"http://{self.old}:{self.port}", path_origins)
        overview = json.loads((output / "run.json").read_text())
        self.assertEqual(overview["wordlists"]["paths_wordlist"],
                         str((explicit_words or source_words).resolve()))
        self.assertEqual(next(item for item in overview["hosts"]
                              if item["host"] == self.old)["action"], "updated")
        summary = json.loads((rerun._host_dir(output, self.old) / "summary.json").read_text())
        self.assertEqual(summary["rerun"]["stages"], ["paths"])
        self.assertEqual(summary["scanners"]["http"]["vhost"]["status"], "completed")

    def test_changed_wordlist_updates_only_dependent_stage(self):
        source_words = self.root / "source-paths.txt"
        source_words.write_text("old\n")
        changed_words = self.root / "changed-paths.txt"
        changed_words.write_text("new\n")
        index = self.source / "run.json"
        overview = json.loads(index.read_text())
        overview["wordlists"]["paths_wordlist"] = str(source_words)
        index.write_text(json.dumps(overview))
        self._scan_with_changed_paths(source_words, self.root / "changed-wordlist",
                                      explicit_words=changed_words)

    def test_same_path_content_change_uses_saved_hash(self):
        source_words = self.root / "source-paths.txt"
        source_words.write_text("old\n")
        index = self.source / "run.json"
        overview = json.loads(index.read_text())
        overview["wordlists"]["paths_wordlist"] = str(source_words)
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        index.write_text(json.dumps(overview))
        source_words.write_text("new\n")
        self._scan_with_changed_paths(source_words, self.root / "changed-contents")

    def test_legacy_source_explicit_same_path_updates_stage(self):
        source_words = self.root / "source-paths.txt"
        source_words.write_text("old\n")
        index = self.source / "run.json"
        overview = json.loads(index.read_text())
        overview["wordlists"]["paths_wordlist"] = str(source_words)
        self.assertNotIn("wordlist_hashes", overview)
        index.write_text(json.dumps(overview))
        self._scan_with_changed_paths(source_words, self.root / "legacy-same-path",
                                      explicit_words=source_words)

    def test_new_host_inherits_source_wordlist(self):
        source_words = self.root / "source-paths.txt"
        source_words.write_text("saved\n")
        index = self.source / "run.json"
        overview = json.loads(index.read_text())
        overview["wordlists"]["paths_wordlist"] = str(source_words)
        index.write_text(json.dumps(overview))
        seen = []

        def scan(host, port, run_dir, options, progress):
            seen.append((host, options.paths_wordlist))
            return self._scan_host(host, port, run_dir, options, progress)

        with patch.object(cli, "run_host", side_effect=scan):
            code = cli.main(["--extend-run", str(self.source), "--host", self.fresh,
                             "--out-dir", str(self.root / "extended-single")])

        self.assertEqual(code, 0)
        self.assertIn((self.fresh, source_words), seen)
        saved = json.loads((self.root / "extended-single" / "run.json").read_text())
        self.assertIsNone(saved["wordlist_hashes"]["paths_wordlist"])

    def test_new_hosts_file_excludes_hostname_scanned_in_extended_run(self):
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["new_hosts"] = [
            {"name": self.fresh, "sources": ["tls_san"],
             "source_ip_port": ["192.0.2.10:8080"]},
            {"name": "other.example.test", "sources": ["web_link"],
             "source_ip_port": ["192.0.2.10:8080"]},
        ]
        summary_path.write_text(json.dumps(summary))
        output = self.root / "new-hosts-extended"

        with patch.object(cli, "run_host", side_effect=self._scan_host):
            self.assertEqual(cli.main(["--extend-run", str(self.source),
                                       "--host", self.fresh,
                                       "--out-dir", str(output)]), 0)

        self.assertEqual((output / "new-hosts.txt").read_text().splitlines(),
                         ["other.example.test"])

    def test_dns_partial_retries_but_dns_unavailable_is_reused(self):
        dns_failed = "dns-partial.example.test"
        self._save_source_host(dns_failed, "partial", "partial")
        index = self.source / "run.json"
        overview = json.loads(index.read_text())
        overview["hosts"].append({"host": dns_failed, "status": "partial"})
        index.write_text(json.dumps(overview))
        hosts_file = self.root / "dns-hosts.txt"
        hosts_file.write_text(self.dns_partial + "\n" + dns_failed + "\n")
        output = self.root / "dns-extended"

        with patch.object(cli, "run_host", side_effect=self._scan_host) as scanner:
            self.assertEqual(cli.main(["--extend-run", str(self.source),
                                       "--hosts-file", str(hosts_file),
                                       "--out-dir", str(output)]), 0)

        scanned_hosts = [call.args[0] for call in scanner.call_args_list]
        self.assertIn(dns_failed, scanned_hosts)
        self.assertNotIn(self.dns_partial, scanned_hosts)
        actions = {item["host"]: item["action"]
                   for item in json.loads((output / "run.json").read_text())["hosts"]}
        self.assertEqual(actions[self.dns_partial], "reused")
        self.assertEqual(actions[dns_failed], "scanned")

    def test_missing_saved_wordlist_does_not_block_reuse(self):
        overview = self._keep_only_old()
        words = self.root / "old-paths.txt"
        words.write_text("admin\n")
        overview["wordlists"]["paths_wordlist"] = str(words)
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        saved_hash = overview["wordlist_hashes"]["paths_wordlist"]
        (self.source / "run.json").write_text(json.dumps(overview))
        words.unlink()

        output = self.root / "reuse-with-missing-wordlist"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected rescan")):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        saved = json.loads((output / "run.json").read_text())
        self.assertEqual(saved["hosts"][0]["action"], "reused")
        self.assertEqual(saved["wordlist_hashes"]["paths_wordlist"], saved_hash)

    def test_missing_unrelated_wordlist_does_not_block_path_update(self):
        overview = self._keep_only_old()
        missing_prefixes = self.root / "prefixes.txt"
        missing_prefixes.write_text("web\n")
        old_paths = self.root / "old-paths.txt"
        old_paths.write_text("admin\n")
        new_paths = self.root / "new-paths.txt"
        new_paths.write_text("backup\n")
        overview["wordlists"].update(host_prefixes_wordlist=str(missing_prefixes),
                                     paths_wordlist=str(old_paths))
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        prefix_hash = overview["wordlist_hashes"]["host_prefixes_wordlist"]
        (self.source / "run.json").write_text(json.dumps(overview))
        host_summary = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(host_summary.read_text())
        summary["dns"]["scanner"] = {"status": "completed"}
        host_summary.write_text(json.dumps(summary))
        missing_prefixes.unlink()

        output = self.root / "path-update-missing-prefixes"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected rescan")), \
             patch.object(rerun, "run_paths", return_value={"status": "completed", "candidates": []}), \
             patch.object(rerun, "run_vhost", side_effect=AssertionError("prefix scan ran")):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--paths-wordlist", str(new_paths), "--out-dir", str(output)])
        self.assertEqual(code, 0)
        saved = json.loads((output / "run.json").read_text())
        self.assertEqual(saved["hosts"][0]["action"], "updated")
        self.assertEqual(saved["wordlist_hashes"]["host_prefixes_wordlist"], prefix_hash)

    def test_changed_extension_filename_override_updates_extensions(self):
        overview = self._keep_only_old()
        base_paths = self.root / "base-paths.txt"
        base_paths.write_text("base\n")
        override = self.root / "override-paths.txt"
        override.write_text("first\n")
        extensions = self.root / "extensions.txt"
        extensions.write_text("php\n")
        overview["wordlists"].update(paths_wordlist=str(base_paths),
                                     extensions_wordlist=str(extensions),
                                     extension_names_wordlist=str(override))
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        (self.source / "run.json").write_text(json.dumps(overview))
        override.write_text("second\n")
        used_names = []

        def extensions_scan(_origin, names, _extensions, _observed, _directory,
                            _max_requests, *, progress):
            used_names.append(names)
            return {"status": "completed", "candidates": [], "artifacts": []}

        output = self.root / "extension-override-update"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected rescan")), \
             patch.object(rerun, "run_extensions", side_effect=extensions_scan), \
             patch.object(rerun, "run_paths", side_effect=AssertionError("path scan ran")):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(used_names, [override])
        saved = json.loads((output / "run.json").read_text())
        self.assertEqual(saved["hosts"][0]["action"], "updated")
        self.assertEqual(saved["wordlist_hashes"]["extension_names_wordlist"],
                         cli.hash_wordlists({"extension_names_wordlist": str(override)})[
                             "extension_names_wordlist"])

    def test_public_sources_added_without_rescanning_web(self):
        self._keep_only_old()
        output = self.root / "public-only"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected rescan")), \
             patch("webrecon.public.run_public_sources",
                   return_value={"status": "completed", "candidates": [], "artifacts": []}):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--public-sources", "--out-dir", str(output)])
        self.assertEqual(code, 0)
        summary = json.loads((rerun._host_dir(output, self.old) / "summary.json").read_text())
        self.assertEqual(summary["rerun"]["stages"], ["public"])
        self.assertEqual(summary["public_sources"]["status"], "completed")

    def test_bounded_crawl_partial_is_reused(self):
        self._keep_only_old()
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["status"] = "partial"
        summary["scan_settings"] = {"web": {"max_pages": 50, "max_depth": 2,
                                              "max_body_bytes": 1024 * 1024,
                                              "max_requests": 200},
                                    "max_extra_requests": 100000, "public_sources": False}
        summary["web"]["http"]["status"] = "partial"
        summary["web"]["http"]["partial_reasons"] = ["crawl_limit"]
        summary["web"]["http"]["candidate_urls"] = [
            {"url": f"http://{self.old}:{self.port}/next", "source": "crawl_limit"}]
        summary_path.write_text(json.dumps(summary))

        output = self.root / "bounded-crawl"
        with patch.object(cli, "run_host", side_effect=AssertionError("bounded crawl repeated")):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        saved = json.loads((output / "run.json").read_text())
        self.assertEqual(saved["hosts"][0]["action"], "reused")

    def test_incomplete_web_body_is_rescanned(self):
        self._keep_only_old()
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["status"] = "partial"
        summary["web"]["http"]["status"] = "partial"
        summary["web"]["http"]["partial_reasons"] = ["incomplete_body"]
        summary_path.write_text(json.dumps(summary))

        output = self.root / "incomplete-body"
        with patch.object(cli, "run_host", side_effect=self._scan_host) as scanner:
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        scanner.assert_called_once()
        saved = json.loads((output / "run.json").read_text())
        self.assertEqual(saved["hosts"][0]["action"], "scanned")

    def test_changed_web_limit_rescans_and_omitted_limit_inherits(self):
        overview = self._keep_only_old()
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        profile = {"web": {"max_pages": 10, "max_depth": 2,
                           "max_body_bytes": 1024 * 1024, "max_requests": 200},
                   "max_extra_requests": 100000, "public_sources": False}
        summary["scan_settings"] = profile
        summary_path.write_text(json.dumps(summary))
        overview["scan_settings"] = profile
        (self.source / "run.json").write_text(json.dumps(overview))

        inherited = self.root / "inherited-limit"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected rescan")):
            self.assertEqual(cli.main(["--extend-run", str(self.source), "--host", self.old,
                                       "--out-dir", str(inherited)]), 0)
        self.assertEqual(json.loads((inherited / "run.json").read_text())[
            "scan_settings"]["web"]["max_pages"], 10)

        changed = self.root / "changed-limit"
        with patch.object(cli, "run_host", side_effect=self._scan_host) as scanner:
            self.assertEqual(cli.main(["--extend-run", str(self.source), "--host", self.old,
                                       "--max-pages", "20", "--out-dir", str(changed)]), 0)
        scanner.assert_called_once()
        self.assertEqual(json.loads((changed / "run.json").read_text())[
            "hosts"][0]["action"], "scanned")

    def test_changed_extra_request_limit_updates_extensions_only(self):
        overview = self._keep_only_old()
        names = self.root / "names.txt"
        names.write_text("admin\n")
        extensions = self.root / "extensions.txt"
        extensions.write_text("php\n")
        overview["wordlists"].update(paths_wordlist=str(names),
                                     extensions_wordlist=str(extensions))
        profile = {"web": {"max_pages": 50, "max_depth": 2,
                           "max_body_bytes": 1024 * 1024, "max_requests": 200},
                   "max_extra_requests": 100, "public_sources": False}
        overview["scan_settings"] = profile
        (self.source / "run.json").write_text(json.dumps(overview))
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["scan_settings"] = profile
        summary_path.write_text(json.dumps(summary))

        output = self.root / "new-extension-limit"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected full scan")), \
             patch.object(rerun, "run_extensions",
                          return_value={"status": "completed", "candidates": []}) as extension_scan, \
             patch.object(rerun, "run_paths", side_effect=AssertionError("path scan ran")):
            self.assertEqual(cli.main(["--extend-run", str(self.source), "--host", self.old,
                                       "--max-extra-requests", "200", "--out-dir", str(output)]), 0)
        extension_scan.assert_called_once()
        self.assertEqual(json.loads((rerun._host_dir(output, self.old) /
                                     "summary.json").read_text())["rerun"]["stages"], ["extensions"])

    def test_public_source_skip_is_a_completed_update(self):
        self._keep_only_old()
        output = self.root / "public-unavailable"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected rescan")), \
             patch("webrecon.public.run_public_sources",
                   return_value={"status": "unavailable", "candidates": [], "artifacts": []}):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--public-sources", "--out-dir", str(output)])
        self.assertEqual(code, 0)
        summary = json.loads((rerun._host_dir(output, self.old) / "summary.json").read_text())
        self.assertEqual(summary["rerun"]["status"], "completed")
        self.assertEqual(summary["public_sources"]["status"], "unavailable")

    def test_failed_full_retry_keeps_prior_evidence_and_attempt(self):
        overview = self._keep_only_old()
        profile = {"web": {"max_pages": 10, "max_depth": 2,
                           "max_body_bytes": 1024 * 1024, "max_requests": 200},
                   "max_extra_requests": 100000, "public_sources": False}
        overview["scan_settings"] = profile
        (self.source / "run.json").write_text(json.dumps(overview))
        source_summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        original = json.loads(source_summary_path.read_text())
        original["scan_settings"] = profile
        source_summary_path.write_text(json.dumps(original))

        def failed_scan(host, port, run_dir, options, progress):
            result = self._scan_host(host, port, run_dir, options, progress)
            result["status"] = "error"
            result["stages"]["resolution"] = {"status": "error"}
            (rerun._host_dir(run_dir, host) / "summary.json").write_text(json.dumps(result))
            return result

        output = self.root / "failed-full-retry"
        with patch.object(cli, "run_host", side_effect=failed_scan):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--max-pages", "20", "--out-dir", str(output)])
        self.assertEqual(code, 1)
        kept = json.loads((rerun._host_dir(output, self.old) / "summary.json").read_text())
        self.assertEqual(kept["action"], "retry_failed")
        self.assertEqual(kept["web"]["http"]["pages"][0]["title"], "Saved")
        self.assertEqual((output / kept["retry"]["summary"]).is_file(), True)
        self.assertEqual((output / (kept["web"]["http"]["pages"][0]["prefix"] + ".body"))
                         .read_text(), "saved response")
        self.assertIn("retry summary", (output / "report.md").read_text())

    def test_failed_path_update_keeps_prior_result(self):
        overview = self._keep_only_old()
        old_words = self.root / "old-words.txt"
        old_words.write_text("admin\n")
        new_words = self.root / "new-words.txt"
        new_words.write_text("portal\n")
        overview["wordlists"]["paths_wordlist"] = str(old_words)
        (self.source / "run.json").write_text(json.dumps(overview))
        output = self.root / "failed-path-update"
        with patch.object(rerun, "run_paths",
                          return_value={"status": "error", "candidates": [], "artifacts": []}):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--paths-wordlist", str(new_words), "--out-dir", str(output)])
        self.assertEqual(code, 1)
        kept = json.loads((rerun._host_dir(output, self.old) / "summary.json").read_text())
        self.assertEqual(kept["action"], "retry_failed")
        self.assertEqual(kept["scanners"]["http"]["paths"]["status"], "completed")
        attempt = json.loads((output / kept["retry"]["summary"]).read_text())
        self.assertEqual(attempt["scanners"]["http"]["paths"]["status"], "error")
        self.assertEqual(kept["retry"]["stages"], ["paths"])

        recovered = self.root / "path-update-recovered"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected full scan")), \
             patch.object(rerun, "run_paths",
                          return_value={"status": "completed", "candidates": [], "artifacts": []}) as path_scan:
            second_code = cli.main(["--extend-run", str(output), "--host", self.old,
                                    "--out-dir", str(recovered)])
        self.assertEqual(second_code, 0)
        path_scan.assert_called_once()
        final = json.loads((rerun._host_dir(recovered, self.old) / "summary.json").read_text())
        self.assertEqual(final["action"], "updated")
        self.assertNotIn("retry", final)
        shutil.rmtree(self.source)
        shutil.rmtree(output)
        report.report_existing_run(recovered)
        for href in re.findall(r"\]\(([^)]+)\)", (recovered / "report.md").read_text()):
            self.assertTrue((recovered / unquote(href)).is_file(), href)

    def test_failed_dns_words_retries_without_repeating_vhost(self):
        overview = self._keep_only_old()
        prefixes = self.root / "prefixes.txt"
        prefixes.write_text("admin\n")
        overview["wordlists"]["host_prefixes_wordlist"] = str(prefixes)
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        (self.source / "run.json").write_text(json.dumps(overview))
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["status"] = "partial"
        summary["dns"].update(status="partial", required_failures=[],
                              scanner={"status": "error"})
        summary_path.write_text(json.dumps(summary))
        output = self.root / "dns-only-retry"
        replacement = {"status": "completed", "records": {"A": ["192.0.2.10"]},
                       "scanner": {"status": "completed"}, "candidates": []}
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected full scan")), \
             patch.object(rerun, "rerun_dns_words", return_value=replacement) as dns_scan, \
             patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost repeated")):
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        dns_scan.assert_called_once()
        final = json.loads((rerun._host_dir(output, self.old) / "summary.json").read_text())
        self.assertEqual(final["action"], "updated")

    def test_failed_vhost_retries_without_repeating_dns_words(self):
        overview = self._keep_only_old()
        prefixes = self.root / "prefixes.txt"
        prefixes.write_text("admin\n")
        overview["wordlists"]["host_prefixes_wordlist"] = str(prefixes)
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        (self.source / "run.json").write_text(json.dumps(overview))
        summary_path = rerun._host_dir(self.source, self.old) / "summary.json"
        summary = json.loads(summary_path.read_text())
        summary["status"] = "partial"
        summary["dns"]["scanner"] = {"status": "completed"}
        summary["scanners"]["http"]["vhost"]["status"] = "timeout"
        summary_path.write_text(json.dumps(summary))
        output = self.root / "vhost-only-retry"
        with patch.object(cli, "run_host", side_effect=AssertionError("unexpected full scan")), \
             patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS repeated")), \
             patch.object(rerun, "run_vhost",
                          return_value={"status": "completed", "candidates": []}) as vhost_scan:
            code = cli.main(["--extend-run", str(self.source), "--host", self.old,
                             "--out-dir", str(output)])
        self.assertEqual(code, 0)
        vhost_scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
