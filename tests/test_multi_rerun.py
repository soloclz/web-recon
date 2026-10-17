"""Integration checks for wordlist-driven --from-run selection."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from webrecon import cli, rerun
from fixture_report import fixture_overview, load_report, save_fixture_report


class MultiRerunTests(unittest.TestCase):
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
        self.old_paths = self._wordlist("old-paths.txt")
        self.source_result = {
            "host": self.host,
            "port": self.port,
            "status": "completed",
            "resolved_ips": ["127.0.0.1"],
            "request_count": 7,
            "stages": {
                "resolution": {"status": "completed"},
                "scheme": {"status": "completed"},
                "dns": {"status": "completed"},
            },
            "dns": {
                "status": "completed",
                "records": {"A": ["127.0.0.1"]},
                "candidates": [
                    {"name": "old.box.example.test", "source": "gobuster_dns"}
                ],
                "scanner": {"status": "completed"},
            },
            "tls": {"status": "unavailable", "san": []},
            "web": {
                "http": {
                    "status": "completed",
                    "origin": self.origin,
                    "pages": [{"url": self.origin + "/login.php"}],
                    "fixed": [],
                    "source_maps": [],
                    "candidate_urls": [],
                    "found_hosts": [],
                }
            },
            "scanners": {
                "http": {
                    "vhost": {"status": "completed", "candidates": []},
                    "paths": {"status": "completed", "candidates": []},
                    "extensions": {
                        "status": "completed",
                        "confirmed_extensions": [".php"],
                        "candidates": [
                            {
                                "url": self.origin + "/index.php",
                                "phase": "known_basename",
                                "assessment": "different_from_missing_baseline",
                            }
                        ],
                        "uncertain_hits": [],
                    },
                }
            },
            "public_sources": {"status": "not_run"},
            "new_hosts": [],
        }
        (self.host_dir / "summary.json").write_text(json.dumps(self.source_result))
        save_fixture_report(self.source, {
                "port": self.port,
                "hosts": [{"host": self.host}],
                "wordlists": {"paths_wordlist": str(self.old_paths)},
            })

    def _wordlist(self, name):
        path = self.root / name
        path.write_text("new\n")
        return path

    def _run(self, name, *options):
        output = self.root / name
        code = cli.main(
            ["--from-run", str(self.source), *options, "--out-dir", str(output)]
        )
        summary = json.loads(
            (rerun._host_dir(output, self.host) / "summary.json").read_text()
        )
        return code, output, summary

    def _dns_result(self):
        return {
            "status": "completed",
            "records": {"A": ["127.0.0.1"]},
            "candidates": [
                {"name": "new.box.example.test", "source": "gobuster_dns"}
            ],
            "scanner": {"status": "completed"},
        }

    def _path_result(self):
        return {
            "status": "completed",
            "candidates": [
                {
                    "url": self.origin + "/new",
                    "assessment": "different_from_missing_baseline",
                }
            ],
        }

    def _extension_result(self):
        return {
            "status": "completed",
            "confirmed_extensions": [".php"],
            "candidates": [
                {
                    "url": self.origin + "/new.php",
                    "phase": "known_extension",
                    "assessment": "different_from_missing_baseline",
                }
            ],
            "uncertain_hits": [],
        }

    def test_one_prefix_flag_infers_prefix_stage(self):
        prefixes = self._wordlist("prefixes.txt")
        with (
            patch.object(rerun, "rerun_dns_words", return_value=self._dns_result()) as dns,
            patch.object(rerun, "run_vhost", return_value={"status": "completed", "candidates": []}) as vhost,
            patch.object(rerun, "run_paths", side_effect=AssertionError("paths reran")),
            patch.object(rerun, "run_extensions", side_effect=AssertionError("extensions reran")),
        ):
            code, _, summary = self._run(
                "prefixes", "--host-prefixes-wordlist", str(prefixes)
            )
        self.assertEqual(code, 0)
        dns.assert_called_once()
        vhost.assert_called_once()
        self.assertEqual(
            summary["scanners"]["http"]["paths"],
            self.source_result["scanners"]["http"]["paths"],
        )

    def test_one_path_flag_infers_path_and_filename_stages(self):
        paths = self._wordlist("paths.txt")
        with (
            patch.object(rerun, "run_paths", return_value=self._path_result()) as path_scan,
            patch.object(rerun, "run_extension_filenames", return_value=self._extension_result()) as filenames,
            patch.object(rerun, "run_extensions", side_effect=AssertionError("full extension scan reran")),
            patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost reran")),
            patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS reran")),
        ):
            code, _, summary = self._run(
                "paths", "--paths-wordlist", str(paths)
            )
        self.assertEqual(code, 0)
        path_scan.assert_called_once()
        filenames.assert_called_once()
        self.assertEqual(
            summary["scanners"]["http"]["vhost"],
            self.source_result["scanners"]["http"]["vhost"],
        )

    def test_rerun_keeps_hash_of_unchanged_stage(self):
        prefixes = self._wordlist("old-prefixes.txt")
        overview = fixture_overview(self.source)
        overview["wordlists"]["host_prefixes_wordlist"] = str(prefixes)
        overview["wordlist_hashes"] = cli.hash_wordlists(overview["wordlists"])
        old_hash = overview["wordlist_hashes"]["host_prefixes_wordlist"]
        save_fixture_report(self.source, overview)
        prefixes.write_text("changed without a prefix rerun\n")
        paths = self._wordlist("replacement-paths.txt")

        with patch.object(rerun, "run_paths", return_value=self._path_result()), \
             patch.object(rerun, "run_extension_filenames", return_value=self._extension_result()):
            code, output, _ = self._run("hash-preservation", "--paths-wordlist", str(paths))

        self.assertEqual(code, 0)
        saved = load_report(output)["run"]
        self.assertEqual(saved["wordlist_hashes"]["host_prefixes_wordlist"], old_hash)
        self.assertNotEqual(old_hash, cli.hash_wordlists({"prefix": str(prefixes)})["prefix"])

    def test_one_extension_flag_infers_extension_stage(self):
        extensions = self._wordlist("extensions.txt")
        with (
            patch.object(rerun, "run_extensions", return_value=self._extension_result()) as ext_scan,
            patch.object(rerun, "run_paths", side_effect=AssertionError("paths reran")),
            patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost reran")),
            patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS reran")),
        ):
            code, _, _ = self._run(
                "extensions", "--extensions-wordlist", str(extensions)
            )
        self.assertEqual(code, 0)
        ext_scan.assert_called_once()
        self.assertEqual(ext_scan.call_args.args[1], self.old_paths)
        self.assertEqual(ext_scan.call_args.args[2], extensions)

    def test_path_and_extension_flags_run_each_stage_once(self):
        paths = self._wordlist("paths.txt")
        extensions = self._wordlist("extensions.txt")
        with (
            patch.object(rerun, "run_paths", return_value=self._path_result()) as path_scan,
            patch.object(rerun, "run_extensions", return_value=self._extension_result()) as ext_scan,
            patch.object(rerun, "run_extension_filenames", side_effect=AssertionError("duplicate filename scan")) as filenames,
            patch.object(rerun, "run_vhost", side_effect=AssertionError("vhost reran")),
            patch.object(rerun, "rerun_dns_words", side_effect=AssertionError("DNS reran")),
        ):
            code, output, summary = self._run(
                "paths-extensions",
                "--paths-wordlist", str(paths),
                "--extensions-wordlist", str(extensions),
            )
        self.assertEqual(code, 0)
        path_scan.assert_called_once()
        ext_scan.assert_called_once()
        filenames.assert_not_called()
        self.assertEqual(ext_scan.call_args.args[1], paths)
        self.assertEqual(ext_scan.call_args.args[2], extensions)
        self.assertEqual(
            summary["scanners"]["http"]["extensions"]["candidates"],
            self._extension_result()["candidates"],
        )
        overview = load_report(output)["run"]
        self.assertEqual(overview["source_run"], str(self.source.resolve()))
        self.assertEqual(overview["rerun_stages"], ["paths", "extensions"])
        self.assertNotIn("only", overview)
        self.assertEqual(overview["wordlists"]["paths_wordlist"], str(paths.resolve()))
        self.assertEqual(overview["wordlists"]["extensions_wordlist"], str(extensions.resolve()))
        self.assertEqual(json.loads((output / "report.json").read_text())["run"]["rerun_stages"],
                         ["paths", "extensions"])

    def test_three_flags_run_each_stage_once(self):
        prefixes = self._wordlist("prefixes.txt")
        paths = self._wordlist("paths.txt")
        extensions = self._wordlist("extensions.txt")
        with (
            patch.object(rerun, "rerun_dns_words", return_value=self._dns_result()) as dns,
            patch.object(rerun, "run_vhost", return_value={"status": "completed", "candidates": []}) as vhost,
            patch.object(rerun, "run_paths", return_value=self._path_result()) as path_scan,
            patch.object(rerun, "run_extensions", return_value=self._extension_result()) as ext_scan,
            patch.object(rerun, "run_extension_filenames", side_effect=AssertionError("duplicate filename scan")) as filenames,
        ):
            code, _, _ = self._run(
                "all-three",
                "--host-prefixes-wordlist", str(prefixes),
                "--paths-wordlist", str(paths),
                "--extensions-wordlist", str(extensions),
            )
        self.assertEqual(code, 0)
        dns.assert_called_once()
        vhost.assert_called_once()
        path_scan.assert_called_once()
        ext_scan.assert_called_once()
        filenames.assert_not_called()

    def test_explicit_only_remains_supported(self):
        paths = self._wordlist("paths.txt")
        with (
            patch.object(rerun, "run_paths", return_value=self._path_result()) as path_scan,
            patch.object(rerun, "run_extension_filenames", return_value=self._extension_result()) as filenames,
            patch.object(rerun, "run_extensions", side_effect=AssertionError("full extension scan reran")),
        ):
            code, _, _ = self._run(
                "legacy-only", "--only", "paths", "--paths-wordlist", str(paths)
            )
        self.assertEqual(code, 0)
        path_scan.assert_called_once()
        filenames.assert_called_once()

    def test_extension_path_override_has_separate_provenance_and_chains(self):
        replacement_paths = self._wordlist("replacement-paths.txt")
        first_extensions = self._wordlist("first-extensions.txt")
        next_extensions = self._wordlist("next-extensions.txt")
        with (
            patch.object(rerun, "run_extensions", return_value=self._extension_result()) as first_scan,
            patch.object(rerun, "run_paths", side_effect=AssertionError("path scan reran")),
        ):
            code, first_run, first_summary = self._run(
                "extension-override",
                "--only", "extensions",
                "--paths-wordlist", str(replacement_paths),
                "--extensions-wordlist", str(first_extensions),
            )
        self.assertEqual(code, 0)
        first_scan.assert_called_once()
        self.assertEqual(first_scan.call_args.args[1], replacement_paths)
        self.assertEqual(
            first_summary["scanners"]["http"]["paths"],
            self.source_result["scanners"]["http"]["paths"],
        )
        first_metadata = load_report(first_run)["run"]
        self.assertEqual(first_metadata["wordlists"]["paths_wordlist"], str(self.old_paths))
        self.assertEqual(
            first_metadata["wordlists"]["extension_names_wordlist"],
            str(replacement_paths.resolve()),
        )

        next_run = self.root / "extension-after-override"
        with patch.object(
            rerun, "run_extensions", return_value=self._extension_result()
        ) as next_scan:
            next_code = cli.main([
                "--from-run", str(first_run),
                "--extensions-wordlist", str(next_extensions),
                "--out-dir", str(next_run),
            ])
        self.assertEqual(next_code, 0)
        next_scan.assert_called_once()
        self.assertEqual(next_scan.call_args.args[1].resolve(), replacement_paths.resolve())

    def test_scanner_workers_two_overlaps_independent_stages(self):
        paths = self._wordlist("parallel-paths.txt")
        extensions = self._wordlist("parallel-extensions.txt")
        both_started = threading.Barrier(2, timeout=5)
        thread_ids = {}
        rates = {}

        def path_scan(*_args, progress=None, rate=None, on_candidate=None):
            thread_ids["paths"] = threading.get_ident()
            rates["paths"] = rate
            both_started.wait()
            return self._path_result()

        def extension_scan(*_args, progress=None, rate=None, on_candidate=None):
            thread_ids["extensions"] = threading.get_ident()
            rates["extensions"] = rate
            both_started.wait()
            return self._extension_result()

        with (
            patch.object(rerun, "run_paths", side_effect=path_scan) as paths_mock,
            patch.object(rerun, "run_extensions", side_effect=extension_scan) as extensions_mock,
            patch.object(rerun, "run_extension_filenames", side_effect=AssertionError("duplicate filename scan")),
        ):
            code, _, _ = self._run(
                "parallel-scanners",
                "--paths-wordlist", str(paths),
                "--extensions-wordlist", str(extensions),
                "--scanner-workers", "2", "--ffuf-rate", "6",
            )
        self.assertEqual(code, 0)
        paths_mock.assert_called_once()
        extensions_mock.assert_called_once()
        self.assertNotEqual(thread_ids["paths"], thread_ids["extensions"])
        self.assertEqual(rates, {"paths": 6, "extensions": 6})

    def test_from_run_without_wordlist_rejects_before_creating_output(self):
        output = self.root / "no-flags"
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["--from-run", str(self.source), "--out-dir", str(output)])
        self.assertFalse(output.exists())

    def test_legacy_source_saves_explicit_rate_without_inheriting_it_later(self):
        paths = self._wordlist("new-paths.txt")
        with (
            patch.object(rerun, "run_paths", return_value=self._path_result()),
            patch.object(rerun, "run_extension_filenames",
                         return_value=self._extension_result()),
        ):
            code, updated, _ = self._run(
                "legacy-rate", "--paths-wordlist", str(paths), "--ffuf-rate", "7")
        self.assertEqual(code, 0)
        self.assertEqual(load_report(updated)["run"][
            "scan_settings"]["ffuf_rate"], 7)

        next_run = self.root / "auto-after-legacy-rate"
        with patch.object(cli, "run_host", side_effect=AssertionError("completed host rescanned")):
            self.assertEqual(cli.main([
                "--host", self.host, "--port", str(self.port),
                "--out-dir", str(next_run)]), 0)
        data = load_report(next_run)
        metadata = data["run"]
        self.assertIsNone(metadata["scan_settings"]["ffuf_rate"])
        self.assertEqual(data["hosts"][0]["action"], "reused")

    def test_matching_host_and_port_are_accepted_as_redundant(self):
        paths = self._wordlist("paths.txt")
        with (
            patch.object(rerun, "run_paths", return_value=self._path_result()) as path_scan,
            patch.object(rerun, "run_extension_filenames", return_value=self._extension_result()),
        ):
            code, _, _ = self._run(
                "matching-target",
                "--host", self.host,
                "--port", str(self.port),
                "--paths-wordlist", str(paths),
            )
        self.assertEqual(code, 0)
        path_scan.assert_called_once()

    def test_mismatched_host_or_port_rejects_before_creating_output(self):
        paths = self._wordlist("paths.txt")
        for name, target in (
            ("different-host", ["--host", "other.example.test"]),
            ("different-port", ["--port", "8081"]),
        ):
            with self.subTest(name=name):
                output = self.root / name
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    cli.main([
                        "--from-run", str(self.source),
                        *target,
                        "--paths-wordlist", str(paths),
                        "--out-dir", str(output),
                    ])
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
