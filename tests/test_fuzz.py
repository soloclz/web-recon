import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webrecon import fuzz


def hit(word, url, *, status=200, length=120, words=20, lines=4):
    return {
        "input": {"FUZZ": word},
        "url": url,
        "status": status,
        "length": length,
        "words": words,
        "lines": lines,
    }


BASELINE = {"status": 200, "length": 100, "words": 10, "lines": 2}
PAIR = {"probes": [BASELINE, BASELINE]}


class FuzzTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = []

    def wordlist(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def scanner(self, results_by_name, returncode=0):
        def run(argv, **kwargs):
            self.commands.append(argv)
            output = Path(argv[argv.index("-o") + 1])
            name = output.stem
            output.write_text(json.dumps({"results": results_by_name.get(name, [])}), encoding="utf-8")
            return subprocess.CompletedProcess(argv, returncode, b"scanner output", b"scanner error")

        return run

    def test_vhost_prefixes_exact_input_and_filters_default_host(self):
        names = self.wordlist("names.txt", "admin\nrandom\n")
        results = {
            "vhost": [
                hit("admin", "http://box.htb:8080/", length=500),
                hit("random", "http://box.htb:8080/", length=100, words=10, lines=2),
            ]
        }
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])
        ), patch.object(fuzz.subprocess, "run", side_effect=self.scanner(results)):
            report = fuzz.run_vhost("http://box.htb:8080", "box.htb", names, self.root / "out")
        self.assertEqual(report["status"], "completed")
        self.assertEqual([x["hostname"] for x in report["candidates"]], ["admin.box.htb"])
        command = self.commands[0]
        self.assertIn("Host: FUZZ.box.htb", command)
        self.assertNotIn("-recursion", command)
        self.assertTrue((self.root / "out" / "vhost.status.json").is_file())
        self.assertTrue((self.root / "out" / "vhost.stdout").is_file())
        self.assertTrue((self.root / "out" / "vhost.stderr").is_file())

    def test_vhost_missing_control_keeps_hit_uncertain(self):
        names = self.wordlist("names.txt", "admin\n")
        results = {"vhost": [hit("admin", "http://box.htb/", length=500)]}
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz, "_save_controls", return_value=([BASELINE], [], ["second probe failed"])
        ), patch.object(fuzz.subprocess, "run", side_effect=self.scanner(results)):
            report = fuzz.run_vhost("http://box.htb", "box.htb", names, self.root / "out")
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["uncertain_hits"][0]["hostname"], "admin.box.htb")
        self.assertEqual(report["uncertain_hits"][0]["assessment"], "baseline_unavailable")
        self.assertTrue((self.root / "out" / "vhost.json").is_file())

    def test_vhost_uses_rendered_host_when_ffuf_input_is_calibration_word(self):
        names = self.wordlist("names.txt", "admin\n")
        rendered = hit(".htaccessORbOkMKu", "http://box.htb:8080/", length=500)
        rendered["host"] = "admin.box.htb"
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])
        ), patch.object(fuzz.subprocess, "run", side_effect=self.scanner({"vhost": [rendered]})):
            report = fuzz.run_vhost("http://box.htb:8080", "box.htb", names, self.root / "out")
        self.assertEqual([item["hostname"] for item in report["candidates"]], ["admin.box.htb"])

    def test_paths_keep_only_hits_different_from_missing_path(self):
        names = self.wordlist("paths.txt", "fallback\nadmin\n")
        results = {
            "paths": [
                hit("fallback", "https://box.htb/fallback", length=100, words=10, lines=2),
                hit("admin", "https://box.htb/admin", status=302, length=0, words=0, lines=0),
            ]
        }
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=self.scanner(results)
        ):
            report = fuzz.run_paths("https://box.htb", names, self.root / "out", baseline=PAIR)
        self.assertEqual([x["url"] for x in report["candidates"]], ["https://box.htb/admin"])
        self.assertEqual(report["candidates"][0]["assessment"], "different_from_missing_baseline")
        self.assertIn("https://box.htb/FUZZ", self.commands[0])
        self.assertNotIn("-rate", self.commands[0])

    def test_paths_unstable_controls_keep_hits_uncertain(self):
        names = self.wordlist("paths.txt", "admin\n")
        results = {"paths": [hit("admin", "http://box.htb/admin", length=500)]}
        different = {"status": 200, "length": 120, "words": 10, "lines": 2}
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz, "_save_controls", return_value=([BASELINE, different], [], [])
        ), patch.object(fuzz.subprocess, "run", side_effect=self.scanner(results)):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out")
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["uncertain_hits"][0]["url"], "http://box.htb/admin")
        self.assertEqual(report["uncertain_hits"][0]["assessment"], "unstable_missing_baseline")
        self.assertTrue((self.root / "out" / "paths.json").is_file())

    def test_extension_then_filename_scan_respects_extra_request_cap(self):
        extensions = self.wordlist("extensions.txt", "php\n# ignored\n.txt\n")
        paths = self.wordlist("paths.txt", "admin\nlogin\nprofile\nconfig\n")
        results = {
            "extension-stem-1": [hit(".php", "http://box.htb/index.php", length=400)],
            "extension-filenames-1": [hit("admin", "http://box.htb/admin.php", length=450)],
        }
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=self.scanner(results)
        ), patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])) as controls:
            report = fuzz.run_extensions(
                "http://box.htb", paths, extensions, [], self.root / "out", 2, baseline=BASELINE
            )
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["confirmed_extensions"], [".php"])
        self.assertEqual(report["extra_request_count"], 2)
        self.assertEqual([x["phase"] for x in report["candidates"]], ["known_basename", "known_extension"])
        self.assertIn("http://box.htb/indexFUZZ", self.commands[0])
        self.assertIn("http://box.htb/FUZZ.php", self.commands[1])
        self.assertEqual((self.root / "out" / "extension-names-1.txt").read_text(), "admin\nlogin\n")
        self.assertEqual((self.root / "out" / "extensions.normalized.txt").read_text(), ".php\n.txt\n")
        self.assertEqual(controls.call_count, 1)
        self.assertEqual(controls.call_args.kwargs["path_suffix"], ".php")

    def test_extension_progress_names_stem_and_confirmed_extension_without_renaming_artifacts(self):
        extensions = self.wordlist("extensions.txt", "php\n")
        paths = self.wordlist("paths.txt", "admin\n")
        seen = []

        def scan(args, name, stdout, stderr, progress, timeout):
            seen.append(name)
            progress(name, 1, 1)
            hits = ([hit(".php", "http://box.htb/index.php", length=400)]
                    if name == "extension-stem-1" else [])
            Path(args[args.index("-o") + 1]).write_text(json.dumps({"results": hits}))
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            return 0, False

        updates = []
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])), \
             patch.object(fuzz, "_run_with_progress", side_effect=scan):
            result = fuzz.run_extensions("http://box.htb", paths, extensions, ["login"],
                                         self.root / "out", 1, progress=lambda *args: updates.append(args))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(seen, ["extension-stem-1", "extension-stem-2", "extension-filenames-1"])
        self.assertEqual(updates, [("extension-stem-1:index", 1, 1),
                                   ("extension-stem-2:login", 1, 1),
                                   ("extension-filenames-1:.php", 1, 1)])
        for name in seen:
            self.assertTrue((self.root / "out" / f"{name}.status.json").is_file())
            self.assertTrue((self.root / "out" / f"{name}.json").is_file())
        self.assertEqual(json.loads((self.root / "out" / "extension-stem-1.status.json").read_text())
                         ["returncode"], 0)

    def test_filename_only_rerun_progress_names_each_confirmed_extension(self):
        paths = self.wordlist("paths.txt", "admin\n")
        seen = []

        def scan(args, name, stdout, stderr, progress, timeout):
            seen.append(name)
            progress(name, 1, 1)
            Path(args[args.index("-o") + 1]).write_text('{"results": []}')
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            return 0, False

        updates = []
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])), \
             patch.object(fuzz, "_run_with_progress", side_effect=scan):
            result = fuzz.run_extension_filenames(
                "http://box.htb", paths, [".txt", ".php"], self.root / "out", 2,
                progress=lambda *args: updates.append(args))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(seen, ["extension-filenames-1", "extension-filenames-2"])
        self.assertEqual(updates, [("extension-filenames-1:.php", 1, 1),
                                   ("extension-filenames-2:.txt", 1, 1)])
        for name in seen:
            self.assertTrue((self.root / "out" / f"{name}.status.json").is_file())
            self.assertTrue((self.root / "out" / f"{name}.json").is_file())

    def test_extension_uses_rendered_url_when_ffuf_input_is_calibration_word(self):
        extensions = self.wordlist("extensions.txt", "php\n")
        paths = self.wordlist("paths.txt", "admin\n")
        results = {
            "extension-stem-1": [hit(".htaccessORbOkMKu", "http://box.htb/index.php", length=400)],
            "extension-filenames-1": [hit(".htaccessORbOkMKu", "http://box.htb/admin.php", length=450)],
        }
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=self.scanner(results)
        ), patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])):
            report = fuzz.run_extensions(
                "http://box.htb", paths, extensions, [], self.root / "out", 1
            )
        self.assertEqual(report["confirmed_extensions"], [".php"])
        self.assertEqual(report["extra_request_count"], 1)
        self.assertEqual([item["url"] for item in report["candidates"]],
                         ["http://box.htb/index.php", "http://box.htb/admin.php"])

    def test_php_fallback_does_not_confirm_extension_or_scan_names(self):
        extensions = self.wordlist("extensions.txt", ".php\n")
        paths = self.wordlist("paths.txt", "admin\nlogin\n")
        php_fallback = {"status": 200, "length": 400, "words": 20, "lines": 4}
        results = {
            "extension-stem-1": [hit(".php", "http://box.htb/index.php", length=400)],
            "extension-stem-2": [hit(".php", "http://box.htb/login.php", length=400)],
        }
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=self.scanner(results)
        ), patch.object(fuzz, "_save_controls", return_value=([php_fallback, php_fallback], [], [])) as controls:
            report = fuzz.run_extensions(
                "http://box.htb", paths, extensions, ["login"], self.root / "out", 100000,
                baseline=BASELINE,
            )
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["confirmed_extensions"], [])
        self.assertEqual(report["extra_request_count"], 0)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(controls.call_count, 1)
        self.assertEqual(len(self.commands), 2)

    def test_incomplete_extension_controls_do_not_trigger_name_scan(self):
        extensions = self.wordlist("extensions.txt", ".php\n")
        paths = self.wordlist("paths.txt", "admin\n")
        results = {"extension-stem-1": [hit(".php", "http://box.htb/index.php", length=400)]}
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=self.scanner(results)
        ), patch.object(fuzz, "_save_controls", return_value=([BASELINE], [], ["one probe failed"])):
            report = fuzz.run_extensions("http://box.htb", paths, extensions, [], self.root / "out", 100)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["confirmed_extensions"], [])
        self.assertEqual(report["extra_request_count"], 0)
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["uncertain_hits"][0]["assessment"], "extension_baseline_unavailable")

    def test_extension_controls_probe_two_missing_files_with_same_suffix(self):
        observed = []

        def probe(origin, path, host_header=None):
            observed.append(path)
            return {
                "status": 404, "length": 3, "words": 1, "lines": 1,
                "truncated": False, "headers": [], "body": b"404",
            }

        with patch.object(fuzz, "_probe", side_effect=probe):
            controls, artifacts, diagnostics = fuzz._save_controls(
                "http://box.htb", self.root, "extension-php", path_suffix=".php"
            )
        self.assertEqual(len(controls), 2)
        self.assertEqual(len(observed), 2)
        self.assertTrue(all(path.startswith("/webrecon-missing-") and path.endswith(".php") for path in observed))
        self.assertEqual(diagnostics, [])
        self.assertEqual(len(artifacts), 4)

    def test_partial_scanner_failure_remains_error_with_artifacts(self):
        names = self.wordlist("paths.txt", "admin\n")
        results = {"paths": [hit("admin", "http://box.htb/admin", length=500)]}
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=self.scanner(results, returncode=2)
        ):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out", baseline=PAIR)
        self.assertEqual(report["status"], "error")
        self.assertEqual(len(report["candidates"]), 1)
        self.assertTrue(any("partial results" in text for text in report["diagnostics"]))
        self.assertTrue((self.root / "out" / "paths.json").is_file())

    def test_streamed_hit_survives_timeout_without_final_json(self):
        names = self.wordlist("paths.txt", "admin\n")
        live = []
        streamed = hit("YWRtaW4=", "http://box.htb/admin", length=500)

        def scan(argv, name, stdout, stderr, progress, timeout, *, on_hit):
            stdout.write_bytes(json.dumps(streamed).encode() + b"\n")
            stderr.write_bytes(b":: Progress: [1/2]")
            on_hit(streamed)
            return None, True

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_run_with_progress", side_effect=scan):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out", baseline=PAIR,
                                    on_candidate=live.append)

        self.assertEqual(report["status"], "error")
        self.assertEqual(live, report["candidates"])
        self.assertTrue(any("timed out" in item for item in report["diagnostics"]))
        self.assertTrue(any("stdout hits retained: 1" in item for item in report["diagnostics"]))
        self.assertEqual(fuzz._streamed_results(self.root / "out" / "paths.stdout")[0]["input"]["FUZZ"],
                         "admin")
        self.assertEqual(json.loads((self.root / "out" / "paths.status.json").read_text())["returncode"],
                         None)

    def test_invalid_final_json_recovers_complete_streamed_hits(self):
        names = self.wordlist("paths.txt", "admin\n")
        streamed = hit("YWRtaW4=", "http://box.htb/admin", length=500)

        def scan(argv, name, stdout, stderr, progress, timeout, *, on_hit):
            stdout.write_bytes(json.dumps(streamed).encode() + b"\nnot-json\n")
            stderr.write_bytes(b"")
            Path(argv[argv.index("-o") + 1]).write_text('{"results": [')
            return 0, False

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_run_with_progress", side_effect=scan):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out", baseline=PAIR,
                                    on_candidate=lambda *_: None)

        self.assertEqual(report["status"], "error")
        self.assertEqual(report["candidates"][0]["url"], "http://box.htb/admin")
        self.assertTrue(any("invalid ffuf JSON" in item for item in report["diagnostics"]))
        self.assertTrue((self.root / "out" / "paths.json").is_file())

    def test_https_uses_insecure_tls_and_incomplete_baseline_still_probes(self):
        names = self.wordlist("paths.txt", "admin\n")
        response = {
            "status": 200,
            "length": 8,
            "words": 1,
            "lines": 1,
            "truncated": False,
            "headers": [("Content-Type", "text/html")],
            "body": b"baseline",
        }
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz, "_probe", side_effect=lambda *args: response.copy()
        ) as probe, patch.object(fuzz.subprocess, "run", side_effect=self.scanner({"paths": []})):
            report = fuzz.run_paths(
                "https://box.htb", names, self.root / "out", baseline={"status": 200, "size": 8}
            )
        self.assertEqual(report["status"], "completed")
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(len(report["controls"]), 2)
        self.assertIn("-k", self.commands[0])
        self.assertTrue((self.root / "out" / "path-control-1.body").is_file())

    def test_missing_ffuf_and_start_failure_return_unavailable(self):
        names = self.wordlist("paths.txt", "admin\n")
        with patch.object(fuzz.shutil, "which", return_value=None):
            report = fuzz.run_paths("http://box.htb", names, self.root / "absent", baseline=PAIR)
        self.assertEqual(report["status"], "unavailable")
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=FileNotFoundError("ffuf disappeared")
        ):
            report = fuzz.run_paths("http://box.htb", names, self.root / "failed", baseline=PAIR)
        self.assertEqual(report["status"], "unavailable")
        self.assertTrue((self.root / "failed" / "paths.status.json").is_file())

    def test_other_start_error_is_reported(self):
        names = self.wordlist("paths.txt", "admin\n")
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=PermissionError("blocked")
        ):
            report = fuzz.run_paths("http://box.htb", names, self.root / "failed", baseline=PAIR)
        self.assertEqual(report["status"], "error")

    def test_ffuf_request_errors_make_scan_incomplete(self):
        names = self.wordlist("paths.txt", "admin\n")

        def run(argv, **kwargs):
            output = Path(argv[argv.index("-o") + 1])
            output.write_text(json.dumps({"results": []}), encoding="utf-8")
            return subprocess.CompletedProcess(argv, 0, b"", b"\r\x1b[2K:: Progress: [1/1] :: Errors: 3 ::")

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "run", side_effect=run
        ):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out", baseline=PAIR)
        self.assertEqual(report["status"], "error")
        self.assertTrue(any("3 request errors" in item for item in report["diagnostics"]))

    def test_ffuf_progress_is_reported_before_completion_and_raw_streams_remain(self):
        names = self.wordlist("paths.txt", "admin\nmissing\n")
        actual_popen = subprocess.Popen
        launched = []
        events = []

        def launch(argv, **kwargs):
            output = Path(argv[argv.index("-o") + 1])
            output.write_text(json.dumps({"results": []}), encoding="utf-8")
            script = (
                "import os,time; "
                "os.write(2,b'\\r\\x1b[2K:: Progress: [0/2] :: Errors: 0 ::'); "
                "time.sleep(.4); "
                "os.write(2,b'\\r\\x1b[2K:: Progress: [1/2] :: Errors: 0 ::'); "
                "time.sleep(.4); "
                "os.write(2,b'\\r\\x1b[2K:: Progress: [2/2] :: Errors: 0 ::'); "
                "os.write(1,b'raw stdout\\n')"
            )
            process = actual_popen([sys.executable, "-c", script], **kwargs)
            launched.append(process)
            return process

        def progress(name, done, total):
            events.append((name, done, total, launched[-1].poll()))

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "Popen", side_effect=launch
        ):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out", baseline=PAIR, progress=progress)
        self.assertEqual(report["status"], "completed")
        self.assertTrue(any(name == "paths" and done == 0 and total == 2 and state is None
                            for name, done, total, state in events))
        self.assertEqual(events[-1][:3], ("paths", 2, 2))
        self.assertEqual((self.root / "out" / "paths.stdout").read_bytes(), b"raw stdout\n")
        self.assertIn(b"Progress: [2/2]", (self.root / "out" / "paths.stderr").read_bytes())

    def test_live_path_hit_arrives_before_ffuf_exits_and_skips_baseline_and_duplicates(self):
        names = self.wordlist("paths.txt", "admin\nmissing\n")
        actual_popen = subprocess.Popen
        active = []
        events = []
        release = self.root / "release"
        streamed = [
            hit("YWRtaW4=", "http://box.htb/admin", length=500),
            hit("YWRtaW4=", "http://box.htb/admin", length=500),
            hit("bWlzc2luZw==", "http://box.htb/missing", length=100, words=10, lines=2),
        ]
        final = [hit("admin", "http://box.htb/admin", length=500),
                 hit("missing", "http://box.htb/missing", length=100, words=10, lines=2)]

        def launch(argv, **kwargs):
            self.assertIn("-json", argv)
            output = Path(argv[argv.index("-o") + 1])
            script = (
                "import json,os,time; "
                f"records={streamed!r}; "
                f"result={final!r}; "
                f"output={str(output)!r}; "
                f"release={str(release)!r}; "
                "[os.write(1,(json.dumps(row)+'\\n').encode()) for row in records]; "
                "os.write(1,b'not-json\\n'); "
                "deadline=time.monotonic()+3;\n"
                "while not os.path.exists(release) and time.monotonic()<deadline:\n"
                " time.sleep(.02)\n"
                "open(output,'w').write(json.dumps({'results':result}))"
            )
            process = actual_popen([sys.executable, "-c", script], **kwargs)
            active.append(process)
            return process

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz.subprocess, "Popen", side_effect=launch):
            def receive(item):
                events.append((item, active[-1].poll()))
                release.write_text("continue", encoding="utf-8")

            report = fuzz.run_paths(
                "http://box.htb", names, self.root / "out", baseline=PAIR,
                on_candidate=receive,
            )

        self.assertEqual(report["status"], "completed")
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0][1])
        self.assertEqual(events[0][0], report["candidates"][0])
        self.assertEqual(events[0][0]["url"], "http://box.htb/admin")
        raw = (self.root / "out" / "paths.stdout").read_bytes()
        self.assertEqual(raw.count(b'"url": "http://box.htb/admin"'), 2)
        self.assertIn(b"not-json\n", raw)

    def test_live_vhost_uses_rendered_host_from_ffuf_json(self):
        names = self.wordlist("names.txt", "admin\n")
        seen = []
        streamed = hit("YWRtaW4=", "http://box.htb/", length=500)
        streamed["host"] = "admin.box.htb"
        final = hit("admin", "http://box.htb/", length=500)
        final["host"] = "admin.box.htb"

        def stream(argv, name, stdout, stderr, progress, timeout, *, on_hit):
            self.assertIn("-json", argv)
            on_hit(streamed)
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"results": [final]}))
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            return 0, False

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])), \
             patch.object(fuzz, "_run_with_progress", side_effect=stream):
            report = fuzz.run_vhost("http://box.htb", "box.htb", names, self.root / "out",
                                    on_candidate=seen.append)

        self.assertEqual(seen, report["candidates"])
        self.assertEqual(seen[0]["hostname"], "admin.box.htb")

    def test_live_extension_hits_use_extension_controls_in_both_phases(self):
        extensions = self.wordlist("extensions.txt", "php\n")
        paths = self.wordlist("paths.txt", "admin\n")
        seen = []
        results = {
            "extension-stem-1": [hit(".php", "http://box.htb/index.php", length=400)],
            "extension-filenames-1": [hit("admin", "http://box.htb/admin.php", length=450)],
        }

        def stream(argv, name, stdout, stderr, progress, timeout, *, on_hit):
            self.assertIn("-json", argv)
            for result in results[name]:
                streamed = {**result, "input": {"FUZZ": "Y2FsaWJyYXRpb24="}}
                on_hit(streamed)
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"results": results[name]}))
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            return 0, False

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])) as controls, \
             patch.object(fuzz, "_run_with_progress", side_effect=stream):
            report = fuzz.run_extensions("http://box.htb", paths, extensions, [],
                                         self.root / "out", 1, on_candidate=seen.append)

        self.assertEqual(seen, report["candidates"])
        self.assertEqual([item["phase"] for item in seen], ["known_basename", "known_extension"])
        self.assertEqual(controls.call_count, 1)

    def test_live_extension_filename_rerun_reports_before_final_json(self):
        paths = self.wordlist("paths.txt", "admin\n")
        seen = []
        result = hit("admin", "http://box.htb/admin.php", length=450)

        def stream(argv, name, stdout, stderr, progress, timeout, *, on_hit):
            self.assertIn("-json", argv)
            on_hit({**result, "input": {"FUZZ": "YWRtaW4="}})
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"results": [result]}))
            stdout.write_bytes(b"")
            stderr.write_bytes(b"")
            return 0, False

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])), \
             patch.object(fuzz, "_run_with_progress", side_effect=stream):
            report = fuzz.run_extension_filenames("http://box.htb", paths, [".php"],
                                                  self.root / "out", 1, on_candidate=seen.append)

        self.assertEqual(seen, report["candidates"])
        self.assertEqual(seen[0]["phase"], "known_extension")

    def test_streaming_ffuf_timeout_retains_partial_streams(self):
        names = self.wordlist("paths.txt", "admin\n")
        actual_popen = subprocess.Popen

        def launch(argv, **kwargs):
            output = Path(argv[argv.index("-o") + 1])
            output.write_text(json.dumps({"results": []}), encoding="utf-8")
            script = "import os,time; os.write(2,b':: Progress: [0/1]'); time.sleep(5)"
            return actual_popen([sys.executable, "-c", script], **kwargs)

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), patch.object(
            fuzz.subprocess, "Popen", side_effect=launch
        ), patch.object(fuzz, "TIMEOUT", 0.1):
            report = fuzz.run_paths("http://box.htb", names, self.root / "out", baseline=PAIR,
                                    progress=lambda *args: None)
        self.assertEqual(report["status"], "error")
        self.assertTrue(any("timed out" in message for message in report["diagnostics"]))
        self.assertEqual(json.loads((self.root / "out" / "paths.status.json").read_text())["returncode"], None)
        self.assertIn(b"Progress: [0/1]", (self.root / "out" / "paths.stderr").read_bytes())

    def test_large_wordlist_extends_streaming_scan_timeout(self):
        names = self.wordlist("names.txt", "# comment\n" + "admin\n" * 50)
        observed = []

        def stream(argv, name, stdout, stderr, progress, timeout):
            observed.append(timeout)
            Path(argv[argv.index("-o") + 1]).write_text(json.dumps({"results": []}), encoding="utf-8")
            stderr.write_bytes(b"")
            return 0, False

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "_save_controls", return_value=([BASELINE, BASELINE], [], [])), \
             patch.object(fuzz, "TIMEOUT_ESTIMATED_RATE", 1), patch.object(fuzz, "TIMEOUT", 10), \
             patch.object(fuzz, "_run_with_progress", side_effect=stream):
            report = fuzz.run_vhost("http://box.htb", "box.htb", names, self.root / "out",
                                    progress=lambda *_: None)

        self.assertEqual(report["status"], "completed")
        self.assertEqual(observed, [75])
        status = json.loads((self.root / "out" / "vhost.status.json").read_text())
        self.assertEqual(status["timeout_seconds"], 75)

    def test_custom_ffuf_rate_sets_command_and_timeout(self):
        names = self.wordlist("names.txt", "admin\n" * 50)
        observed = []

        def scanner(argv, **kwargs):
            observed.append((argv, kwargs["timeout"]))
            Path(argv[argv.index("-o") + 1]).write_text('{"results": []}')
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz, "TIMEOUT", 10), \
             patch.object(fuzz.subprocess, "run", side_effect=scanner):
            report = fuzz.run_paths("http://box.htb", names, self.root / "custom-rate",
                                    baseline=PAIR, rate=2)

        self.assertEqual(report["status"], "completed")
        self.assertEqual(observed[0][0][observed[0][0].index("-rate") + 1], "2")
        self.assertEqual(observed[0][1], 38)
        status = json.loads((self.root / "custom-rate" / "paths.status.json").read_text())
        self.assertEqual(status["timeout_seconds"], 38)

    def test_explicit_twenty_is_passed_to_ffuf(self):
        names = self.wordlist("names.txt", "admin\n")
        with patch.object(fuzz.shutil, "which", return_value="/usr/bin/ffuf"), \
             patch.object(fuzz.subprocess, "run", side_effect=self.scanner({})):
            report = fuzz.run_paths("http://box.htb", names, self.root / "explicit-twenty",
                                    baseline=PAIR, rate=20)

        self.assertEqual(report["status"], "completed")
        command = self.commands[0]
        self.assertEqual(command[command.index("-rate") + 1], "20")


if __name__ == "__main__":
    unittest.main()
