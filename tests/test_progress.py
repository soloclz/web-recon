import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webrecon.progress import ProgressReporter


class FakeTTY(io.StringIO):
    def isatty(self):
        return True


class ProgressTests(unittest.TestCase):
    def test_vhost_display_explains_counter_without_repeating_scan_name(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("sys.stderr", output), ProgressReporter(Path(directory)) as progress:
                progress.start("box.htb", "scanner:http:vhost")
                progress.update("box.htb", "scanner:http:vhost", "vhost", 9222, 114438)
                progress.finish("box.htb", "scanner:http:vhost", "completed")

            self.assertIn("HTTP vhost scan 9,222/114,438 tried (8%), elapsed", output.getvalue())
            self.assertNotIn("vhost/vhost", output.getvalue())
            events = [json.loads(line) for line in (Path(directory) / "progress.jsonl").read_text().splitlines()]
            self.assertTrue(any(event.get("stage") == "scanner:http:vhost" and event.get("scan") == "vhost"
                                for event in events))

    def test_extension_subscan_uses_readable_terminal_label(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("sys.stderr", output), ProgressReporter(Path(directory)) as progress:
                progress.start("box.htb", "scanner:https:extensions")
                progress.update("box.htb", "scanner:https:extensions", "extension-stem-1:index", 2, 10)
                progress.update("box.htb", "scanner:https:extensions", "extension-filenames-1:.php", 1, 50)

            self.assertIn("HTTPS extension scan (known filename: index.*)", output.getvalue())
            self.assertIn("HTTPS extension scan (filename guesses: *.php)", output.getvalue())
            self.assertNotIn("#1", output.getvalue())
            events = [json.loads(line) for line in (Path(directory) / "progress.jsonl").read_text().splitlines()]
            scans = [event["scan"] for event in events if event["event"] == "progress"]
            self.assertEqual(scans, ["extension-stem-1:index", "extension-filenames-1:.php"])

    def test_filename_only_rerun_displays_confirmed_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("sys.stderr", output), ProgressReporter(Path(directory)) as progress:
                progress.start("box.htb", "scanner:http:extension-filenames")
                progress.update("box.htb", "scanner:http:extension-filenames",
                                "extension-filenames-1:.php", 3, 10)

            self.assertIn("HTTP filename scan (filename guesses: *.php)", output.getvalue())

    def test_candidate_is_immediate_deduplicated_and_structured(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("sys.stderr", output), ProgressReporter(Path(directory)) as progress:
                progress.start("box.htb", "dns")
                item = {"kind": "dns-record", "source": "dig", "name": "box.htb",
                        "answer": "10.10.10.1"}
                self.assertTrue(progress.candidate("box.htb", "dns", item,
                                                   "A box.htb → 10.10.10.1", status="observed"))
                self.assertFalse(progress.candidate("box.htb", "dns", item,
                                                    "A box.htb → 10.10.10.1", status="observed"))
                self.assertTrue(progress.candidate("box.htb", "dns",
                                                   {**item, "source": "secondary"},
                                                   "A box.htb → 10.10.10.1", status="observed"))
                self.assertTrue(progress.candidate("box.htb", "dns-words", item,
                                                   "A box.htb → 10.10.10.1", status="observed"))

            self.assertEqual(output.getvalue().count("observed DNS checks"), 2)
            events = [json.loads(line) for line in
                      (Path(directory) / "progress.jsonl").read_text().splitlines()]
            findings = [event for event in events if event["event"] == "finding"]
            self.assertEqual(len(findings), 3)
            self.assertEqual(findings[0]["item"], item)
            self.assertEqual(findings[0]["status"], "observed")

    def test_tty_candidate_keeps_one_live_line_and_sanitizes_untrusted_text(self):
        with tempfile.TemporaryDirectory() as directory:
            output = FakeTTY()
            with patch("sys.stderr", output), patch(
                    "webrecon.progress.shutil.get_terminal_size",
                    return_value=os.terminal_size((70, 24))):
                with ProgressReporter(Path(directory)) as progress:
                    progress.start("box.htb", "scanner:http:paths")
                    progress.update("box.htb", "scanner:http:paths", "paths", 2, 10)
                    progress.candidate("box.htb", "scanner:http:paths",
                                       {"kind": "path", "source": "ffuf", "url": "/admin"},
                                       "/admin\x1b[31m\r\nhello", status="candidate")
                    progress.update("box.htb", "scanner:http:paths", "paths", 10, 10)
                    progress.finish("box.htb", "scanner:http:paths", "completed")

            terminal = output.getvalue()
            self.assertEqual(terminal.count("\n"), 2)
            self.assertIn("candidate HTTP path scan: /admin [31m  hello\n", terminal)
            self.assertNotIn("\x1b[31m", terminal)
            self.assertIn("\r\x1b[2K", terminal)
            candidate_line = terminal.split("candidate HTTP path scan:", 1)[1].split("\n", 1)[0]
            self.assertLessEqual(len("candidate HTTP path scan:" + candidate_line), 69)
            events = [json.loads(line) for line in
                      (Path(directory) / "progress.jsonl").read_text().splitlines()]
            finding = next(event for event in events if event["event"] == "finding")
            self.assertEqual(finding["display"], "/admin\x1b[31m\r\nhello")

    def test_tty_finish_redraws_other_active_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            output = FakeTTY()
            with patch("sys.stderr", output), ProgressReporter(Path(directory)) as progress:
                progress.start("box.htb", "dns")
                progress.start("box.htb", "web:http")
                progress.finish("box.htb", "web:http", "completed")
                progress.finish("box.htb", "dns", "completed")

            terminal = output.getvalue()
            after_web_finish = terminal.split("HTTP Web checks completed", 1)[1]
            self.assertIn("DNS checks started", after_web_finish)
            self.assertEqual(terminal.count("\n"), 2)

    def test_tty_candidate_preserves_full_value_after_wrapping(self):
        with tempfile.TemporaryDirectory() as directory:
            output = FakeTTY()
            with patch("sys.stderr", output), patch(
                    "webrecon.progress.shutil.get_terminal_size",
                    return_value=os.terminal_size((40, 24))):
                with ProgressReporter(Path(directory)) as progress:
                    progress.candidate("h", "dns", {"kind": "title", "value": "秘密"},
                                       "秘密" * 20, status="observed")

            self.assertIn("秘密" * 20, output.getvalue())

    def test_same_form_action_with_different_methods_is_not_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("sys.stderr", io.StringIO()), ProgressReporter(Path(directory)) as progress:
                get = {"kind": "url", "source": "form_action", "url": "http://box.htb/login",
                       "method": "get"}
                self.assertTrue(progress.candidate("box.htb", "web:http", get, "GET /login"))
                self.assertTrue(progress.candidate("box.htb", "web:http",
                                                   {**get, "method": "post"}, "POST /login"))

    def test_non_tty_finding_stays_on_one_sanitized_line(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("sys.stderr", output), ProgressReporter(Path(directory)) as progress:
                progress.candidate("box.htb", "web:http", {"kind": "title", "title": "tricky"},
                                   "portal\n[forged] \x1b[31m", status="observed")
            self.assertEqual(output.getvalue().count("\n"), 1)
            self.assertNotIn("\x1b", output.getvalue())
            self.assertIn("portal [forged]", output.getvalue())

    def test_candidate_dedup_cache_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("sys.stderr", io.StringIO()), ProgressReporter(Path(directory)) as progress:
                progress._candidate_cache_limit = 2
                for name in ("first", "second", "third"):
                    self.assertTrue(progress.candidate("box.htb", "web:http",
                                                       {"kind": "link", "url": name}, name))
                self.assertEqual(len(progress._candidate_keys), 2)
                self.assertTrue(progress.candidate("box.htb", "web:http",
                                                   {"kind": "link", "url": "first"}, "first"))


if __name__ == "__main__":
    unittest.main()
