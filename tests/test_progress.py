import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webrecon.progress import ProgressReporter


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


if __name__ == "__main__":
    unittest.main()
