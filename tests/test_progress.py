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
                progress.update("box.htb", "scanner:https:extensions", "extension-stem-1", 2, 10)
                progress.update("box.htb", "scanner:https:extensions", "extension-filenames-1", 1, 50)

            self.assertIn("HTTPS extension scan (known filename #1)", output.getvalue())
            self.assertIn("HTTPS extension scan (filename guesses #1)", output.getvalue())


if __name__ == "__main__":
    unittest.main()
