"""Tests for optional public-index lookups; all HTTP responses are local fixtures."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webrecon.public import run_public_sources


class PublicSourcesTests(unittest.TestCase):
    def test_candidates_are_scoped_and_no_discovered_host_is_requested(self):
        requested = []
        crt = [
            {"name_value": "api.example.net\n*.dev.example.net\n*.example.net\nforeign.net\nexample.net"},
            {"name_value": "API.EXAMPLE.NET\nfoo.example.net.evil.test"},
        ]
        cdx = [
            ["original"],
            ["https://example.net/login"],
            ["http://old.example.net/config.php"],
            ["https://foreign.net/should-not-appear"],
        ]

        def fetch(url):
            requested.append(url)
            return json.dumps(crt if url.startswith("https://crt.sh/") else cdx).encode()

        with tempfile.TemporaryDirectory() as temp_dir, patch("webrecon.public._fetch", side_effect=fetch):
            result = run_public_sources("example.net", Path(temp_dir))
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(requested), 2)
            self.assertTrue(requested[0].startswith("https://crt.sh/"))
            self.assertTrue(requested[1].startswith("https://web.archive.org/cdx/search/cdx?"))
            self.assertTrue(all(Path(path).is_file() for path in result["artifacts"]))
            self.assertEqual(
                result["candidates"],
                [
                    {"kind": "hostname", "name": "api.example.net", "source": "crt.sh"},
                    {"kind": "hostname_pattern", "name": "*.dev.example.net", "source": "crt.sh"},
                    {"kind": "hostname_pattern", "name": "*.example.net", "source": "crt.sh"},
                    {"kind": "hostname", "name": "old.example.net", "source": "wayback_cdx"},
                    {"kind": "url", "url": "http://old.example.net/config.php", "source": "wayback_cdx"},
                    {"kind": "url", "url": "https://example.net/login", "source": "wayback_cdx"},
                ],
            )

    def test_reserved_or_ip_targets_do_not_contact_public_indexes(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch("webrecon.public._fetch") as fetch:
            for host in ("machine.htb", "server.local", "localhost", "192.0.2.10", "bad host"):
                result = run_public_sources(host, Path(temp_dir))
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["candidates"], [])
            fetch.assert_not_called()
            self.assertEqual(list(Path(temp_dir).iterdir()), [])

    def test_one_source_failure_keeps_other_source_results_and_status(self):
        def fetch(url):
            if url.startswith("https://crt.sh/"):
                raise OSError("service unavailable")
            return b'[["original"],["https://example.net/archived"]]'

        with tempfile.TemporaryDirectory() as temp_dir, patch("webrecon.public._fetch", side_effect=fetch):
            result = run_public_sources("example.net", Path(temp_dir))
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["sources"]["crt.sh"]["status"], "error")
            self.assertEqual(result["sources"]["wayback_cdx"]["status"], "completed")
            self.assertEqual(
                result["candidates"],
                [{"kind": "url", "url": "https://example.net/archived", "source": "wayback_cdx"}],
            )
            self.assertEqual(len(result["artifacts"]), 1)


if __name__ == "__main__":
    unittest.main()
