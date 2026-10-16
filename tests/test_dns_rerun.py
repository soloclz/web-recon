"""Focused tests for wordlist-only DNS reruns."""

from __future__ import annotations

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


from webrecon import dns


def previous_result(root: Path) -> dict:
    old = root / "old"
    old.mkdir()
    old_stdout = old / "gobuster-dns.stdout.txt"
    old_stderr = old / "gobuster-dns.stderr.txt"
    old_meta = old / "gobuster-dns.json"
    for path in (old_stdout, old_stderr, old_meta):
        path.write_text("old evidence", encoding="utf-8")
    dig_stdout = old / "dig-a.stdout.txt"
    dig_stdout.write_text("fixed evidence", encoding="utf-8")
    return {
        "status": "completed", "records": {"A": ["192.0.2.20"]},
        "candidates": [
            {"name": "ptr.example.test", "source": "dns_ptr"},
            {"name": "old.example.test", "source": "gobuster_dns",
             "addresses": ["192.0.2.50"], "wildcard_match": False},
            {"name": "shared.example.test", "source": "dns_axfr",
             "other_sources": ["gobuster_dns"],
             "addresses": ["192.0.2.50"], "wildcard_match": False},
        ],
        "queries": [
            {"command": ["dig", "example.test", "A"], "stdout": str(dig_stdout)},
            {"command": ["gobuster", "dns", "--domain", "example.test"],
             "stdout": str(old_stdout), "stderr": str(old_stderr), "meta": str(old_meta)},
        ],
        "artifacts": [str(dig_stdout), str(old_stdout), str(old_stderr), str(old_meta)],
        "diagnostics": ["fixed issue", "gobuster-dns: exit 2; see stderr"],
        "required_failures": [],
        "wildcard": {"name": "webrecon-old.example.test", "addresses": ["192.0.2.99"],
                     "aliases": [], "detected": True},
        "zone": {"name": None, "confirmed": False, "nameservers": [],
                 "authoritative_nameservers": []},
        "checked_zones": [],
        "scanner": {"status": "completed", "stdout": str(old_stdout),
                    "stderr": str(old_stderr)},
    }


class RerunDnsWordsTest(unittest.TestCase):
    def test_only_gobuster_runs_and_replaces_its_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = previous_result(root)
            snapshot = copy.deepcopy(previous)
            wordlist = root / "new.txt"
            wordlist.write_text("new\nshared\nwild\n", encoding="utf-8")
            commands = []

            def fake_run(args, **_):
                commands.append(args)
                if args[0] != "gobuster":
                    raise AssertionError("fixed DNS query was repeated")
                return subprocess.CompletedProcess(args, 0,
                    "Found: new.example.test [192.0.2.50]\n"
                    "Found: shared.example.test [192.0.2.51]\n"
                    "Found: wild.example.test [192.0.2.99]\n", "")

            with patch.object(dns.subprocess, "run", fake_run):
                result = dns.rerun_dns_words(previous, "example.test", wordlist,
                                             root / "new")
            self.assertEqual(previous, snapshot)
            self.assertEqual(1, len(commands))
            self.assertEqual(["gobuster", "dns", "--domain", "example.test", "-w",
                              str(wordlist)], commands[0])
            self.assertEqual("completed", result["status"])
            names = {item["name"]: item for item in result["candidates"]}
            self.assertNotIn("old.example.test", names)
            self.assertIn("ptr.example.test", names)
            self.assertEqual(["dns_axfr", "gobuster_dns"],
                             [names["shared.example.test"]["source"],
                              names["shared.example.test"]["other_sources"][0]])
            self.assertEqual(["192.0.2.51"], names["shared.example.test"]["addresses"])
            self.assertTrue(names["wild.example.test"]["wildcard_match"])
            self.assertEqual(["fixed issue"], result["diagnostics"])
            self.assertEqual(2, len(result["queries"]))
            self.assertTrue(all(Path(path).parent != root / "old" or
                                Path(path).name == "dig-a.stdout.txt"
                                for path in result["artifacts"]))
            self.assertTrue((root / "old" / "gobuster-dns.stdout.txt").exists())
            self.assertTrue((root / "new" / "gobuster-dns.stdout.txt").exists())

    def test_new_scanner_failure_preserves_fixed_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = previous_result(root)
            previous["required_failures"] = ["dig-txt"]
            wordlist = root / "new.txt"
            wordlist.write_text("new\n", encoding="utf-8")
            with patch.object(dns.subprocess, "run", return_value=subprocess.CompletedProcess(
                    ["gobuster"], 2, "Found: new.example.test [192.0.2.50]\n",
                    "resolver failed\n")):
                result = dns.rerun_dns_words(previous, "example.test", wordlist,
                                             root / "new")
            self.assertEqual("partial", result["status"])
            self.assertEqual("error", result["scanner"]["status"])
            self.assertIn("dig-txt", result["required_failures"])
            self.assertIn("gobuster-dns: exit 2; see stderr", result["diagnostics"])
            self.assertIn("new.example.test", [item["name"] for item in result["candidates"]])

    def test_unusable_dns_does_not_start_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = previous_result(root)
            previous["records"] = {"A": []}
            wordlist = root / "new.txt"
            wordlist.write_text("new\n", encoding="utf-8")
            with patch.object(dns.subprocess, "run", side_effect=AssertionError("scanner ran")):
                result = dns.rerun_dns_words(previous, "example.test", wordlist,
                                             root / "new")
            self.assertEqual("unavailable", result["status"])
            self.assertEqual("unavailable", result["scanner"]["status"])
            self.assertEqual(["ptr.example.test", "shared.example.test"],
                             [item["name"] for item in result["candidates"]])

    def test_omitted_wordlist_clears_old_scanner_and_keeps_fixed_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = previous_result(root)
            with patch.object(dns.subprocess, "run", side_effect=AssertionError("scanner ran")):
                result = dns.rerun_dns_words(previous, "example.test", None, root / "new")
            self.assertEqual("completed", result["status"])
            self.assertEqual("not_run", result["scanner"]["status"])
            shared = next(item for item in result["candidates"]
                          if item["name"] == "shared.example.test")
            self.assertNotIn("addresses", shared)
            self.assertNotIn("wildcard_match", shared)
            self.assertNotIn("other_sources", shared)

    def test_existing_scanner_evidence_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = previous_result(root)
            wordlist = root / "new.txt"
            wordlist.write_text("new\n", encoding="utf-8")
            with patch.object(dns.subprocess, "run", side_effect=AssertionError("scanner ran")):
                with self.assertRaises(FileExistsError):
                    dns.rerun_dns_words(previous, "example.test", wordlist, root / "old")
            self.assertEqual("old evidence", (root / "old" / "gobuster-dns.stdout.txt").read_text())


if __name__ == "__main__":
    unittest.main()
