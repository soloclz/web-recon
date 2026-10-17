"""Behavioral checks for DNS evidence and scanner orchestration."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon import dns  # noqa: E402


def dig_output(*records: str, status: str = "NOERROR", aa: bool = False) -> str:
    flags = "qr aa rd" if aa else "qr rd ra"
    answer = "\n".join(records)
    return (f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 7\n"
            f";; flags: {flags}; QUERY: 1, ANSWER: {len(records)}, AUTHORITY: 0\n"
            f";; ANSWER SECTION:\n{answer}\n\n;; SERVER: 192.0.2.53#53\n")


class DnsTest(unittest.TestCase):
    def test_streamed_gobuster_candidate_arrives_before_process_exits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wordlist = root / "prefixes.txt"
            wordlist.write_text("api\n", encoding="utf-8")
            marker = root / "candidate-seen"
            events = []
            actual_popen = subprocess.Popen
            script = (
                "import pathlib, sys, time\n"
                "marker = pathlib.Path(sys.argv[1])\n"
                "print('Found: api.app.example.test [192.0.2.21]', flush=True)\n"
                "for _ in range(100):\n"
                "    if marker.exists(): sys.exit(0)\n"
                "    time.sleep(0.02)\n"
                "sys.exit(3)\n"
            )

            def fake_run(args, **_kwargs):
                records = (["app.example.test. 300 IN A 192.0.2.20"]
                           if args[1] == "app.example.test" and args[2] == "A" else [])
                return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

            def fake_popen(args, **kwargs):
                self.assertEqual("gobuster", args[0])
                return actual_popen([sys.executable, "-u", "-c", script, str(marker)],
                                    **kwargs)

            def candidate(event):
                events.append(event)
                if event.get("source") == "gobuster_dns":
                    raw = root / "dns" / "gobuster-dns.stdout.txt"
                    self.assertIn("api.app.example.test", raw.read_text())
                    marker.touch()

            with patch.object(dns.subprocess, "run", side_effect=fake_run), \
                    patch.object(dns.subprocess, "Popen", side_effect=fake_popen):
                result = dns.run_dns("app.example.test", [], wordlist, root / "dns",
                                     on_candidate=candidate)
            self.assertEqual("completed", result["status"])
            self.assertTrue(marker.exists())
            self.assertIn({"kind": "dns_record", "source": "dns_record",
                           "name": "app.example.test", "record_type": "A",
                           "value": "192.0.2.20"}, events)
            self.assertIn({"kind": "hostname", "source": "gobuster_dns",
                           "name": "api.app.example.test",
                           "addresses": ["192.0.2.21"],
                           "wildcard_match": False}, events)
            self.assertEqual("api.app.example.test",
                             result["candidates"][0]["name"])
            self.assertEqual("Found: api.app.example.test [192.0.2.21]\n",
                             (root / "dns" / "gobuster-dns.stdout.txt").read_text())
            self.assertTrue((root / "dns" / "gobuster-dns.json").exists())

    def test_rerun_streams_only_new_gobuster_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wordlist = root / "prefixes.txt"
            wordlist.write_text("new\n", encoding="utf-8")
            marker = root / "rerun-candidate-seen"
            actual_popen = subprocess.Popen

            def fake_run(args, **_kwargs):
                records = (["app.example.test. 300 IN A 192.0.2.20"]
                           if args[1] == "app.example.test" and args[2] == "A" else [])
                return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

            with patch.object(dns.subprocess, "run", side_effect=fake_run):
                previous = dns.run_dns("app.example.test", [], None, root / "old")

            script = (
                "import pathlib, sys, time\n"
                "marker = pathlib.Path(sys.argv[1])\n"
                "print('Found: new.app.example.test [192.0.2.22]', flush=True)\n"
                "for _ in range(100):\n"
                "    if marker.exists(): sys.exit(0)\n"
                "    time.sleep(0.02)\n"
                "sys.exit(3)\n"
            )
            events = []

            def fake_popen(args, **kwargs):
                self.assertEqual("gobuster", args[0])
                return actual_popen([sys.executable, "-u", "-c", script, str(marker)],
                                    **kwargs)

            def candidate(event):
                events.append(event)
                marker.touch()

            with patch.object(dns.subprocess, "Popen", side_effect=fake_popen), \
                    patch.object(dns.subprocess, "run", side_effect=AssertionError("dig repeated")):
                result = dns.rerun_dns_words(previous, "app.example.test", wordlist,
                                             root / "new", on_candidate=candidate)
            self.assertEqual("completed", result["status"])
            self.assertEqual(["new.app.example.test"],
                             [item["name"] for item in result["candidates"]])
            self.assertEqual("gobuster_dns", events[0]["source"])
            self.assertTrue(marker.exists())

    def test_hosts_only_name_marks_dns_unavailable_and_keeps_raw_evidence(self) -> None:
        commands = []

        def fake_run(args, **kwargs):
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, dig_output(status="NXDOMAIN"), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            wordlist = Path(tmp) / "prefixes.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            result = dns.run_dns("app.lab.htb", ["192.0.2.20"], wordlist, Path(tmp))
            self.assertEqual("unavailable", result["status"])
            self.assertEqual("unavailable", result["scanner"]["status"])
            self.assertEqual([], result["candidates"])
            self.assertTrue((Path(tmp) / "dig-a.stdout.txt").exists())
            self.assertTrue((Path(tmp) / "dig-ptr-0.json").exists())
            self.assertFalse(any("AXFR" in command for command in commands))
            self.assertFalse(any("gobuster" == command[0] for command in commands))

    def test_confirmed_exact_zone_axfr_and_prefix_wordlist_with_wildcard_control(self) -> None:
        commands = []

        def fake_run(args, **kwargs):
            commands.append(args)
            if args[0] == "gobuster":
                return subprocess.CompletedProcess(
                    args, 0, "Found: admin.example.test [192.0.2.99]\n"
                    "api.example.test 192.0.2.40\n"
                    "Found: other.invalid [192.0.2.80]\n", "")
            if "AXFR" in args:
                output = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1\n"
                          "dev.example.test. 300 IN A 192.0.2.30\n"
                          "example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1\n"
                          ";; XFR size: 3 records (messages 1, bytes 200)\n")
                return subprocess.CompletedProcess(args, 0, output, "")
            if args[1].startswith("webrecon-"):
                rr = args[2]
                output = dig_output(f"{args[1]}. 300 IN A 192.0.2.99") if rr == "A" else dig_output()
                return subprocess.CompletedProcess(args, 0, output, "")
            if args[1].startswith("@") and args[3] in {"SOA", "NS"}:
                record = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"
                          if args[3] == "SOA" else
                          "example.test. 300 IN NS ns.example.test.")
                output = dig_output(record, aa=True)
                return subprocess.CompletedProcess(args, 0, output, "")
            rr = args[2] if args[1] != "-x" else "PTR"
            records = {
                "A": ["example.test. 300 IN A 192.0.2.20"],
                "SOA": ["example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"],
                "NS": ["example.test. 300 IN NS ns.example.test."],
                "PTR": ["20.2.0.192.in-addr.arpa. 300 IN PTR ptr.example.test."],
            }.get(rr, [])
            # The configured resolver can return a cached SOA without aa.
            return subprocess.CompletedProcess(args, 0, dig_output(*records, aa=rr != "SOA"), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run), \
                patch.object(dns.secrets, "token_hex", return_value="abcdef0123456789"):
            wordlist = Path(tmp) / "prefixes.txt"
            wordlist.write_text("admin\n", encoding="utf-8")
            result = dns.run_dns("example.test", ["192.0.2.20"], wordlist, Path(tmp) / "dns")
            self.assertEqual("completed", result["status"])
            self.assertTrue(result["zone"]["confirmed"])
            self.assertEqual(["ns.example.test"], result["zone"]["nameservers"])
            self.assertEqual(["ns.example.test"], result["zone"]["authoritative_nameservers"])
            self.assertTrue(result["wildcard"]["detected"])
            self.assertIn("dev.example.test", [item["name"] for item in result["candidates"]])
            admin = next(item for item in result["candidates"] if item["name"] == "admin.example.test")
            self.assertEqual("gobuster_dns", admin["source"])
            self.assertTrue(admin["wildcard_match"])
            api = next(item for item in result["candidates"] if item["name"] == "api.example.test")
            self.assertEqual("gobuster_dns", api["source"])
            self.assertEqual(["192.0.2.40"], api["addresses"])
            self.assertIn("ptr.example.test", [item["name"] for item in result["candidates"]])
            self.assertNotIn("other.invalid", [item["name"] for item in result["candidates"]])
            self.assertIn(["dig", "@ns.example.test", "example.test", "AXFR", "+time=3", "+tries=1"], commands)
            self.assertIn(["gobuster", "dns", "--domain", "example.test", "-w", str(wordlist)], commands)

    def test_non_authoritative_soa_does_not_trigger_axfr(self) -> None:
        commands = []

        def fake_run(args, **kwargs):
            commands.append(args)
            rr = args[2] if args[1] != "-x" else "PTR"
            records = {
                "A": ["app.example.test. 300 IN A 192.0.2.20"],
                "SOA": ["app.example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"],
                "NS": ["app.example.test. 300 IN NS ns.example.test."],
            }.get(rr, [])
            return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            result = dns.run_dns("app.example.test", [], None, Path(tmp))
            self.assertEqual("completed", result["status"])
            self.assertFalse(result["zone"]["confirmed"])
            self.assertFalse(any("AXFR" in command for command in commands))

    def test_parent_zone_requires_authoritative_soa_and_ns_and_keeps_wordlist_under_input(self) -> None:
        commands = []

        def fake_run(args, **kwargs):
            commands.append(args)
            if args[0] == "gobuster":
                return subprocess.CompletedProcess(
                    args, 0, "Found: dev.app.example.test [192.0.2.31]\n", "")
            if "AXFR" in args:
                output = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1\n"
                          "app.example.test. 300 IN A 192.0.2.20\n"
                          "admin.example.test. 300 IN A 192.0.2.30\n"
                          "example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1\n"
                          ";; XFR size: 4 records (messages 1, bytes 250)\n")
                return subprocess.CompletedProcess(args, 0, output, "")
            if args[1].startswith("@"):
                rr = args[3]
                record = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"
                          if rr == "SOA" else "example.test. 300 IN NS ns.example.test.")
                return subprocess.CompletedProcess(args, 0, dig_output(record, aa=True), "")
            if args[1] == "example.test":
                rr = args[2]
                record = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"
                          if rr == "SOA" else "example.test. 300 IN NS ns.example.test.")
                return subprocess.CompletedProcess(args, 0, dig_output(record), "")
            records = (["app.example.test. 300 IN A 192.0.2.20"]
                       if args[1] == "app.example.test" and args[2] == "A" else [])
            return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            wordlist = Path(tmp) / "prefixes.txt"
            wordlist.write_text("dev\n", encoding="utf-8")
            result = dns.run_dns("app.example.test", ["192.0.2.20"], wordlist, Path(tmp) / "dns")
            self.assertEqual("completed", result["status"])
            self.assertEqual("example.test", result["zone"]["name"])
            self.assertTrue(result["zone"]["confirmed"])
            self.assertEqual(["ns.example.test"], result["zone"]["authoritative_nameservers"])
            self.assertIn("admin.example.test", [item["name"] for item in result["candidates"]])
            self.assertIn("dev.app.example.test", [item["name"] for item in result["candidates"]])
            self.assertIn(["gobuster", "dns", "--domain", "app.example.test", "-w", str(wordlist)], commands)
            self.assertIn(["dig", "@ns.example.test", "example.test", "AXFR", "+time=3", "+tries=1"], commands)

    def test_parent_zone_without_authoritative_ns_answer_skips_axfr(self) -> None:
        commands = []

        def fake_run(args, **kwargs):
            commands.append(args)
            if args[1].startswith("@"):
                rr = args[3]
                record = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"
                          if rr == "SOA" else "example.test. 300 IN NS ns.example.test.")
                return subprocess.CompletedProcess(args, 0,
                                                   dig_output(record, aa=rr == "SOA"), "")
            if args[1] == "example.test":
                record = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"
                          if args[2] == "SOA" else "example.test. 300 IN NS ns.example.test.")
                return subprocess.CompletedProcess(args, 0, dig_output(record), "")
            records = (["app.example.test. 300 IN A 192.0.2.20"]
                       if args[1] == "app.example.test" and args[2] == "A" else [])
            return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            result = dns.run_dns("app.example.test", [], None, Path(tmp))
            self.assertEqual("completed", result["status"])
            self.assertFalse(result["zone"]["confirmed"])
            self.assertFalse(any("AXFR" in command for command in commands))

    def test_parent_lookup_stops_before_tld_and_after_five_levels(self) -> None:
        commands = []

        def fake_run(args, **kwargs):
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, dig_output(status="NXDOMAIN"), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            result = dns.run_dns("a.b.c.d.e.f.g.example.test", [], None, Path(tmp))
            self.assertEqual("unavailable", result["status"])
            self.assertEqual(6, len(result["checked_zones"]))
            self.assertTrue(all(name["name"].count(".") >= 1
                                for name in result["checked_zones"]))

    def test_requested_gobuster_failure_marks_dns_partial(self) -> None:
        def fake_run(args, **kwargs):
            if args[0] == "gobuster":
                return subprocess.CompletedProcess(args, 2, "", "resolver failed\n")
            records = (["app.example.test. 300 IN A 192.0.2.20"]
                       if args[1] == "app.example.test" and args[2] == "A" else [])
            return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            wordlist = Path(tmp) / "prefixes.txt"
            wordlist.write_text("dev\n", encoding="utf-8")
            result = dns.run_dns("app.example.test", [], wordlist, Path(tmp) / "dns")
            self.assertEqual("partial", result["status"])
            self.assertEqual("error", result["scanner"]["status"])
            self.assertEqual([], result["required_failures"])
            self.assertIn("resolver failed", (Path(tmp) / "dns" / "gobuster-dns.stderr.txt").read_text())

    def test_required_dig_failure_marks_dns_partial(self) -> None:
        def fake_run(args, **kwargs):
            if args[1] == "app.example.test" and args[2] == "TXT":
                return subprocess.CompletedProcess(args, 9, "", "query timed out\n")
            records = (["app.example.test. 300 IN A 192.0.2.20"]
                       if args[1] == "app.example.test" and args[2] == "A" else [])
            return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            result = dns.run_dns("app.example.test", [], None, Path(tmp))
            self.assertEqual("partial", result["status"])
            self.assertEqual(["dig-txt"], result["required_failures"])

    def test_no_usable_dns_and_dig_subprocess_failures_is_error(self) -> None:
        def fake_run(args, **kwargs):
            raise FileNotFoundError("dig is unavailable")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            result = dns.run_dns("app.lab.htb", [], None, Path(tmp))
            self.assertEqual("error", result["status"])
            self.assertIn("dig-a", result["required_failures"])
            self.assertTrue((Path(tmp) / "dig-a.stderr.txt").exists())

    def test_axfr_refusal_alone_keeps_dns_completed(self) -> None:
        def fake_run(args, **kwargs):
            if "AXFR" in args:
                return subprocess.CompletedProcess(args, 9, "", "Transfer failed.\n")
            if args[1].startswith("@"):
                rr = args[3]
                record = ("example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"
                          if rr == "SOA" else "example.test. 300 IN NS ns.example.test.")
                return subprocess.CompletedProcess(args, 0, dig_output(record, aa=True), "")
            records = {
                "A": ["example.test. 300 IN A 192.0.2.20"],
                "SOA": ["example.test. 300 IN SOA ns.example.test. hostmaster.example.test. 1 1 1 1 1"],
                "NS": ["example.test. 300 IN NS ns.example.test."],
            }.get(args[2], []) if args[1] == "example.test" else []
            return subprocess.CompletedProcess(args, 0, dig_output(*records), "")

        with tempfile.TemporaryDirectory() as tmp, patch.object(dns.subprocess, "run", fake_run):
            result = dns.run_dns("example.test", [], None, Path(tmp))
            self.assertEqual("completed", result["status"])
            self.assertEqual([], result["required_failures"])
            axfr = next(query for query in result["queries"] if "AXFR" in query["command"])
            self.assertEqual("error", axfr["status"])


if __name__ == "__main__":
    unittest.main()
