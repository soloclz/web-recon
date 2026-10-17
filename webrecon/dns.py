"""DNS evidence collection for one explicitly supplied hostname.

This module does not use the operating system's hosts file as a DNS source.
The caller can continue its Web work when the configured DNS resolver cannot
answer for a hostname that the operating system resolves through hosts.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import secrets
import subprocess
import threading
from pathlib import Path
from typing import Callable


RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SOA", "NS")
_HOST_RE = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_DIG_STATUS_RE = re.compile(r"\bstatus:\s*([A-Z]+)")
_GOBUSTER_FOUND_RE = re.compile(
    r"^\s*(?:Found:\s+)?(\S+)(?:\s+(?:\[([^\]]+)\]|(\S+)))?\s*$", re.I
)
_RR_RE = re.compile(r"^(\S+)\s+(\d+)\s+(IN|CH|HS)\s+([A-Z0-9]+)\s+(.+)$", re.I)


def _name(value: str) -> str:
    """Return an ASCII DNS hostname, without a final root dot."""
    value = value.rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    if not _HOST_RE.fullmatch(value):
        raise ValueError("invalid hostname")
    return value


def _write_command(out_dir: Path, stem: str, args: list[str], timeout: int,
                   on_stdout_line: Callable[[str], None] | None = None) -> dict:
    stdout_path = out_dir / f"{stem}.stdout.txt"
    stderr_path = out_dir / f"{stem}.stderr.txt"
    meta_path = out_dir / f"{stem}.json"
    result: dict = {"command": args, "returncode": None, "timed_out": False,
                    "stdout": str(stdout_path), "stderr": str(stderr_path),
                    "meta": str(meta_path)}
    try:
        if on_stdout_line is None:
            completed = subprocess.run(args, capture_output=True, text=True,
                                       errors="replace", timeout=timeout, check=False)
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            result["returncode"] = completed.returncode
        else:
            expired = threading.Event()
            callback_error = None
            with stdout_path.open("w", encoding="utf-8") as stdout_file, \
                    stderr_path.open("w", encoding="utf-8") as stderr_file:
                process = subprocess.Popen(args, stdout=subprocess.PIPE,
                                           stderr=stderr_file, text=True,
                                           errors="replace", bufsize=1)

                def stop_on_timeout() -> None:
                    if process.poll() is None:
                        expired.set()
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass

                timer = threading.Timer(timeout, stop_on_timeout)
                timer.daemon = True
                timer.start()
                try:
                    assert process.stdout is not None
                    for line in process.stdout:
                        stdout_file.write(line)
                        stdout_file.flush()
                        try:
                            on_stdout_line(line)
                        except Exception as exc:
                            callback_error = f"{type(exc).__name__}: {exc}"
                            process.kill()
                            break
                    result["returncode"] = process.wait()
                finally:
                    timer.cancel()
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    if process.stdout is not None:
                        process.stdout.close()
            stdout = stdout_path.read_text(encoding="utf-8")
            stderr = stderr_path.read_text(encoding="utf-8")
            result["timed_out"] = expired.is_set()
            if callback_error is not None:
                result["callback_error"] = callback_error
                stderr += f"\nCandidate callback failed: {callback_error}\n"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        result["timed_out"] = True
        stderr += f"\nCommand timed out after {timeout} seconds.\n"
    except OSError as exc:
        stdout = ""
        stderr = f"{type(exc).__name__}: {exc}\n"
    result["status"] = ("timeout" if result["timed_out"] else
                        "completed" if result["returncode"] == 0 and
                        "callback_error" not in result else "error")
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    meta_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    result["output"] = stdout
    return result


def _parse_dig(output: str) -> dict:
    """Extract answer records while retaining the unmodified dig text on disk."""
    match = _DIG_STATUS_RE.search(output)
    is_axfr = "XFR size:" in output
    flags = set()
    answers: list[dict] = []
    section = None
    for line in output.splitlines():
        if line.startswith(";; flags:"):
            flags_match = re.search(r";; flags:\s*([^;]+);", line)
            if flags_match:
                flags = set(flags_match.group(1).split())
        if line == ";; ANSWER SECTION:":
            section = "answer"
            continue
        if line.startswith(";; ") and line.endswith(" SECTION:"):
            section = None
            continue
        if line.startswith(";;") or line.startswith(";") or not line.strip():
            continue
        # AXFR output omits the normal ANSWER SECTION heading. Its records
        # appear as plain RR lines, so the parser accepts them everywhere.
        rr = _RR_RE.match(line)
        if rr and (section == "answer" or is_axfr):
            owner, ttl, rr_class, rr_type, data = rr.groups()
            answers.append({"name": owner.rstrip(".").lower(), "ttl": int(ttl),
                            "class": rr_class.upper(), "type": rr_type.upper(),
                            "data": data.strip()})
    return {"status": match.group(1) if match else None,
            "authoritative": "aa" in flags, "answers": answers}


def _rr_data(parsed: dict, owner: str, rr_type: str) -> list[str]:
    return [rr["data"] for rr in parsed["answers"]
            if rr["name"] == owner and rr["type"] == rr_type]


def _add_candidate(candidates: dict[str, dict], name: str, source: str,
                   on_candidate: Callable[[dict], None] | None = None,
                   **details: object) -> None:
    try:
        name = _name(name)
    except ValueError:
        return
    is_new = name not in candidates
    candidate = candidates.setdefault(name, {"name": name, "source": source})
    newly_sourced = is_new
    if candidate["source"] != source:
        sources = candidate.setdefault("other_sources", [])
        newly_sourced = source not in sources
        if newly_sourced:
            sources.append(source)
    candidate.update(details)
    if newly_sourced and on_candidate is not None:
        on_candidate({"kind": "hostname", "source": source, "name": name,
                      **details})


def _read_gobuster_line(line: str, host: str, wildcard_addresses: set[str],
                        candidates: dict[str, dict],
                        on_candidate: Callable[[dict], None] | None) -> None:
    found = _GOBUSTER_FOUND_RE.match(line)
    if not found:
        return
    found_name = found.group(1).rstrip(".").lower()
    if not found_name.endswith(f".{host}"):
        return
    address_text = found.group(2) or found.group(3) or ""
    addresses = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{2,}",
                           address_text, re.I)
    candidate_addresses = []
    for address in addresses:
        try:
            candidate_addresses.append(str(ipaddress.ip_address(address)))
        except ValueError:
            pass
    _add_candidate(candidates, found_name, "gobuster_dns", on_candidate,
                   addresses=candidate_addresses,
                   wildcard_match=bool(candidate_addresses and
                                       set(candidate_addresses) == wildcard_addresses))


def run_dns(host: str, ips: list[str], prefix_wordlist: Path | None,
            out_dir: Path,
            on_candidate: Callable[[dict], None] | None = None) -> dict:
    """Query records, PTR, wildcard, confirmed-zone AXFR, and optional DNS words.

    Every subprocess receives an argument array. Parent names are checked only
    for a confirmed zone; wordlist prefixes stay under the supplied hostname.
    No Web address is used as a DNS server. Candidates remain unverified leads.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"status": "error", "records": {}, "candidates": [],
                    "artifacts": [], "diagnostics": [], "queries": [],
                    "required_failures": [],
                    "wildcard": {"name": None, "addresses": [], "aliases": [],
                                 "detected": False},
                    "zone": {"name": None, "confirmed": False,
                             "nameservers": [], "authoritative_nameservers": []},
                    "checked_zones": [],
                    "scanner": {"status": "not_run"}}
    try:
        host = _name(host)
    except ValueError as exc:
        result["diagnostics"].append(str(exc))
        return result

    candidates: dict[str, dict] = {}
    emitted_records: set[tuple[str, str, str]] = set()

    def execute(stem: str, args: list[str], timeout: int = 12,
                on_stdout_line: Callable[[str], None] | None = None) -> dict:
        run = _write_command(out_dir, stem, args, timeout, on_stdout_line)
        result["queries"].append({key: value for key, value in run.items()
                                  if key != "output"})
        result["artifacts"].extend([run["stdout"], run["stderr"], run["meta"]])
        if (on_candidate is not None and args[0] == "dig" and
                not stem.startswith("dig-wildcard-")):
            for rr in _parse_dig(run["output"])["answers"]:
                key = (rr["name"], rr["type"], rr["data"])
                if key not in emitted_records:
                    emitted_records.add(key)
                    on_candidate({"kind": "dns_record", "source": "dns_record",
                                  "name": rr["name"], "record_type": rr["type"],
                                  "value": rr["data"]})
        if run["returncode"] is None or run["returncode"] != 0:
            result["diagnostics"].append(
                f"{stem}: timeout" if run["timed_out"] else
                f"{stem}: exit {run['returncode']}; see stderr")
            if args[0] == "dig" and "AXFR" not in args:
                result["required_failures"].append(stem)
        return run

    parsed_by_type = {}
    for rr_type in RECORD_TYPES:
        run = execute(f"dig-{rr_type.lower()}",
                      ["dig", host, rr_type, "+time=3", "+tries=1"])
        parsed = _parse_dig(run["output"])
        parsed_by_type[rr_type] = parsed
        result["records"][rr_type] = _rr_data(parsed, host, rr_type)
        if parsed["status"] in {"SERVFAIL", "REFUSED"}:
            result["diagnostics"].append(f"dig {rr_type}: {parsed['status']}")

    for index, ip_text in enumerate(dict.fromkeys(ips)):
        try:
            ip = str(ipaddress.ip_address(ip_text))
        except ValueError:
            result["diagnostics"].append(f"invalid resolved IP: {ip_text}")
            continue
        run = execute(f"dig-ptr-{index}",
                      ["dig", "-x", ip, "+time=3", "+tries=1"])
        parsed = _parse_dig(run["output"])
        for rr in parsed["answers"]:
            if rr["type"] == "PTR":
                _add_candidate(candidates, rr["data"], "dns_ptr", on_candidate)

    usable = any(parsed["status"] == "NOERROR" and
                 any(rr["name"] == host for rr in parsed["answers"])
                 for parsed in parsed_by_type.values())

    # A normal recursive answer for app.example.test has no app SOA. Check its
    # ancestors, closest first, but stop before the TLD and after five parents.
    labels = host.split(".")
    zone_names = [host] + [".".join(labels[level:])
                           for level in range(1, min(len(labels) - 1, 6))]
    for level, zone_name in enumerate(zone_names):
        if level == 0:
            zone_soa = parsed_by_type["SOA"]
            zone_ns = parsed_by_type["NS"]
        else:
            zone_soa = _parse_dig(execute(
                f"dig-zone-{level}-soa",
                ["dig", zone_name, "SOA", "+time=3", "+tries=1"])["output"])
            zone_ns = _parse_dig(execute(
                f"dig-zone-{level}-ns",
                ["dig", zone_name, "NS", "+time=3", "+tries=1"])["output"])
        exact_soa = zone_soa["status"] == "NOERROR" and bool(
            _rr_data(zone_soa, zone_name, "SOA"))
        nameservers = []
        if zone_ns["status"] == "NOERROR":
            for entry in _rr_data(zone_ns, zone_name, "NS"):
                try:
                    nameservers.append(_name(entry.split()[0]))
                except ValueError:
                    result["diagnostics"].append(
                        f"{zone_name}: invalid NS record: {entry}")
        nameservers = list(dict.fromkeys(nameservers))
        authoritative_ns = []
        if exact_soa:
            for ns_index, nameserver in enumerate(nameservers):
                ns_soa = _parse_dig(execute(
                    f"dig-zone-{level}-ns-{ns_index}-soa",
                    ["dig", f"@{nameserver}", zone_name, "SOA", "+norecurse",
                     "+time=3", "+tries=1"])["output"])
                ns_ns = _parse_dig(execute(
                    f"dig-zone-{level}-ns-{ns_index}-ns",
                    ["dig", f"@{nameserver}", zone_name, "NS", "+norecurse",
                     "+time=3", "+tries=1"])["output"])
                if (ns_soa["status"] == "NOERROR" and ns_soa["authoritative"]
                        and _rr_data(ns_soa, zone_name, "SOA")
                        and ns_ns["status"] == "NOERROR" and ns_ns["authoritative"]
                        and _rr_data(ns_ns, zone_name, "NS")):
                    authoritative_ns.append(nameserver)
        result["checked_zones"].append(
            {"name": zone_name, "exact_soa": exact_soa,
             "nameservers": nameservers,
             "authoritative_nameservers": authoritative_ns})
        if authoritative_ns:
            result["zone"] = {"name": zone_name, "confirmed": True,
                              "nameservers": nameservers,
                              "authoritative_nameservers": authoritative_ns}
            break

    if not usable and not result["zone"]["confirmed"]:
        result["status"] = "error" if result["required_failures"] else "unavailable"
        if prefix_wordlist is not None:
            result["scanner"] = {
                "status": "error" if result["required_failures"] else "unavailable",
                "reason": "DNS checks failed" if result["required_failures"] else
                          "no input record or confirmed DNS zone"}
        result["diagnostics"].append(
            "configured DNS resolver did not return an input record or confirmed zone")
        result["candidates"] = list(candidates.values())
        return result

    # A random sibling establishes whether ordinary address hits could be a
    # wildcard DNS answer. Its name is deliberately not a candidate.
    wildcard_name = f"webrecon-{secrets.token_hex(8)}.{host}"
    result["wildcard"]["name"] = wildcard_name
    wildcard_addresses: set[str] = set()
    wildcard_aliases: set[str] = set()
    for rr_type in ("A", "AAAA", "CNAME"):
        run = execute(f"dig-wildcard-{rr_type.lower()}",
                      ["dig", wildcard_name, rr_type, "+time=3", "+tries=1"])
        parsed = _parse_dig(run["output"])
        if rr_type == "CNAME":
            wildcard_aliases.update(_rr_data(parsed, wildcard_name, rr_type))
        else:
            wildcard_addresses.update(_rr_data(parsed, wildcard_name, rr_type))
    result["wildcard"]["addresses"] = sorted(wildcard_addresses)
    result["wildcard"]["aliases"] = sorted(wildcard_aliases)
    result["wildcard"]["detected"] = bool(wildcard_addresses or wildcard_aliases)

    if result["zone"]["confirmed"]:
        zone_name = result["zone"]["name"]
        for index, nameserver in enumerate(result["zone"]["authoritative_nameservers"]):
            run = execute(f"dig-axfr-{index}",
                          ["dig", f"@{nameserver}", zone_name, "AXFR",
                           "+time=3", "+tries=1"], timeout=30)
            if "XFR size:" not in run["output"]:
                continue
            for rr in _parse_dig(run["output"])["answers"]:
                owner = rr["name"]
                if owner != host and owner != zone_name and owner.endswith(f".{zone_name}"):
                    _add_candidate(candidates, owner, "dns_axfr", on_candidate)

    if prefix_wordlist is not None:
        prefix_wordlist = Path(prefix_wordlist)
        if not prefix_wordlist.is_file():
            result["diagnostics"].append(
                f"gobuster wordlist not found: {prefix_wordlist}")
            result["scanner"] = {"status": "error", "reason": "wordlist not found"}
        else:
            def found_line(line: str) -> None:
                _read_gobuster_line(line, host, wildcard_addresses,
                                    candidates, on_candidate)

            run = execute("gobuster-dns", ["gobuster", "dns", "--domain", host,
                                           "-w", str(prefix_wordlist)], timeout=600,
                          on_stdout_line=found_line if on_candidate else None)
            result["scanner"] = {"status": run["status"],
                                 "command": run["command"],
                                 "stdout": run["stdout"], "stderr": run["stderr"]}
            if on_candidate is None:
                for line in run["output"].splitlines():
                    found_line(line)

    result["candidates"] = list(candidates.values())
    scanner_failed = (prefix_wordlist is not None and
                      result["scanner"]["status"] != "completed")
    result["status"] = "partial" if result["required_failures"] or scanner_failed else "completed"
    return result


def rerun_dns_words(previous_dns: dict, host: str, prefix_wordlist: Path | None,
                    out_dir: Path,
                    on_candidate: Callable[[dict], None] | None = None) -> dict:
    """Replace only the Gobuster stage in a saved DNS result; never call dig.

    Fixed DNS queries, their artifacts, and PTR/AXFR candidates stay in the
    result. The caller must keep those referenced artifacts available and use a
    new output directory for this attempt's Gobuster artifacts.
    """
    host = _name(host)
    if not isinstance(previous_dns, dict) or not all(
        key in previous_dns for key in ("records", "zone", "candidates", "queries",
                                  "artifacts", "diagnostics", "required_failures", "wildcard")
    ):
        raise ValueError("previous DNS result is incomplete")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = copy.deepcopy(previous_dns)

    # A fixed source may also have found a name that Gobuster found. In that
    # case keep the fixed candidate, but remove the old scanner's annotations.
    fixed_candidates: dict[str, dict] = {}
    for item in result["candidates"]:
        if item.get("source") == "gobuster_dns":
            continue
        candidate = item.copy()
        other_sources = [source for source in candidate.get("other_sources", [])
                         if source != "gobuster_dns"]
        if other_sources:
            candidate["other_sources"] = other_sources
        else:
            candidate.pop("other_sources", None)
        if "gobuster_dns" in item.get("other_sources", []):
            candidate.pop("addresses", None)
            candidate.pop("wildcard_match", None)
        fixed_candidates[candidate["name"]] = candidate

    old_scanner_artifacts = set()
    fixed_queries = []
    for query in result["queries"]:
        command = query.get("command") or []
        if command and command[0] == "gobuster":
            old_scanner_artifacts.update(query.get(key) for key in ("stdout", "stderr", "meta"))
        else:
            fixed_queries.append(query)
    old_scanner = result.get("scanner", {})
    old_scanner_artifacts.update(old_scanner.get(key) for key in ("stdout", "stderr"))
    old_scanner_names = {Path(path).name for path in old_scanner_artifacts if path}
    result["queries"] = fixed_queries
    result["artifacts"] = [path for path in result["artifacts"]
                           if path not in old_scanner_artifacts and Path(path).name not in old_scanner_names]
    result["diagnostics"] = [line for line in result["diagnostics"]
                             if not line.startswith(("gobuster-dns:", "gobuster wordlist not found:"))]
    result["scanner"] = {"status": "not_run"}

    # run_dns stops before Gobuster if no input record or confirmed zone was
    # found. The saved records contain only records owned by the input host.
    usable = any(result["records"].get(rr_type) for rr_type in RECORD_TYPES)
    if not usable and not result["zone"].get("confirmed", False):
        result["status"] = "error" if result["required_failures"] else "unavailable"
        if prefix_wordlist is not None:
            result["scanner"] = {
                "status": "error" if result["required_failures"] else "unavailable",
                "reason": "DNS checks failed" if result["required_failures"] else
                          "no input record or confirmed DNS zone"}
        result["candidates"] = list(fixed_candidates.values())
        return result

    if prefix_wordlist is not None:
        prefix_wordlist = Path(prefix_wordlist)
        if not prefix_wordlist.is_file():
            result["diagnostics"].append(f"gobuster wordlist not found: {prefix_wordlist}")
            result["scanner"] = {"status": "error", "reason": "wordlist not found"}
        else:
            if any((out_dir / f"gobuster-dns.{suffix}").exists()
                   for suffix in ("stdout.txt", "stderr.txt", "json")):
                raise FileExistsError(f"Gobuster artifacts already exist in {out_dir}")
            wildcard_addresses = set(result["wildcard"].get("addresses", []))

            def found_line(line: str) -> None:
                _read_gobuster_line(line, host, wildcard_addresses,
                                    fixed_candidates, on_candidate)

            run = _write_command(out_dir, "gobuster-dns",
                                 ["gobuster", "dns", "--domain", host,
                                  "-w", str(prefix_wordlist)], 600,
                                 on_stdout_line=found_line if on_candidate else None)
            result["queries"].append({key: value for key, value in run.items()
                                      if key != "output"})
            result["artifacts"].extend([run["stdout"], run["stderr"], run["meta"]])
            if run["returncode"] is None or run["returncode"] != 0:
                result["diagnostics"].append(
                    "gobuster-dns: timeout" if run["timed_out"] else
                    f"gobuster-dns: exit {run['returncode']}; see stderr")
            result["scanner"] = {"status": run["status"],
                                 "command": run["command"],
                                 "stdout": run["stdout"], "stderr": run["stderr"]}
            if on_candidate is None:
                for line in run["output"].splitlines():
                    found_line(line)

    result["candidates"] = list(fixed_candidates.values())
    scanner_failed = (prefix_wordlist is not None and result["scanner"]["status"] != "completed")
    result["status"] = "partial" if result["required_failures"] or scanner_failed else "completed"
    return result
