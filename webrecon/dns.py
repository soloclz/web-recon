"""DNS evidence collection for one explicitly supplied hostname.

This module does not use the operating system's hosts file as a DNS source.
The caller can continue its Web work when the configured DNS resolver cannot
answer for a hostname that the operating system resolves through hosts.
"""

from __future__ import annotations

import ipaddress
import json
import re
import secrets
import subprocess
from pathlib import Path


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


def _write_command(out_dir: Path, stem: str, args: list[str], timeout: int) -> dict:
    stdout_path = out_dir / f"{stem}.stdout.txt"
    stderr_path = out_dir / f"{stem}.stderr.txt"
    meta_path = out_dir / f"{stem}.json"
    result: dict = {"command": args, "returncode": None, "timed_out": False,
                    "stdout": str(stdout_path), "stderr": str(stderr_path),
                    "meta": str(meta_path)}
    try:
        completed = subprocess.run(args, capture_output=True, text=True,
                                   errors="replace", timeout=timeout, check=False)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        result["returncode"] = completed.returncode
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
                        "completed" if result["returncode"] == 0 else "error")
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
                   **details: object) -> None:
    try:
        name = _name(name)
    except ValueError:
        return
    candidate = candidates.setdefault(name, {"name": name, "source": source})
    if candidate["source"] != source:
        candidate.setdefault("other_sources", []).append(source)
    candidate.update(details)


def run_dns(host: str, ips: list[str], prefix_wordlist: Path | None,
            out_dir: Path) -> dict:
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

    def execute(stem: str, args: list[str], timeout: int = 12) -> dict:
        run = _write_command(out_dir, stem, args, timeout)
        result["queries"].append({key: value for key, value in run.items()
                                  if key != "output"})
        result["artifacts"].extend([run["stdout"], run["stderr"], run["meta"]])
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
                _add_candidate(candidates, rr["data"], "dns_ptr")

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
                    _add_candidate(candidates, owner, "dns_axfr")

    if prefix_wordlist is not None:
        prefix_wordlist = Path(prefix_wordlist)
        if not prefix_wordlist.is_file():
            result["diagnostics"].append(
                f"gobuster wordlist not found: {prefix_wordlist}")
            result["scanner"] = {"status": "error", "reason": "wordlist not found"}
        else:
            run = execute("gobuster-dns", ["gobuster", "dns", "--domain", host,
                                           "-w", str(prefix_wordlist)], timeout=600)
            result["scanner"] = {"status": run["status"],
                                 "command": run["command"],
                                 "stdout": run["stdout"], "stderr": run["stderr"]}
            for line in run["output"].splitlines():
                found = _GOBUSTER_FOUND_RE.match(line)
                if not found:
                    continue
                found_name = found.group(1).rstrip(".").lower()
                if not found_name.endswith(f".{host}"):
                    continue
                address_text = found.group(2) or found.group(3) or ""
                addresses = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{2,}",
                                       address_text, re.I)
                candidate_addresses = []
                for address in addresses:
                    try:
                        candidate_addresses.append(str(ipaddress.ip_address(address)))
                    except ValueError:
                        pass
                _add_candidate(candidates, found_name, "gobuster_dns",
                               addresses=candidate_addresses,
                               wildcard_match=bool(candidate_addresses and
                                                   set(candidate_addresses) ==
                                                   wildcard_addresses))

    result["candidates"] = list(candidates.values())
    scanner_failed = (prefix_wordlist is not None and
                      result["scanner"]["status"] != "completed")
    result["status"] = "partial" if result["required_failures"] or scanner_failed else "completed"
    return result
