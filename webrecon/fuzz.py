"""Bounded ffuf scans for virtual hosts, paths, and file extensions.

The scanner's JSON is evidence, not a list of confirmed resources.  Each
stage saves its output and compares hits with two deliberately missing
requests.  ffuf's own auto-calibration supplies an additional filter.
"""

from __future__ import annotations

import http.client
import json
import math
import re
import secrets
import shutil
import ssl
import subprocess
import time
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlsplit


TIMEOUT_ESTIMATED_RATE = 20
TIMEOUT = 60 * 60
BODY_LIMIT = 1024 * 1024
MAX_BASENAMES = 25
_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_FFUF_PROGRESS = re.compile(rb":: Progress: \[(\d+)/(\d+)\]")


def _scan_timeout(wordlist: Path, rate: int | None = None) -> float:
    """Allow a wordlist enough time; an estimate does not limit ffuf speed."""
    with wordlist.open("rb") as source:
        entries = sum(1 for line in source if line.strip() and not line.lstrip().startswith(b"#"))
    return max(TIMEOUT, math.ceil(entries / (TIMEOUT_ESTIMATED_RATE if rate is None else rate) * 1.5))


def _progress_with_target(
    progress: Callable[[str, int, int], None] | None, target: str
) -> Callable[[str, int, int], None] | None:
    if progress is None:
        return None

    def report(scan: str, current: int, total: int) -> None:
        progress(f"{scan}:{target}", current, total)

    return report


def _report(status: str, **more: object) -> dict:
    return {"status": status, "candidates": [], "uncertain_hits": [], "artifacts": [], "diagnostics": [], **more}


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
        raise ValueError("origin must be an HTTP(S) scheme, hostname, and optional port")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("origin must not contain credentials, query, or fragment")
    return value.rstrip("/")


def _probe(origin: str, path: str, host_header: str | None = None) -> dict:
    """Make one non-following request; a private CA must not block lab baselines."""
    parsed = urlsplit(origin)
    conn_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": 10}
    if parsed.scheme == "https":
        kwargs["context"] = ssl._create_unverified_context()
    conn = conn_type(parsed.hostname, parsed.port, **kwargs)
    headers = {"User-Agent": "web-recon/1.0"}
    if host_header:
        headers["Host"] = host_header
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        body = response.read(BODY_LIMIT + 1)
        bounded = body[:BODY_LIMIT]
        header_pairs = response.getheaders()
        return {
            "status": response.status,
            "length": len(body) if len(body) <= BODY_LIMIT else None,
            "words": len(bounded.split()),
            "lines": len(bounded.splitlines()),
            "truncated": len(body) > BODY_LIMIT,
            "headers": header_pairs,
            "body": bounded,
        }
    finally:
        conn.close()


def _save_controls(
    origin: str, out_dir: Path, kind: str, host: str | None = None, path_suffix: str = ""
) -> tuple[list[dict], list[str], list[str]]:
    controls: list[dict] = []
    artifacts: list[str] = []
    diagnostics: list[str] = []
    for index, suffix in enumerate((secrets.token_hex(5), secrets.token_hex(8)), 1):
        marker = f"webrecon-missing-{suffix}"
        target = f"{marker}.{host}" if kind == "vhost" else f"/{marker}{path_suffix}"
        try:
            raw = _probe(origin, "/" if kind == "vhost" else target, target if kind == "vhost" else None)
        except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
            diagnostics.append(f"{kind} control {index}: {type(exc).__name__}: {exc}")
            continue
        body = raw.pop("body")
        body_path = out_dir / f"{kind}-control-{index}.body"
        meta_path = out_dir / f"{kind}-control-{index}.json"
        body_path.write_bytes(body)
        record = {"request": target, **raw}
        meta_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        controls.append(record)
        artifacts.extend((str(meta_path), str(body_path)))
    return controls, artifacts, diagnostics


def _normalize_controls(baseline: dict | None) -> list[dict]:
    if not baseline:
        return []
    probes = baseline.get("probes") or baseline.get("controls")
    if isinstance(probes, list):
        return [p for p in probes if isinstance(p, dict) and _signature(p) is not None]
    return [baseline] if _signature(baseline) is not None else []


def _signature(record: dict) -> tuple[int, int, int, int] | None:
    try:
        values = (
            int(record.get("status", record.get("status_code"))),
            int(record.get("length", record.get("size"))),
            int(record["words"]),
            int(record["lines"]),
        )
    except (ValueError, TypeError, KeyError):
        return None
    return values


def _assessment(hit: dict, controls: list[dict]) -> str:
    hit_sig = _signature(hit)
    controls_sigs = [_signature(p) for p in controls]
    controls_sigs = [s for s in controls_sigs if s is not None]
    if hit_sig is None or not controls_sigs:
        return "baseline_unavailable"
    if hit_sig in controls_sigs:
        return "matches_missing_baseline"
    return "different_from_missing_baseline"


def _stable_control_pair(controls: list[dict]) -> bool:
    if len(controls) != 2:
        return False
    first, second = (_signature(item) for item in controls)
    return first is not None and first == second


def _strict_assessment(hit: dict, controls: list[dict]) -> str:
    if len(controls) != 2 or any(_signature(item) is None for item in controls):
        return "baseline_unavailable"
    if not _stable_control_pair(controls):
        return "unstable_missing_baseline"
    if _signature(hit) is None:
        return "result_metrics_unavailable"
    return _assessment(hit, controls)


def _extension_assessment(hit: dict, controls: list[dict]) -> str:
    """Only a stable pair of matching-extension misses can confirm a hit."""
    if len(controls) != 2:
        return "extension_baseline_unavailable"
    if any(_signature(item) is None for item in controls):
        return "extension_baseline_unavailable"
    if not _stable_control_pair(controls):
        return "unstable_extension_baseline"
    return _assessment(hit, controls)


def _run_with_progress(
    args: list[str], name: str, stdout: Path, stderr: Path,
    progress: Callable[[str, int, int], None],
    timeout: float,
) -> tuple[int | None, bool]:
    """Keep ffuf's raw streams and report the latest counter while it runs."""
    timed_out = False
    with stdout.open("wb") as stdout_file, stderr.open("wb") as stderr_file:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout_file, stderr=stderr_file)
        try:
            with stderr.open("rb") as progress_file:
                deadline = time.monotonic() + timeout
                tail = b""
                last_count: tuple[int, int] | None = None
                while True:
                    remaining = deadline - time.monotonic()
                    if process.poll() is None and remaining > 0:
                        try:
                            process.wait(timeout=min(0.25, remaining))
                        except subprocess.TimeoutExpired:
                            pass
                    elif process.poll() is None:
                        process.kill()
                        process.wait()
                        timed_out = True
                    chunk = progress_file.read()
                    if chunk:
                        data = tail + chunk
                        matches = _FFUF_PROGRESS.findall(data)
                        if matches:
                            count = tuple(map(int, matches[-1]))
                            if count != last_count:
                                progress(name, *count)
                                last_count = count
                        tail = data[-64:]
                    if process.poll() is not None:
                        break
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return (None if timed_out else process.returncode), timed_out


def _scan(
    out_dir: Path, name: str, wordlist: Path, url: str, *,
    host_header: str | None = None,
    progress: Callable[[str, int, int], None] | None = None,
    rate: int | None = None,
) -> tuple[list[dict], list[str], list[str], str]:
    output = out_dir / f"{name}.json"
    stdout = out_dir / f"{name}.stdout"
    stderr = out_dir / f"{name}.stderr"
    status_path = out_dir / f"{name}.status.json"
    args = ["ffuf", "-ic", "-w", f"{wordlist}:FUZZ", "-u", url]
    if urlsplit(url).scheme == "https":
        args.append("-k")
    if host_header:
        args += ["-H", f"Host: {host_header}"]
    if rate is not None and rate < 1:
        raise ValueError("ffuf rate must be positive")
    args += ["-mc", "all", "-ac"]
    if rate is not None:
        args += ["-rate", str(rate)]
    args += ["-of", "json", "-o", str(output)]
    artifacts = [str(stdout), str(stderr), str(status_path)]
    diagnostics: list[str] = []
    try:
        timeout = _scan_timeout(wordlist, rate)
        if progress is None:
            completed = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False)
            stdout.write_bytes(completed.stdout)
            stderr.write_bytes(completed.stderr)
            returncode = completed.returncode
        else:
            returncode, timed_out = _run_with_progress(args, name, stdout, stderr, progress, timeout)
            if timed_out:
                diagnostics.append(f"{name}: ffuf timed out after {timeout:g} seconds")
    except OSError as exc:
        stdout.write_bytes(b"")
        stderr.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        status_path.write_text(json.dumps({"argv": args, "returncode": None, "start_error": str(exc)}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        diagnostics.append(f"{name}: failed to start ffuf: {type(exc).__name__}: {exc}")
        return [], artifacts, diagnostics, "unavailable" if isinstance(exc, FileNotFoundError) else "error"
    except subprocess.TimeoutExpired as exc:
        stdout.write_bytes(exc.stdout or b"")
        stderr.write_bytes(exc.stderr or b"")
        returncode = None
        diagnostics.append(f"{name}: ffuf timed out after {timeout:g} seconds")
    status_path.write_text(json.dumps({"argv": args, "returncode": returncode,
                                       "timeout_seconds": timeout}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not output.exists():
        diagnostics.append(f"{name}: ffuf did not write JSON output")
        return [], artifacts, diagnostics, "error"
    artifacts.append(str(output))
    try:
        parsed = json.loads(output.read_text(encoding="utf-8"))
        hits = parsed["results"]
        if not isinstance(hits, list) or any(not isinstance(hit, dict) for hit in hits):
            raise ValueError("results is not a list of objects")
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        diagnostics.append(f"{name}: invalid ffuf JSON: {exc}")
        return [], artifacts, diagnostics, "error"
    if returncode != 0:
        diagnostics.append(f"{name}: ffuf exited with status {returncode}; partial results retained")
        return hits, artifacts, diagnostics, "error"
    error_text = stderr.read_text(encoding="utf-8", errors="replace")
    error_counts = [int(value) for value in re.findall(r"\bErrors\s*:\s*(\d+)", error_text)]
    if error_counts and max(error_counts) > 0:
        diagnostics.append(f"{name}: ffuf reported {max(error_counts)} request errors; partial results retained")
        return hits, artifacts, diagnostics, "error"
    return hits, artifacts, diagnostics, "completed"


def _fuzz_input(hit: dict) -> str | None:
    raw = hit.get("input", {}).get("FUZZ")
    # Some ffuf 2.1.0-dev builds replace this with an auto-calibration word.
    # Use the rendered request host or URL where they identify the word.
    return raw if isinstance(raw, str) else None


def _vhost_prefix(hit: dict, host: str) -> str | None:
    requested_host = hit.get("host")
    if isinstance(requested_host, str):
        suffix = f".{host}".lower()
        requested_host = requested_host.lower()
        if requested_host.endswith(suffix):
            return requested_host[: -len(suffix)]
        return None
    return _fuzz_input(hit)


def _rendered_extension(hit: dict, origin: str, stem: str, extensions: list[str]) -> str | None:
    requested_url = hit.get("url")
    if isinstance(requested_url, str):
        return next((extension for extension in extensions
                     if requested_url == f"{origin}/{stem}{extension}"), None)
    return _fuzz_input(hit)


def _hostname(value: str) -> bool:
    return len(value) <= 253 and all(_LABEL.fullmatch(label) for label in value.rstrip(".").split("."))


def _hit_info(hit: dict, assessment: str) -> dict:
    return {
        "status_code": hit.get("status"),
        "size": hit.get("length"),
        "words": hit.get("words"),
        "lines": hit.get("lines"),
        "redirect": hit.get("redirectlocation"),
        "assessment": assessment,
    }


def _wordlist_check(wordlist: Path | None) -> str | None:
    if wordlist is None:
        return "not_run"
    if not wordlist.is_file():
        return "wordlist does not exist or is not a file"
    return None


def run_vhost(
    origin: str, host: str, wordlist: Path | None, out_dir: Path, *,
    progress: Callable[[str, int, int], None] | None = None,
    rate: int | None = None,
) -> dict:
    """Fuzz only prefixes of the supplied hostname using HTTP Host."""
    if wordlist is None:
        return _report("not_run")
    out_dir.mkdir(parents=True, exist_ok=True)
    error = _wordlist_check(wordlist)
    if error:
        return _report("error", diagnostics=[error])
    if not shutil.which("ffuf"):
        return _report("unavailable", diagnostics=["ffuf is not installed"])
    try:
        origin = _origin(origin)
    except ValueError as exc:
        return _report("error", diagnostics=[str(exc)])
    if not _hostname(host):
        return _report("error", diagnostics=["invalid input hostname"])
    controls, artifacts, diagnostics = _save_controls(origin, out_dir, "vhost", host)
    rate_arg = {"rate": rate} if rate is not None else {}
    hits, scan_artifacts, scan_diagnostics, status = _scan(
        out_dir, "vhost", wordlist, f"{origin}/", host_header=f"FUZZ.{host}", progress=progress,
        **rate_arg,
    )
    artifacts.extend(scan_artifacts)
    diagnostics.extend(scan_diagnostics)
    candidates = []
    uncertain_hits = []
    baseline_matches = 0
    for hit in hits:
        prefix = _vhost_prefix(hit, host)
        if not prefix or not _hostname(prefix):
            diagnostics.append("vhost: skipped result with invalid prefix")
            continue
        assessment = _strict_assessment(hit, controls)
        if assessment == "matches_missing_baseline":
            baseline_matches += 1
            continue
        item = {"hostname": f"{prefix}.{host}", "source": "ffuf_vhost", "origin": origin, **_hit_info(hit, assessment)}
        if assessment == "different_from_missing_baseline":
            candidates.append(item)
        else:
            uncertain_hits.append(item)
    if baseline_matches:
        diagnostics.append(f"vhost: {baseline_matches} results match default vhost controls")
    if not _stable_control_pair(controls):
        diagnostics.append("vhost: two complete, stable default vhost controls are required")
        if status == "completed":
            status = "error"
    return _report(status, candidates=candidates, uncertain_hits=uncertain_hits, artifacts=artifacts, diagnostics=diagnostics, controls=controls)


def run_paths(
    origin: str, wordlist: Path | None, out_dir: Path, baseline: dict | None = None, *,
    progress: Callable[[str, int, int], None] | None = None,
    rate: int | None = None,
) -> dict:
    """Scan the origin root without recursion."""
    if wordlist is None:
        return _report("not_run")
    out_dir.mkdir(parents=True, exist_ok=True)
    error = _wordlist_check(wordlist)
    if error:
        return _report("error", diagnostics=[error])
    if not shutil.which("ffuf"):
        return _report("unavailable", diagnostics=["ffuf is not installed"])
    try:
        origin = _origin(origin)
    except ValueError as exc:
        return _report("error", diagnostics=[str(exc)])
    controls = _normalize_controls(baseline)
    artifacts: list[str] = []
    diagnostics: list[str] = []
    if not _stable_control_pair(controls):
        controls, artifacts, diagnostics = _save_controls(origin, out_dir, "path")
    rate_arg = {"rate": rate} if rate is not None else {}
    hits, scan_artifacts, scan_diagnostics, status = _scan(
        out_dir, "paths", wordlist, f"{origin}/FUZZ", progress=progress, **rate_arg
    )
    artifacts.extend(scan_artifacts)
    diagnostics.extend(scan_diagnostics)
    candidates = []
    uncertain_hits = []
    baseline_matches = 0
    for hit in hits:
        assessment = _strict_assessment(hit, controls)
        if assessment == "matches_missing_baseline":
            baseline_matches += 1
            continue
        fuzz = _fuzz_input(hit)
        url = hit.get("url") or (f"{origin}/{quote(fuzz, safe='/._-')}" if fuzz else None)
        if not isinstance(url, str) or not url.startswith(f"{origin}/"):
            diagnostics.append("paths: skipped result outside origin")
            continue
        item = {"url": url, "source": "ffuf_path", **_hit_info(hit, assessment)}
        if assessment == "different_from_missing_baseline":
            candidates.append(item)
        else:
            uncertain_hits.append(item)
    if baseline_matches:
        diagnostics.append(f"paths: {baseline_matches} results match missing path controls")
    if not _stable_control_pair(controls):
        diagnostics.append("paths: two complete, stable missing path controls are required")
        if status == "completed":
            status = "error"
    return _report(status, candidates=candidates, uncertain_hits=uncertain_hits, artifacts=artifacts, diagnostics=diagnostics, controls=controls)


def _known_basename(value: str) -> str | None:
    value = value.strip().split("?", 1)[0].split("#", 1)[0].lstrip("/")
    if not value or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    if re.search(r"[^A-Za-z0-9._/-]", value):
        return None
    last = value.rsplit("/", 1)[-1]
    if "." in last:
        value = value[: -len(last)] + last.rsplit(".", 1)[0]
    return value or None


def _extensions(wordlist: Path) -> list[str]:
    values = []
    seen = set()
    with wordlist.open(encoding="utf-8", errors="replace") as source:
        for line in source:
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            item = "." + item.lstrip(".")
            if not re.fullmatch(r"\.[A-Za-z0-9_-]{1,20}", item) or item in seen:
                continue
            values.append(item)
            seen.add(item)
    return values


def _write_limited_names(source: Path, output: Path, limit: int) -> int:
    count = 0
    with source.open(encoding="utf-8", errors="replace") as input_file, output.open("w", encoding="utf-8") as target:
        for line in input_file:
            name = line.strip()
            if not name or name.startswith("#"):
                continue
            # Keep ffuf substitutions within one root path segment.
            if name in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._~-]+", name):
                continue
            target.write(name + "\n")
            count += 1
            if count >= limit:
                break
    return count


def run_extensions(
    origin: str,
    paths_wordlist: Path | None,
    ext_wordlist: Path | None,
    observed_basenames: list[str],
    out_dir: Path,
    max_extra_requests: int = 100000,
    baseline: dict | None = None,
    *,
    progress: Callable[[str, int, int], None] | None = None,
    rate: int | None = None,
) -> dict:
    """Try known stems with extension words, then bounded names with observed extensions."""
    if ext_wordlist is None:
        return _report("not_run")
    out_dir.mkdir(parents=True, exist_ok=True)
    error = _wordlist_check(ext_wordlist)
    if error:
        return _report("error", diagnostics=[error])
    if max_extra_requests < 0:
        return _report("error", diagnostics=["max_extra_requests must be nonnegative"])
    if not shutil.which("ffuf"):
        return _report("unavailable", diagnostics=["ffuf is not installed"])
    try:
        origin = _origin(origin)
        extensions = _extensions(ext_wordlist)
    except (ValueError, OSError) as exc:
        return _report("error", diagnostics=[str(exc)])
    if not extensions:
        return _report("error", diagnostics=["extension wordlist has no valid extensions"])
    normalized = out_dir / "extensions.normalized.txt"
    normalized.write_text("\n".join(extensions) + "\n", encoding="utf-8")
    artifacts = [str(normalized)]
    diagnostics: list[str] = []
    # A generic missing path cannot classify a *.php fallback.  Keep the
    # baseline argument for the shared API, but use controls of each extension.
    controls_by_extension: dict[str, list[dict]] = {}

    def extension_controls(extension: str) -> list[dict]:
        if extension not in controls_by_extension:
            kind = f"extension-{extension[1:]}"
            values, new_artifacts, new_diagnostics = _save_controls(
                origin, out_dir, kind, path_suffix=extension
            )
            controls_by_extension[extension] = values
            artifacts.extend(new_artifacts)
            diagnostics.extend(new_diagnostics)
        return controls_by_extension[extension]
    stems = list(dict.fromkeys(filter(None, [_known_basename(x) for x in ["index", *observed_basenames]])))
    if len(stems) > MAX_BASENAMES:
        diagnostics.append(f"extension: limited known basenames to {MAX_BASENAMES}")
        stems = stems[:MAX_BASENAMES]
    candidates: list[dict] = []
    uncertain_hits: list[dict] = []
    confirmed: set[str] = set()
    control_warnings: set[str] = set()
    status = "completed"
    known_basename_status = "completed"
    rate_arg = {"rate": rate} if rate is not None else {}
    for index, stem in enumerate(stems, 1):
        hits, new_artifacts, new_diagnostics, scan_status = _scan(
            out_dir, f"extension-stem-{index}", normalized, f"{origin}/{stem}FUZZ",
            progress=_progress_with_target(progress, stem), **rate_arg,
        )
        artifacts.extend(new_artifacts)
        diagnostics.extend(new_diagnostics)
        if scan_status != "completed":
            status = scan_status
            known_basename_status = scan_status
        if scan_status == "unavailable":
            break
        for hit in hits:
            extension = _rendered_extension(hit, origin, stem, extensions)
            if extension not in extensions:
                continue
            assessment = _extension_assessment(hit, extension_controls(extension))
            if assessment == "extension_baseline_unavailable":
                status = "error"
                known_basename_status = "error"
                if extension not in control_warnings:
                    diagnostics.append(f"extension {extension}: missing or truncated control response")
                    control_warnings.add(extension)
            elif assessment == "unstable_extension_baseline" and extension not in control_warnings:
                diagnostics.append(f"extension {extension}: missing responses have different signatures")
                control_warnings.add(extension)
            if assessment == "matches_missing_baseline":
                continue
            if assessment == "different_from_missing_baseline" and scan_status == "completed":
                confirmed.add(extension)
            item = {
                "url": hit.get("url") or f"{origin}/{stem}{extension}",
                "extension": extension,
                "phase": "known_basename",
                "source": "ffuf_extension",
                **_hit_info(hit, assessment),
            }
            if assessment == "different_from_missing_baseline":
                candidates.append(item)
            else:
                uncertain_hits.append(item)
    request_count = 0
    if confirmed and paths_wordlist is not None and max_extra_requests > 0:
        error = _wordlist_check(paths_wordlist)
        if error:
            diagnostics.append(f"extension filename phase: {error}")
            status = "error"
        else:
            ordered = sorted(confirmed)
            for index, extension in enumerate(ordered, 1):
                allocation = max_extra_requests // len(ordered) + (index <= max_extra_requests % len(ordered))
                if allocation <= 0:
                    continue
                limited = out_dir / f"extension-names-{index}.txt"
                count = _write_limited_names(paths_wordlist, limited, allocation)
                artifacts.append(str(limited))
                if count == 0:
                    continue
                request_count += count
                hits, new_artifacts, new_diagnostics, scan_status = _scan(
                    out_dir, f"extension-filenames-{index}", limited, f"{origin}/FUZZ{extension}",
                    progress=_progress_with_target(progress, extension), **rate_arg,
                )
                artifacts.extend(new_artifacts)
                diagnostics.extend(new_diagnostics)
                if scan_status != "completed":
                    status = scan_status
                if scan_status == "unavailable":
                    break
                for hit in hits:
                    assessment = _extension_assessment(hit, extension_controls(extension))
                    if assessment == "matches_missing_baseline":
                        continue
                    word = _fuzz_input(hit)
                    item = {
                        "url": hit.get("url") or (f"{origin}/{quote(word or '', safe='._-')}{extension}"),
                        "extension": extension,
                        "phase": "known_extension",
                        "source": "ffuf_extension",
                        **_hit_info(hit, assessment),
                    }
                    if assessment == "different_from_missing_baseline":
                        candidates.append(item)
                    else:
                        uncertain_hits.append(item)
    return _report(
        status,
        candidates=candidates,
        uncertain_hits=uncertain_hits,
        artifacts=artifacts,
        diagnostics=diagnostics,
        controls=[item for group in controls_by_extension.values() for item in group],
        controls_by_extension=controls_by_extension,
        confirmed_extensions=sorted(confirmed),
        known_basename_status=known_basename_status,
        extra_request_count=request_count,
    )


def run_extension_filenames(
    origin: str,
    paths_wordlist: Path,
    confirmed_extensions: list[str],
    out_dir: Path,
    max_extra_requests: int = 100000,
    *,
    progress: Callable[[str, int, int], None] | None = None,
    rate: int | None = None,
) -> dict:
    """Rescan only names for extensions confirmed by a previous run."""
    if not confirmed_extensions or max_extra_requests == 0:
        return _report("not_run", extra_request_count=0)
    error = _wordlist_check(paths_wordlist)
    if error:
        return _report("error", diagnostics=[error], extra_request_count=0)
    if max_extra_requests < 0:
        return _report("error", diagnostics=["max_extra_requests must be nonnegative"], extra_request_count=0)
    if not shutil.which("ffuf"):
        return _report("unavailable", diagnostics=["ffuf is not installed"], extra_request_count=0)
    try:
        origin = _origin(origin)
    except ValueError as exc:
        return _report("error", diagnostics=[str(exc)], extra_request_count=0)
    extensions = sorted(set(confirmed_extensions))
    if any(not re.fullmatch(r"\.[A-Za-z0-9_-]{1,20}", item) for item in extensions):
        return _report("error", diagnostics=["invalid confirmed extension"], extra_request_count=0)
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates: list[dict] = []
    uncertain_hits: list[dict] = []
    artifacts: list[str] = []
    diagnostics: list[str] = []
    controls_by_extension: dict[str, list[dict]] = {}
    request_count = 0
    status = "completed"
    rate_arg = {"rate": rate} if rate is not None else {}
    for index, extension in enumerate(extensions, 1):
        allocation = max_extra_requests // len(extensions) + (index <= max_extra_requests % len(extensions))
        if allocation <= 0:
            continue
        limited = out_dir / f"extension-names-{index}.txt"
        count = _write_limited_names(paths_wordlist, limited, allocation)
        artifacts.append(str(limited))
        if count == 0:
            continue
        request_count += count
        kind = f"extension-{extension[1:]}"
        controls, new_artifacts, new_diagnostics = _save_controls(
            origin, out_dir, kind, path_suffix=extension
        )
        controls_by_extension[extension] = controls
        artifacts.extend(new_artifacts)
        diagnostics.extend(new_diagnostics)
        if not _stable_control_pair(controls):
            diagnostics.append(f"extension {extension}: missing or unstable control responses")
            status = "error"
        hits, new_artifacts, new_diagnostics, scan_status = _scan(
            out_dir, f"extension-filenames-{index}", limited, f"{origin}/FUZZ{extension}",
            progress=_progress_with_target(progress, extension), **rate_arg,
        )
        artifacts.extend(new_artifacts)
        diagnostics.extend(new_diagnostics)
        if scan_status != "completed":
            status = scan_status
        for hit in hits:
            assessment = _extension_assessment(hit, controls)
            if assessment == "matches_missing_baseline":
                continue
            word = _fuzz_input(hit)
            item = {
                "url": hit.get("url") or f"{origin}/{quote(word or '', safe='._-')}{extension}",
                "extension": extension,
                "phase": "known_extension",
                "source": "ffuf_extension",
                **_hit_info(hit, assessment),
            }
            if assessment == "different_from_missing_baseline":
                candidates.append(item)
            else:
                uncertain_hits.append(item)
    return _report(
        status, candidates=candidates, uncertain_hits=uncertain_hits,
        artifacts=artifacts, diagnostics=diagnostics,
        controls=[item for group in controls_by_extension.values() for item in group],
        controls_by_extension=controls_by_extension,
        confirmed_extensions=extensions, extra_request_count=request_count,
    )
