"""Live stage and scanner progress for a single reconnaissance run."""

from __future__ import annotations

import json
import shutil
import sys
import unicodedata
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from time import monotonic


def _elapsed(seconds: float) -> str:
    whole = max(0, int(seconds))
    minutes, remainder = divmod(whole, 60)
    return f"{minutes}m{remainder:02d}s" if minutes else f"{remainder}s"


_STAGE_LABELS = {
    "resolution": "hostname resolution",
    "dns": "DNS checks",
    "dns-words": "DNS wordlist scan",
    "scheme": "HTTP/HTTPS probe",
    "tls": "TLS certificate",
    "public": "public sources",
}


def _display_stage(stage: str, scan: str | None) -> str:
    parts = stage.split(":")
    if len(parts) == 3 and parts[0] == "scanner":
        _, scheme, purpose = parts
        name = {"paths": "path", "extensions": "extension",
                "extension-filenames": "filename"}.get(purpose, purpose)
        label = f"{scheme.upper()} {name} scan"
        if scan and scan != purpose:
            scan_name, _, target = scan.partition(":")
            stem_number = scan_name.removeprefix("extension-stem-")
            filename_number = scan_name.removeprefix("extension-filenames-")
            if scan_name.startswith("extension-stem-") and stem_number.isdigit():
                detail = f"known filename: {target}.*" if target else f"known filename #{stem_number}"
            elif scan_name.startswith("extension-filenames-") and filename_number.isdigit():
                detail = f"filename guesses: *{target}" if target else f"filename guesses #{filename_number}"
            else:
                detail = scan
            label += f" ({detail})"
        return label
    if len(parts) == 2 and parts[0] == "web":
        return f"{parts[1].upper()} Web checks"
    return _STAGE_LABELS.get(stage, stage)


class ProgressReporter:
    """Append events immediately and keep one live progress line on a TTY."""

    def __init__(self, run_dir: Path, heartbeat_seconds: float = 15):
        self.path = run_dir / "progress.jsonl"
        self.path.touch(exist_ok=False)
        self.heartbeat_seconds = heartbeat_seconds
        self._lock = Lock()
        self._active: dict[tuple[str, str], dict] = {}
        self._tty = sys.stderr.isatty()
        self._line_open = False
        self._candidate_keys: OrderedDict[tuple, None] = OrderedDict()
        self._candidate_cache_limit = 10_000
        self._stop = Event()
        self._thread = Thread(target=self._heartbeat, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        with self._lock:
            if self._tty and self._line_open:
                sys.stderr.write("\n")
                sys.stderr.flush()
                self._line_open = False

    def _append_locked(self, record: dict) -> None:
        with self.path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")

    @staticmethod
    def _single_line(value: str, width: int | None = None) -> str:
        text = []
        used = 0
        for character in value:
            character = character if character.isprintable() else " "
            cells = (0 if unicodedata.combining(character) else
                     2 if unicodedata.east_asian_width(character) in ("W", "F") else 1)
            if width is not None and used + cells > width:
                break
            text.append(character)
            used += cells
        return "".join(text)

    @staticmethod
    def _terminal_width() -> int:
        return max(1, shutil.get_terminal_size(fallback=(120, 24)).columns - 1)

    def _live_locked(self, message: str) -> None:
        if not self._tty:
            print(self._single_line(message), file=sys.stderr, flush=True)
            return
        sys.stderr.write("\r\x1b[2K" + self._single_line(message, self._terminal_width()))
        sys.stderr.flush()
        self._line_open = True

    def _persistent_locked(self, message: str, *, full_candidate: bool = False) -> None:
        if not self._tty:
            safe = self._single_line(message)
            if full_candidate and len(safe) > 2048:
                safe = safe[:2048] + "… [full value in progress.jsonl]"
            print(safe, file=sys.stderr, flush=True)
            return
        if self._line_open:
            sys.stderr.write("\r\x1b[2K")
        safe = self._single_line(message)
        if full_candidate:
            safe = safe[:2048] + ("… [full value in progress.jsonl]" if len(safe) > 2048 else "")
        else:
            safe = self._single_line(message, self._terminal_width())
        sys.stderr.write(safe + "\n")
        self._line_open = False
        visible = [state for state in self._active.values() if "last_message" in state]
        if visible:
            latest = max(visible, key=lambda state: state["rendered_at"])
            self._live_locked(latest["last_message"])
        else:
            sys.stderr.flush()

    @staticmethod
    def _candidate_key(host: str, stage: str, status: str, item: dict,
                       display: str) -> tuple:
        identity_fields = ("name", "url", "hostname", "path", "value", "record",
                           "address", "ip", "target", "answer", "extension", "title",
                           "host", "candidate", "method", "tag", "type", "text")
        fields = {key: item[key] for key in ("kind", "source", *identity_fields)
                  if key in item}
        if not any(key in fields for key in identity_fields):
            fields = item or {"display": display}
        return (host, stage, status, json.dumps(fields, ensure_ascii=False,
                                                sort_keys=True, default=str))

    def candidate(self, host: str, stage: str, item: dict, display: str,
                  status: str = "candidate") -> bool:
        """Publish one observed fact or unconfirmed candidate as soon as it appears."""
        with self._lock:
            key = self._candidate_key(host, stage, status, item, display)
            if key in self._candidate_keys:
                self._candidate_keys.move_to_end(key)
                return False
            self._candidate_keys[key] = None
            if len(self._candidate_keys) > self._candidate_cache_limit:
                self._candidate_keys.popitem(last=False)
            state = self._active.get((host, stage))
            elapsed = round(monotonic() - state["started"], 1) if state else 0.0
            self._append_locked({
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "host": host, "stage": stage, "event": "finding",
                "elapsed_seconds": elapsed, "status": status,
                "item": item, "display": display,
            })
            self._persistent_locked(
                f"[{host}] {status} {_display_stage(stage, None)}: {display}",
                full_candidate=True)
            return True

    def _emit_locked(self, host: str, stage: str, event: str, state: dict,
                     **details: object) -> None:
        elapsed = round(monotonic() - state["started"], 1)
        record = {"time_utc": datetime.now(timezone.utc).isoformat(),
                  "host": host, "stage": stage, "event": event,
                  "elapsed_seconds": elapsed, **details}
        self._append_locked(record)
        scan = details.get("scan", state.get("scan"))
        current = details.get("current", state.get("current"))
        total = details.get("total", state.get("total"))
        message = f"[{host}] {_display_stage(stage, scan if isinstance(scan, str) else None)}"
        if event == "start":
            message += " started"
        elif event == "finish":
            message += f" {details.get('status', 'error')} ({_elapsed(elapsed)})"
        elif isinstance(current, int) and isinstance(total, int) and total > 0:
            percent = 100 * current / total
            message += f" {current:,}/{total:,} tried ({percent:.0f}%), elapsed {_elapsed(elapsed)}"
        else:
            message += f" running, elapsed {_elapsed(elapsed)}"
        if event == "finish":
            self._persistent_locked(message)
        else:
            state["last_message"] = message
            state["rendered_at"] = monotonic()
            self._live_locked(message)

    def start(self, host: str, stage: str) -> None:
        with self._lock:
            state = {"started": monotonic(), "last_progress": 0.0}
            self._active[(host, stage)] = state
            self._emit_locked(host, stage, "start", state)

    def finish(self, host: str, stage: str, status: str) -> None:
        with self._lock:
            state = self._active.pop((host, stage), None)
            if state is not None:
                self._emit_locked(host, stage, "finish", state, status=status)

    def update(self, host: str, stage: str, scan: str, current: int, total: int) -> None:
        if total <= 0 or current < 0:
            return
        with self._lock:
            state = self._active.get((host, stage))
            if state is None:
                return
            current = min(current, total)
            changed_scan = state.get("scan") != scan
            changed_count = state.get("current") != current
            state.update(scan=scan, current=current, total=total)
            now = monotonic()
            if (changed_scan or (changed_count and current == total)
                    or (changed_count and now - state["last_progress"] >= 5)):
                state["last_progress"] = now
                self._emit_locked(host, stage, "progress", state,
                                  scan=scan, current=current, total=total)

    def _heartbeat(self) -> None:
        while not self._stop.wait(self.heartbeat_seconds):
            with self._lock:
                for (host, stage), state in list(self._active.items()):
                    self._emit_locked(host, stage, "heartbeat", state,
                                      **{key: state[key] for key in ("scan", "current", "total")
                                         if key in state})
