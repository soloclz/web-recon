"""Live stage and scanner progress for a single reconnaissance run."""

from __future__ import annotations

import json
import sys
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
            if scan.startswith("extension-stem-") and scan.removeprefix("extension-stem-").isdigit():
                detail = f"known filename #{scan.removeprefix('extension-stem-')}"
            elif scan.startswith("extension-filenames-") and scan.removeprefix("extension-filenames-").isdigit():
                detail = f"filename guesses #{scan.removeprefix('extension-filenames-')}"
            else:
                detail = scan
            label += f" ({detail})"
        return label
    if len(parts) == 2 and parts[0] == "web":
        return f"{parts[1].upper()} Web checks"
    return _STAGE_LABELS.get(stage, stage)


class ProgressReporter:
    """Append events immediately and show a bounded heartbeat in the terminal."""

    def __init__(self, run_dir: Path, heartbeat_seconds: float = 15):
        self.path = run_dir / "progress.jsonl"
        self.path.touch(exist_ok=False)
        self.heartbeat_seconds = heartbeat_seconds
        self._lock = Lock()
        self._active: dict[tuple[str, str], dict] = {}
        self._stop = Event()
        self._thread = Thread(target=self._heartbeat, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()

    def _emit_locked(self, host: str, stage: str, event: str, state: dict,
                     **details: object) -> None:
        elapsed = round(monotonic() - state["started"], 1)
        record = {"time_utc": datetime.now(timezone.utc).isoformat(),
                  "host": host, "stage": stage, "event": event,
                  "elapsed_seconds": elapsed, **details}
        with self.path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
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
        print(message, file=sys.stderr, flush=True)

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
