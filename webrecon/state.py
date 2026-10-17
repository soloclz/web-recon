"""Select the latest run within one engagement directory."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .rerun import _host_dir


def source_port(source: Path) -> int:
    try:
        port = json.loads((source / "run.json").read_text(encoding="utf-8"))["port"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"source run has no readable port: {source}") from exc
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"source run has no valid port: {source}")
    return port


class RunState:
    def __init__(self, scope: Path, port: int):
        self.scope = scope.resolve()
        self.port = port
        self.directory = self.scope / ".web-recon"
        self.pointer = self.directory / f"port-{port}.json"

    def _metadata(self, path: Path) -> dict | None:
        if not path.is_dir() or not (path / "report.md").is_file():
            return None
        try:
            metadata = json.loads((path / "run.json").read_text(encoding="utf-8"))
            hosts = metadata["hosts"]
            if (metadata["port"] != self.port or not isinstance(hosts, list)
                    or not hosts):
                return None
            from .cli import normalize_host
            for entry in hosts:
                host = entry["host"]
                if not isinstance(host, str) or normalize_host(host) != host or not (
                        _host_dir(path, host) / "summary.json").is_file():
                    return None
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return metadata

    def _runs(self) -> dict[Path, dict]:
        runs = {}
        for path in self.scope.iterdir():
            if path.is_symlink() or not path.is_dir() or path == self.directory:
                continue
            metadata = self._metadata(path)
            if metadata is not None:
                runs[path.resolve()] = metadata
        return runs

    @staticmethod
    def _parent(path: Path, metadata: dict) -> Path | None:
        reference = metadata.get("extended_from") or metadata.get("source_run")
        if not isinstance(reference, str) or not reference:
            return None
        parent = Path(reference)
        return (parent if parent.is_absolute() else path / parent).resolve()

    def _pointer_run(self) -> Path | None:
        if not self.pointer.exists():
            return None
        try:
            data = json.loads(self.pointer.read_text(encoding="utf-8"))
            if data["schema"] != 1 or data["port"] != self.port:
                raise ValueError("unexpected state version or port")
            path = Path(data["run"])
            if not path.is_absolute() or path.parent.resolve() != self.scope:
                raise ValueError("run path is outside the engagement directory")
            return path.resolve()
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ValueError(
                f"saved run state is invalid: {self.pointer}; "
                "use --extend-run SOURCE or --fresh") from exc

    def select_source(self) -> Path | None:
        runs = self._runs()
        pointer = self._pointer_run()
        if pointer is not None and pointer not in runs:
            raise ValueError(
                f"saved run is unavailable: {pointer}; "
                "use --extend-run SOURCE or --fresh")
        if pointer is None and not runs:
            return None

        selected = set()
        for path in runs:
            current = path
            visited = set()
            while current in runs and current not in visited:
                if pointer is not None and current == pointer:
                    selected.add(path)
                    break
                visited.add(current)
                current = self._parent(current, runs[current])
        if pointer is None:
            selected = set(runs)
        children = {self._parent(path, runs[path]) for path in selected}
        leaves = sorted(selected - children)
        if len(leaves) != 1:
            candidates = ", ".join(str(path) for path in leaves[:5])
            raise ValueError(
                f"multiple prior runs for port {self.port} in {self.scope}: "
                f"{candidates}; use --extend-run SOURCE or --fresh")
        return leaves[0]

    def record(self, run_dir: Path) -> None:
        run_dir = run_dir.resolve()
        if run_dir.parent != self.scope or self._metadata(run_dir) is None:
            raise ValueError(f"new run is incomplete or outside {self.scope}: {run_dir}")
        payload = {"schema": 1, "port": self.port, "run": str(run_dir)}
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.directory,
                prefix=f".port-{self.port}-", suffix=".tmp", delete=False) as temporary:
            temporary.write(json.dumps(payload, indent=2) + "\n")
            temporary_path = Path(temporary.name)
        try:
            os.replace(temporary_path, self.pointer)
        finally:
            temporary_path.unlink(missing_ok=True)


@contextmanager
def locked_scope(scope: Path, port: int):
    state = RunState(scope, port)
    state.directory.mkdir(parents=True, exist_ok=True)
    lock_path = state.directory / f"port-{port}.lock"
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"another Web recon run is active for port {port} in {state.scope}") from exc
        try:
            yield state
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
