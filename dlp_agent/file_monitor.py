from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileState:
    size: int
    modified_ns: int


@dataclass(frozen=True)
class FileCopyEvent:
    root: Path
    path: Path
    size: int
    modified_ns: int
    change_type: str


class UsbFileMonitor:
    """Poll USB roots and report files that are created or changed."""

    def __init__(self) -> None:
        self._roots: set[Path] = set()
        self._snapshots: dict[Path, dict[Path, FileState]] = {}

    @property
    def roots(self) -> set[Path]:
        return set(self._roots)

    def add_root(self, root: Path) -> None:
        normalized = self._normalize_root(root)
        self._roots.add(normalized)
        self._snapshots[normalized] = self._snapshot(normalized)

    def remove_root(self, root: Path) -> None:
        normalized = self._normalize_root(root)
        self._roots.discard(normalized)
        self._snapshots.pop(normalized, None)

    def poll(self) -> list[FileCopyEvent]:
        events: list[FileCopyEvent] = []
        for root in sorted(self._roots):
            current = self._snapshot(root)
            previous = self._snapshots.get(root, {})

            for path, state in current.items():
                old_state = previous.get(path)
                if old_state is None:
                    events.append(
                        FileCopyEvent(
                            root=root,
                            path=path,
                            size=state.size,
                            modified_ns=state.modified_ns,
                            change_type="created",
                        )
                    )
                elif old_state != state:
                    events.append(
                        FileCopyEvent(
                            root=root,
                            path=path,
                            size=state.size,
                            modified_ns=state.modified_ns,
                            change_type="modified",
                        )
                    )

            self._snapshots[root] = current

        return events

    def _snapshot(self, root: Path) -> dict[Path, FileState]:
        files: dict[Path, FileState] = {}
        if not root.exists():
            return files

        for directory, _, filenames in os.walk(root):
            for filename in filenames:
                path = Path(directory) / filename
                try:
                    stat = path.stat()
                except OSError:
                    continue
                files[path] = FileState(size=stat.st_size, modified_ns=stat.st_mtime_ns)
        return files

    @staticmethod
    def _normalize_root(root: Path) -> Path:
        return Path(str(root)).absolute()
