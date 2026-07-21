from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileHashResult:
    hashes: dict[str, str]
    error: str | None = None


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> FileHashResult:
    algorithms = {
        "sha256": hashlib.sha256(),
        "sha1": hashlib.sha1(),
        "md5": hashlib.md5(),
    }
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(chunk_size):
                for algorithm in algorithms.values():
                    algorithm.update(chunk)
    except OSError as exc:
        return FileHashResult(hashes={}, error=str(exc))
    return FileHashResult(
        hashes={name: algorithm.hexdigest() for name, algorithm in algorithms.items()}
    )
