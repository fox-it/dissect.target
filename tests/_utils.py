from __future__ import annotations

from pathlib import Path


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent.joinpath(filename).resolve()


def mkdirs(root: Path, paths: list[str]) -> None:
    for path in paths:
        root.joinpath(path).mkdir(parents=True)
