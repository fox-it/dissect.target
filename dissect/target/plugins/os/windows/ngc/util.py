from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def read_dat(file: Path) -> str:
    """Read a ``.dat`` file's UTF-16 contents."""
    return file.read_bytes().decode("utf-16-le").rstrip("\x00")
