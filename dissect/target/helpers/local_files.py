from __future__ import annotations
from dissect.target.target import Target


class SingleFileMixin:
    def __init__(self, target: Target) -> None:
        self._path = target.path 

    def get_files() -> None:
        pass
