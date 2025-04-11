from __future__ import annotations

import os
import textwrap
from typing import TYPE_CHECKING

from dissect.target.helpers.cyber import cyber
from dissect.target.loader import Loader
from dissect.target.loader import open as loader_open
from dissect.target.loaders.raw import RawLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

HEADER = r"""
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃      _______     ______  ______ _____      ┃
┃     / ____\ \   / /  _ \|  ____|  __ \     ┃
┃    | |     \ \_/ /| |_) | |__  | |__) |    ┃
┃    | |      \   / |  _ <|  __| |  _  /     ┃
┃    | |____   | |  | |_) | |____| | \ \     ┃
┃     \_____|  |_|  |____/|______|_|  \_\    ┃
┃                                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

"""


class CyberLoader(Loader):
    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self._real = loader_open(path) or RawLoader(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        cols, _ = os.get_terminal_size()
        width = HEADER.index("\n", 1)
        header = textwrap.indent(HEADER, " " * ((cols - width) // 2))
        with cyber(mask_space=True, mask_indent=False):
            print(header)

        target.props["cyber"] = True
        return self._real.map(target)
