from pathlib import Path

from dissect.target import Target
from dissect.target.helpers.cyber import cyber
from dissect.target.loader import Loader
from dissect.target.loader import open as loader_open
from dissect.target.loaders.raw import RawLoader

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
        with cyber(mask_space=True):
            print(HEADER)

        target.props["cyber"] = True
        return self._real.map(target)
