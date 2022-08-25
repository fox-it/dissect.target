from pathlib import Path

import dissect.target.container as container
from dissect.target.loader import Loader, register


class TestLoader(Loader):
    @staticmethod
    def detect(path: Path) -> bool:
        return True

    def map(self, target) -> None:
        target.disks.add(container.open(self.path))
        pass


register(TestLoader.__module__, TestLoader.__name__, internal=False)
