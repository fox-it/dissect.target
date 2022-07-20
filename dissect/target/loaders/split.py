from dissect.target import container
from dissect.target.loader import Loader


def find_files(path):
    return sorted([f for f in path.parent.glob(path.stem + ".*") if f.suffix[1:].isdigit()])


class SplitLoader(Loader):
    def __init__(self, path):
        path = path.resolve()
        super().__init__(path)
        self.files = find_files(path)

    @staticmethod
    def detect(path):
        path = path.resolve()
        return path.suffix[1:].isdigit() and len(find_files(path)) > 1

    def map(self, target):
        target.disks.add(container.open(self.files))
