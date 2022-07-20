from dissect.target import container
from dissect.target.loader import Loader


class RawLoader(Loader):
    @staticmethod
    def detect(path):
        return True

    def map(self, target):
        target.disks.add(container.open(self.path))
