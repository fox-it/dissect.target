from dissect.target import container
from dissect.target.loader import Loader


class EwfLoader(Loader):
    """Load Encase EWF forensic image format files.

    References:
        - https://www.opentext.com/products/encase-forensic
        - https://www.loc.gov/preservation/digital/formats/fdd/fdd000408.shtml
    """

    @staticmethod
    def detect(path):
        return path.suffix.lower() in (".e01", ".s01", ".l01")

    def map(self, target):
        target.disks.add(container.open(self.path))
