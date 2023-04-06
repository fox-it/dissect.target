from dissect.evidence import AsdfSnapshot
from dissect.evidence.asdf.asdf import IDX_METADATA

from dissect.target.containers.asdf import AsdfContainer
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loader import Loader


class AsdfLoader(Loader):
    METADATA_PREFIX = "$asdf$"

    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        self.asdf = AsdfSnapshot(open(path, "rb"))

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".asdf"

    def map(self, target):
        for disk in self.asdf.disks():
            target.disks.add(AsdfContainer(disk))

        target.fs.mount(self.METADATA_PREFIX, TarFilesystem(self.asdf.open(IDX_METADATA)))
