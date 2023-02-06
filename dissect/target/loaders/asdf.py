from dissect.evidence import AsdfSnapshot

from dissect.target.containers.asdf import AsdfContainer
from dissect.target.helpers import fsutil
from dissect.target.loader import Loader
from dissect.target.loaders.tar import TarFile


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

        overlay = target.fs.add_layer()
        for member in self.asdf.metadata.members():
            if member.isdir():
                continue

            path = fsutil.join(self.METADATA_PREFIX, member.name)
            entry = TarFile(overlay, path, member.name, self.asdf.metadata.tar)
            overlay.map_file_entry(entry.path, entry)
