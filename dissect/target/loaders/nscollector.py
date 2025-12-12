from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loaders.tar import TarSubLoader

if TYPE_CHECKING:
    import tarfile as tf
    from pathlib import Path

    from dissect.target.target import Target


class NsCollectorTarSubLoader(TarSubLoader):
    """Loader for tar-based Netscaler Techsupport Collector files.

    References:
        - https://developer-docs.netscaler.com/en-us/adc-command-reference-int/current-release/utility/techsupport.html
        - https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX222958
    """

    @staticmethod
    def detect(path: Path, tarfile: tf.TarFile) -> bool:
        # members = (member.name for member in tarfile.getmembers())
        # filesystem_root = next(iter(members))

        # required_paths = {f"{filesystem_root}/nsconfig/ns.conf", f"{filesystem_root}/shell"}
        if not (names := tarfile.getnames()):
            return False

        root = names[0]
        required_paths = {f"{root}/nsconfig/ns.conf", f"{root}/shell"}

        return required_paths.issubset(names)

    def map(self, target: Target) -> None:
        fs = TarFilesystem(tarfile=self.tar, base=self.tar.getnames()[0], fh=self.tar.fileobj)
        target.filesystems.add(fs)

        # Symlink /nsconfig to /flash/nsconfig to make Citrix parsers compatible
        target.fs.symlink("/nsconfig", "/flash/nsconfig")
