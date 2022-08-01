from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING, BinaryIO, Iterator

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers import keychain
from dissect.target.helpers.lazy import import_lazy
from dissect.target.helpers.utils import readinto

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem
    from dissect.target.volumes.disk import DissectVolumeSystem

disk = import_lazy("dissect.target.volumes.disk")
lvm = import_lazy("dissect.target.volumes.lvm")
vmfs = import_lazy("dissect.target.volumes.vmfs")
bde = import_lazy("dissect.target.volumes.bde")

log = logging.getLogger(__name__)

LOGICAL_VOLUME_MANAGERS: list[type[LogicalVolumeSystem]] = [lvm.LvmVolumeSystem, vmfs.VmfsVolumeSystem]

ENCRYPTED_VOLUME_MANAGERS: list[type[EncryptedVolumeSystem]] = [bde.BitlockerVolumeSystem]


class VolumeSystem:
    """A base class that keeps account of all the :class:`Volume` instances.

    Args:
        fh: The file-like object representing the disk.
        dsk: A disk that contains the volumes.
        serial: Serial number of a volumes.
    """

    def __init__(self, fh: BinaryIO, dsk: BinaryIO = None, serial: str = None):
        self.fh = fh
        self.disk = dsk or fh  # Provide shorthand access to source disk
        self.serial = serial
        self._volumes_list: list[Volume] = None

    def __repr__(self):
        return f"<{self.__class__.__name__} serial={self.serial}>"

    @staticmethod
    def detect(fh: Volume) -> bool:
        """Detects wether this ``VolumeSystem`` class can load this specific disk.

        Returns:
            ``True`` or ``False`` if they can read the ``VolumeSystem``
        """
        raise NotImplementedError()

    def _volumes(self) -> Iterator[Volume]:
        """List all valid found partitions found on the disk.

        Returns:
            An iterator that goes through the ``Volumes`` or partitions of a disk image.
        """
        raise NotImplementedError()

    @property
    def volumes(self) -> list[Volume]:
        """A property that puts all the found volumes inside a list.

        Returns:
            A list of ``Volumes``.
        """
        if self._volumes_list is None:
            self._volumes_list = list(self._volumes())

        return self._volumes_list


class EncryptedVolumeSystem(VolumeSystem):
    """An extention of the :class:`VolumeSystem` class that provides additional function for encryption.

    It adds more helper function to go through specific keys, to see which key matches.

    Args:
        fh: The file like object the :class:`VolumeSystem` is attached to.
    """

    PROVIDER = None

    def __init__(self, fh, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)

        if not self.PROVIDER:
            raise ValueError("Provider identifier is not set")
        self.keys = keychain.get_keys_for_provider(self.PROVIDER) + keychain.get_keys_without_provider()

    def get_keys_for_identifier(self, identifier: str) -> list[keychain.Key]:
        """Retrieves a list of keys that match a single ``identifier``.

        Args:
            identifier: A single Volume identifier for a volume.

        Returns:
            All the keys for a single identiefier.
        """
        return self.get_keys_for_identifiers([identifier])

    def get_keys_for_identifiers(self, identifiers: list[str]) -> list[keychain.Key]:
        """Retrieves a list of keys that match a list of ``identifiers``.

        Args:
            identifiers: A list of different Volume identifiers.

        Returns:
            All the keys for a single identiefier.
        """
        # normalise values before checks
        identifiers = [i.lower() for i in identifiers]
        return [key for key in self.keys if key.identifier and key.identifier.lower() in identifiers]

    def get_keys_without_identifier(self) -> list[keychain.Key]:
        return [key for key in self.keys if key.identifier is None]


class LogicalVolumeSystem(VolumeSystem):
    """A representation for logical ``VolumeSystems``."""

    @staticmethod
    def detect_volume(fh: Volume) -> bool:
        """Determine wether any logical ``Volume`` could be detected.

        Args:
            fh: A ``Volume`` object that might contain more ``Volumes``.

        Returns:
            ``True`` if a volume could be detected, ``False`` otherwise.
        """
        raise NotImplementedError()

    @classmethod
    def open_all(cls, volumes: list[Volume]) -> Iterator[LogicalVolumeSystem]:
        """Open all the volumes/file like objects that correspond to this disk image.

        Args:
            volumes: A list of file-like ``Volume`` objects.

        Returns:
            An iterator of LogicalVolumeSystems.
        """
        raise NotImplementedError()


class Volume(io.IOBase):
    """A representation of a volume on disk.

    It allows to directly interact with the volume.

    Args:
        fh: The raw data stream of the volume.
        number: The logical volume number on disk.
        offset: Where the Volume starts relative to the start of the Disk image.
        size: The size of the Volume.
        vtype: What kind of volume it is.
        name: The name of the Volume.
        guid: The unique identifier.
        raw: A direct connection to the raw data of the disk.
        disk: A direct connection to :class:`dissect.volume.disk.Disk`.
        vs: A dirrect reference to the :class:`VolumeSystem` above.
        fs: A dirrect reference to the :class:`~dissect.target.filesystem.Filesystem` that is on the ``Volume``.
        drive_letter: The letter associated to the ``Volume``, such as `c` or `d` in windows.
    """

    def __init__(
        self,
        fh: BinaryIO,
        number: int,
        offset: int,
        size: int,
        vtype: int,
        name: str,
        guid: str = None,
        raw: BinaryIO = None,
        disk: BinaryIO = None,
        vs: VolumeSystem = None,
        fs: Filesystem = None,
        drive_letter: str = None,
    ):
        self.fh = fh
        self.number = number
        self.offset = offset
        self.size = size
        self.type = vtype
        self.name = name
        self.guid = guid

        # Shorthand access to raw volume, disk, vs and fs objects
        self.raw = raw
        self.disk = disk
        self.vs = vs
        self.fs = fs
        self.drive_letter = drive_letter

        self.seek(0)

    def __repr__(self):
        return f"<Volume name={self.name!r} size={self.size!r} fs={self.fs!r}>"

    def read(self, length: int) -> bytes:
        """Read the ``length`` in bytes from ``fh``.

        Returns:
            The number of bytes that were read.
        """
        return self.fh.read(length)

    def readinto(self, b: bytearray) -> int:
        """Uses :func:`dissect.target.helpers.utils.readinto`."""
        return readinto(buffer=b, fh=self)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """Change the stream positition.

        Change the stream position to ``offset``.

        ``whence`` determines where to seek from:

        * ``io.SEEK_SET`` (``0``):: absolute offset in the stream.
        * ``io.SEEK_CUR`` (``1``):: current position in the stream.
        * ``io.SEEK_END`` (``2``):: end of stream.

        Args:
            offset: The offset relative to the position indicated by ``whence``.
            whence: Where to start the seek from.
        """
        return self.fh.seek(offset, whence)

    def tell(self) -> int:
        """Returns the current position of the ``fh`` stream."""
        return self.fh.tell()

    def seekable(self) -> bool:
        """Returns whether ``seek`` can be used by this container. Always ``True``."""
        return True


def open(fh: BinaryIO, *args, **kwargs) -> DissectVolumeSystem:
    """Open ``fh`` as a :class:`dissect.target.volumes.disk.DissectVolumeSystem`."""
    try:
        return disk.DissectVolumeSystem(fh)
    except Exception as e:
        raise VolumeSystemError(f"Failed to load volume system for {fh}", cause=e)


def is_lvm_volume(volume: Volume) -> bool:
    """Determine if a logical :class:`VolumeSystem` can open this ``volume``.

    It iterates through :var:`LOGICAL_VOLUME_MANAGERS` whether the ``volume`` contains the required volume signature.

    Args:
        volume: A file-like object representing a :class:`Volume`.

    Returns:
        ``True`` if the :class:`LogicalVolumeSystem` can open the specific ``volume``, else ``False``.
    """
    for logical_vs in LOGICAL_VOLUME_MANAGERS:
        try:
            if logical_vs.detect_volume(volume):
                return True
        except ImportError as e:
            log.warning("Failed to import %s", logical_vs, exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to detect logical volume for {volume}", cause=e)

    return False


def is_encrypted(volume: Volume) -> bool:
    """Determine if the ``volume`` is encrypted.

    It iterates through :var:`ENCRYPTED_VOLUME_MANAGERS` whether the ``volume`` contains a encrypted header signature.

    Args:
        volume: A file-like object representing a :class:`Volume`.

    Returns:
        ``True`` if the :class:`EncryptedVolumeSystem` can open the specific ``volume``, else ``False``.
    """
    for manager in ENCRYPTED_VOLUME_MANAGERS:
        try:
            if manager.detect(volume):
                return True
        except ImportError as e:
            log.warning("Failed to import %s", manager, exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to detect encrypted volume for {volume}", cause=e)
    return False


def open_encrypted(volume: Volume) -> Iterator[Volume]:
    """Open an encrypted ``volume``.

    It iterates through :var:`ENCRYPTED_VOLUME_MANAGERS` to see which :class:`EncryptedVolumeSystem` can open this
    specific :class:`Volume`.

    Args:
        volume: A file-like object representing a :class:`Volume`.

    Returns:
        an iterator containing ``volumes`` related to the encrypted volume manager..
    """
    for manager_cls in ENCRYPTED_VOLUME_MANAGERS:
        try:
            if manager_cls.detect(volume):
                volume_manager = manager_cls(volume)
                yield from volume_manager.volumes
        except VolumeSystemError:
            log.exception(f"Failed to open an encrypted volume {volume} with volume manager {manager_cls}")
    return None


def open_lvm(volumes: list[Volume], *args, **kwargs) -> Iterator[VolumeSystem]:
    """Open a logical volume system..

    It iterates through :var:`LOGICAL_VOLUME_MANAGERS` to see which :class:`LogicalVolumeSystem` can open this
    specific :class:`Volume`.

    Args:
        volumes: A list of file-like objects representing multiple :class:`Volume` object.

    Returns:
        an iterator containing all the volumes contained in the file-like ``volumes`` list.
    """
    for logical_vs in LOGICAL_VOLUME_MANAGERS:
        try:
            yield from logical_vs.open_all(volumes)
        except ImportError as e:
            log.warning("Failed to import %s", logical_vs, exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to load logical volume system for {volumes}", cause=e)
