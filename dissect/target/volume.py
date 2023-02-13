from __future__ import annotations

import io
import logging
from typing import TYPE_CHECKING, BinaryIO, Iterator, Optional, Union

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers import keychain
from dissect.target.helpers.lazy import import_lazy
from dissect.target.helpers.utils import readinto

if TYPE_CHECKING:
    from dissect.target.container import Container
    from dissect.target.filesystem import Filesystem
    from dissect.target.volumes.disk import DissectVolumeSystem

disk = import_lazy("dissect.target.volumes.disk")
"""A lazy import of :mod:`dissect.target.volumes.disk`."""
lvm = import_lazy("dissect.target.volumes.lvm")
"""A lazy import of :mod:`dissect.target.volumes.lvm`."""
vmfs = import_lazy("dissect.target.volumes.vmfs")
"""A lazy import of :mod:`dissect.target.volumes.vmfs`."""
bde = import_lazy("dissect.target.volumes.bde")
"""A lazy import of :mod:`dissect.target.volumes.bde`."""

log = logging.getLogger(__name__)
"""A logger instance for this module."""

LOGICAL_VOLUME_MANAGERS: list[type[LogicalVolumeSystem]] = [lvm.LvmVolumeSystem, vmfs.VmfsVolumeSystem]
"""All available :class:`LogicalVolumeSystem` classes."""
ENCRYPTED_VOLUME_MANAGERS: list[type[EncryptedVolumeSystem]] = [bde.BitlockerVolumeSystem]
"""All available :class:`EncryptedVolumeSystem` classes."""


class VolumeSystem:
    """The base class for a volume system implementation.

    Volume systems are responsible for parsing a volume system over one or more disks and
    returning all available volumes.

    Subclasses of ``VolumeSystem`` must implement the ``_detect`` and ``_volumes`` methods.

    Args:
        fh: The source file-like object(s) on which to open the volume system.
        dsk: A reference to the source disk or container.
        serial: Serial number of the volume system, if any.
    """

    def __init__(
        self, fh: Union[BinaryIO, list[BinaryIO]], dsk: Optional[Container] = None, serial: Optional[str] = None
    ):
        self.fh = fh
        self.disk = dsk or fh  # Provide shorthand access to source disk
        self.serial = serial
        self._volumes_list: list[Volume] = None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} serial={self.serial}>"

    @classmethod
    def detect(cls, fh: BinaryIO) -> bool:
        """Detects whether this ``VolumeSystem`` class can be opened on the given file-like object.

        The position of ``fh`` will be restored before returning.

        Returns:
            ``True`` or ``False`` if the ``VolumeSystem`` can be opened from this file-like object.
        """
        offset = fh.tell()
        try:
            fh.seek(0)
            return cls._detect(fh)
        except Exception as e:
            log.warning("Failed to detect %s volume system", cls)
            log.debug("", exc_info=e)
        finally:
            fh.seek(offset)

        return False

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detects whether this ``VolumeSystem`` class can be opened on the given file-like object.

        This method should be implemented by subclasses. The position of ``fh`` is guaranteed to be ``0``.

        Returns:
            ``True`` or ``False`` if the ``VolumeSystem`` can be opened from this file-like object.
        """
        raise NotImplementedError()

    def _volumes(self) -> Iterator[Volume]:
        """List all valid discovered volumes found on the volume system.

        Returns:
            An iterator of all :class:`Volume` of the ``VolumeSystem``.
        """
        raise NotImplementedError()

    @property
    def volumes(self) -> list[Volume]:
        """A list of all the discovered volumes."""
        if self._volumes_list is None:
            self._volumes_list = list(self._volumes())

        return self._volumes_list


class EncryptedVolumeSystem(VolumeSystem):
    """An extension of the :class:`VolumeSystem` class that provides additional functionality for
    dealing with encryption.

    It adds helper functions for interacting with the :attr:`~dissect.target.helpers.keychain.KEYCHAIN`,
    so that subclasses don't have to manually interact with it.

    Subclasses must set the ``PROVIDER`` class attribute to a unique string, e.g. ``bitlocker``.

    Args:
        fh: The file-like object on which to open the encrypted volume system.
    """

    PROVIDER: str = None

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)

        if not self.PROVIDER:
            raise ValueError("Provider identifier is not set")
        self.keys = keychain.get_keys_for_provider(self.PROVIDER) + keychain.get_keys_without_provider()

    def get_keys_for_identifier(self, identifier: str) -> list[keychain.Key]:
        """Retrieves a list of keys that match a single ``identifier``.

        Args:
            identifier: A single key identifier.

        Returns:
            All the keys for a single identifier.
        """
        return self.get_keys_for_identifiers([identifier])

    def get_keys_for_identifiers(self, identifiers: list[str]) -> list[keychain.Key]:
        """Retrieves a list of keys that match a list of ``identifiers``.

        Args:
            identifiers: A list of different key identifiers.
        """
        # normalise values before checks
        identifiers = [i.lower() for i in identifiers]
        return [key for key in self.keys if key.identifier and key.identifier.lower() in identifiers]

    def get_keys_without_identifier(self) -> list[keychain.Key]:
        """Retrieve a list of keys that have no identifier (``None``).

        These are the keys where no specific identifier was specified.
        """
        return [key for key in self.keys if key.identifier is None]


class LogicalVolumeSystem(VolumeSystem):
    """An extension of the :class:`VolumeSystem` class that provides additional functionality for dealing with
    logical volume systems.
    """

    @classmethod
    def detect_volume(cls, fh: BinaryIO) -> bool:
        """Determine whether the given file-like object belongs to this logical volume system.

        The position of ``fh`` will be restored before returning.

        Args:
            fh: A file-like object that may be part of the logical volume system.

        Returns:
            ``True`` if the given file-like object is part of the logical volume system, ``False`` otherwise.
        """
        offset = fh.tell()
        try:
            fh.seek(0)
            return cls._detect_volume(fh)
        except Exception as e:
            log.warning("Failed to detect %s logical volume", cls)
            log.debug("", exc_info=e)
        finally:
            fh.seek(offset)

        return False

    @staticmethod
    def _detect_volume(fh: BinaryIO) -> bool:
        """Determine whether the given file-like object belongs to this logical volume system.

        This method should be implemented by subclasses. The position of ``fh`` is guaranteed to be ``0``.

        Args:
            fh: A file-like object that may be part of the logical volume system.

        Returns:
            ``True`` if the given file-like object is part of the logical volume system, ``False`` otherwise.
        """
        raise NotImplementedError()

    @classmethod
    def open_all(cls, volumes: list[BinaryIO]) -> Iterator[LogicalVolumeSystem]:
        """Open all the discovered logical volume systems from the given file-like objects.

        There can be more than one logical volume system on a given set of file-like objects. For example, you can have
        five disks or volumes with two separate LVM2 volume groups. This function is responsible for grouping
        the correct disks and volumes with each other, and correctly opening each distinct logical volume system.

        Args:
            volumes: A list of file-like objects to discover and open the logical volume systems on.

        Returns:
            An iterator of :class:`LogicalVolumeSystem`.
        """
        raise NotImplementedError()


class Volume(io.IOBase):
    """A representation of a volume on disk.

    It behaves like a regular file-like object with some additional information bound to it.

    Args:
        fh: The raw file-like object of the volume.
        number: The logical volume number of this volume within the volume system.
        offset: Where the volume starts relative to the start of the volume system.
        size: The size of the volume.
        vtype: What kind of volume it is.
        name: The name of the volume.
        guid: The unique identifier of the volume.
        raw: A reference to the implementation specific object that the volume system uses for representing the volume.
        disk: A reference to the associated :class:`~dissect.volume.disk.Disk`.
        vs: A reference to the associated :class:`VolumeSystem`.
        fs: A reference to the :class:`~dissect.target.filesystem.Filesystem` that is on this ``Volume``.
        drive_letter: The letter associated to the ``Volume``, such as `c` or `d` in Windows.
    """

    def __init__(
        self,
        fh: BinaryIO,
        number: int,
        offset: Optional[int],
        size: int,
        vtype: Optional[int],
        name: Optional[str],
        guid: Optional[str] = None,
        raw: Optional[BinaryIO] = None,
        disk: Optional[BinaryIO] = None,
        vs: Optional[VolumeSystem] = None,
        fs: Optional[Filesystem] = None,
        drive_letter: Optional[str] = None,
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

    def __repr__(self) -> str:
        return f"<Volume name={self.name!r} size={self.size!r} fs={self.fs!r}>"

    def read(self, length: int) -> bytes:
        """Read a ``length`` of bytes from this ``Volume``."""
        return self.fh.read(length)

    def readinto(self, b: bytearray) -> int:
        """Uses :func:`dissect.target.helpers.utils.readinto`."""
        return readinto(buffer=b, fh=self)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        """Change the stream position to ``offset``.

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
        """Returns the current seek position of the ``Volume``."""
        return self.fh.tell()

    def seekable(self) -> bool:
        """Returns whether ``seek`` can be used by this volume. Always ``True``."""
        return True


def open(fh: BinaryIO, *args, **kwargs) -> DissectVolumeSystem:
    """Open a :class:`~dissect.target.volumes.disk.DissectVolumeSystem` on the given file-like object.

    Args:
        fh: The file-like object to open a :class:`~dissect.target.volumes.disk.DissectVolumeSystem` on.

    Raises:
        VolumeSystemError: If opening the :class:`~dissect.target.volumes.disk.DissectVolumeSystem` failed.

    Returns:
        An opened :class:`~dissect.target.volumes.disk.DissectVolumeSystem`.
    """
    try:
        return disk.DissectVolumeSystem(fh)
    except Exception as e:
        raise VolumeSystemError(f"Failed to load volume system for {fh}", cause=e)


def is_lvm_volume(volume: BinaryIO) -> bool:
    """Determine whether the given file-like object belongs to any supported logical volume system.

    Args:
        volume: A file-like object to test if it is part of any logical volume system.
    """
    for logical_vs in LOGICAL_VOLUME_MANAGERS:
        try:
            if logical_vs.detect_volume(volume):
                return True
        except ImportError as e:
            log.warning("Failed to import %s", logical_vs)
            log.debug("", exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to detect logical volume for {volume}", cause=e)

    return False


def is_encrypted(volume: BinaryIO) -> bool:
    """Determine whether the given file-like object belongs to any supported encrypted volume system.

    Args:
        volume: A file-like object to test if it is part of any encrypted volume system.
    """
    for manager in ENCRYPTED_VOLUME_MANAGERS:
        try:
            if manager.detect(volume):
                return True
        except ImportError as e:
            log.warning("Failed to import %s", manager)
            log.debug("", exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to detect encrypted volume for {volume}", cause=e)
    return False


def open_encrypted(volume: BinaryIO) -> Iterator[Volume]:
    """Open an encrypted ``volume``.

    An encrypted volume can only be opened if the encrypted volume system can successfully decrypt the volume,
    meaning that the correct decryption key must be present in the :attr:`~dissect.target.helpers.keychain.KEYCHAIN`.

    The resulting :class:`Volume` object provides transparent decryption of the encrypted volume.

    Args:
        volume: A file-like object representing a :class:`Volume`.

    Returns:
        An iterator of decrypted :class:`Volume` objects as opened by the encrypted volume manager.
    """
    for manager_cls in ENCRYPTED_VOLUME_MANAGERS:
        try:
            if manager_cls.detect(volume):
                volume_manager = manager_cls(volume)
                yield from volume_manager.volumes
        except ImportError as e:
            log.warning("Failed to import %s", manager_cls)
            log.debug("", exc_info=e)
        except VolumeSystemError:
            log.exception(f"Failed to open an encrypted volume {volume} with volume manager {manager_cls}")
    return None


def open_lvm(volumes: list[BinaryIO], *args, **kwargs) -> Iterator[VolumeSystem]:
    """Open a single logical volume system on a list of file-like objects.

    Args:
        volumes: A list of file-like objects to open a logical volume system on.

    Returns:
        An iterator of all the :class:`Volume` objects opened by the logical volume system.
    """
    for logical_vs in LOGICAL_VOLUME_MANAGERS:
        try:
            yield from logical_vs.open_all(volumes)
        except ImportError as e:
            log.warning("Failed to import %s", logical_vs)
            log.debug("", exc_info=e)
        except Exception as e:
            raise VolumeSystemError(f"Failed to load logical volume system for {volumes}", cause=e)
