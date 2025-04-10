from __future__ import annotations

import io
import logging
from struct import error as StructError
from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct
from dissect.ole import OLE
from dissect.ole.exceptions import Error as OleError
from dissect.shellitem.lnk import Lnk

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.shell_application_ids import APPLICATION_IDENTIFIERS
from dissect.target.helpers.utils import findall
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.lnk import LnkRecord, parse_lnk_file

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

log = logging.getLogger(__name__)

LNK_GUID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

JumpListRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/jumplist",
    [
        ("string", "type"),
        ("string", "application_id"),
        ("string", "application_name"),
        *LnkRecord.target_fields,
    ],
)


custom_destination_def = """
struct header {
    int version;
    int unknown1;
    int unknown2;
    int value_type;
}

struct header_end {
    int number_of_entries;
}

struct header_end_0 {
    uint16  name_length;
    wchar   name[name_length];
    int     number_of_entries;
}

struct footer {
    char magic[4];
}
"""

c_custom_destination = cstruct()
c_custom_destination.load(custom_destination_def)


class JumpListFile:
    def __init__(self, fh: BinaryIO, file_name: str):
        self.fh = fh
        self.file_name = file_name

        self.application_id, self.application_type = file_name.split(".")
        self.application_type = self.application_type.split("-")[0]
        self.application_name = APPLICATION_IDENTIFIERS.get(self.application_id)

    def __iter__(self) -> Iterator[Lnk]:
        raise NotImplementedError

    @property
    def name(self) -> str:
        """Return the name of the application."""
        return self.application_name

    @property
    def id(self) -> str:
        """Return the application identifier."""
        return self.application_id

    @property
    def type(self) -> str:
        """Return the type of the Jump List file."""
        return self.application_type


class AutomaticDestinationFile(JumpListFile):
    """Parse Jump List AutomaticDestination file."""

    def __init__(self, fh: BinaryIO, file_name: str):
        super().__init__(fh, file_name)
        self.ole = OLE(self.fh)

    def __iter__(self) -> Iterator[Lnk]:
        for dir_name in self.ole.root.listdir():
            if dir_name == "DestList":
                continue

            dir = self.ole.get(dir_name)

            for item in dir.open():
                try:
                    yield Lnk(io.BytesIO(item))
                except StructError:  # noqa: PERF203
                    continue
                except Exception as e:
                    log.warning("Failed to parse LNK file from directory %s", dir_name)
                    log.debug("", exc_info=e)
                    continue


class CustomDestinationFile(JumpListFile):
    """Parse Jump List CustomDestination file."""

    MAGIC_FOOTER = 0xBABFFBAB
    VERSIONS = (2,)

    def __init__(self, fh: BinaryIO, file_name: str):
        super().__init__(fh, file_name)

        self.fh.seek(-4, io.SEEK_END)
        self.footer = c_custom_destination.footer(self.fh.read(4))
        self.magic = int.from_bytes(self.footer.magic, "little")

        self.fh.seek(0, io.SEEK_SET)
        self.header = c_custom_destination.header(self.fh)
        self.version = self.header.version

        if self.header.value_type == 0:
            self.header_end = c_custom_destination.header_end_0(self.fh)
        elif self.header.value_type in [1, 2]:
            self.header_end = c_custom_destination.header_end(self.fh)
        else:
            raise NotImplementedError(
                f"The value_type ({self.header.value_type}) of the CustomDestination file is not implemented"
            )

        if self.version not in self.VERSIONS:
            raise NotImplementedError(f"The CustomDestination file has an unsupported version: {self.version}")

        if self.magic != self.MAGIC_FOOTER:
            raise ValueError(f"The CustomDestination file has an invalid magic footer: {self.magic}")

    def __iter__(self) -> Iterator[Lnk]:
        # Searches for all LNK GUID's because the number of entries in the header is not always correct.
        buf = self.fh.read()

        for offset in findall(buf, LNK_GUID):
            try:
                lnk = Lnk(io.BytesIO(buf[offset + len(LNK_GUID) :]))
                yield lnk
            except EOFError:  # noqa: PERF203
                break
            except Exception as e:
                log.warning("Failed to parse LNK file from a CustomDestination file")
                log.debug("", exc_info=e)
                continue


class JumpListPlugin(Plugin):
    """Jump List is a Windows feature introduced in Windows 7.

    It stores information about recently accessed applications and files.

    References:
        - https://forensics.wiki/jump_lists
        - https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
    """

    __namespace__ = "jumplist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.automatic_destinations = []
        self.custom_destinations = []

        for user_details in self.target.user_details.all_with_home():
            for destination in user_details.home_path.glob(
                "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms"
            ):
                self.custom_destinations.append([destination, user_details.user])

        for user_details in self.target.user_details.all_with_home():
            for destination in user_details.home_path.glob(
                "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms"
            ):
                self.automatic_destinations.append([destination, user_details.user])

    def check_compatible(self) -> None:
        if not any([self.automatic_destinations, self.custom_destinations]):
            raise UnsupportedPluginError("No Jump List files found")

    @export(record=JumpListRecord)
    def custom_destination(self) -> Iterator[JumpListRecord]:
        """Return the content of CustomDestination Windows Jump Lists.

        These are created when a user pins an application or a file in a Jump List.

        Yields JumpListRecord with fields:

        .. code-block:: text

            type (string): Type of Jump List.
            application_id (string): ID of the application.
            application_name (string): Name of the application.
            lnk_path (path): Path of the link (.lnk) file.
            lnk_name (string): Name of the link (.lnk) file.
            lnk_mtime (datetime): Modification time of the link (.lnk) file.
            lnk_atime (datetime): Access time of the link (.lnk) file.
            lnk_ctime (datetime): Creation time of the link (.lnk) file.
            lnk_relativepath (path): Relative path of target file to the link (.lnk) file.
            lnk_workdir (path): Path of the working directory the link (.lnk) file will execute from.
            lnk_iconlocation (path): Path of the display icon used for the link (.lnk) file.
            lnk_arguments (string): Command-line arguments passed to the target (linked) file.
            local_base_path (string): Absolute path of the target (linked) file.
            common_path_suffix (string): Suffix of the local_base_path.
            lnk_full_path (string): Full path of the linked file. Made from local_base_path and common_path_suffix.
            lnk_net_name (string): Specifies a server share path; for example, "\\\\server\\share".
            lnk_device_name (string): Specifies a device; for example, the drive letter "D:"
            machine_id (string): The NetBIOS name of the machine where the linked file was last known to reside.
            target_mtime (datetime): Modification time of the target (linked) file.
            target_atime (datetime): Access time of the target (linked) file.
            target_ctime (datetime): Creation time of the target (linked) file.
        """
        yield from self._generate_records(self.custom_destinations, CustomDestinationFile)

    @export(record=JumpListRecord)
    def automatic_destination(self) -> Iterator[JumpListRecord]:
        """Return the content of AutomaticDestination Windows Jump Lists.

        These are created automatically when a user opens an application or file.

        Yields JumpListRecord with fields:

        .. code-block:: text

            type (string): Type of Jump List.
            application_id (string): ID of the application.
            application_name (string): Name of the application.
            lnk_path (path): Path of the link (.lnk) file.
            lnk_name (string): Name of the link (.lnk) file.
            lnk_mtime (datetime): Modification time of the link (.lnk) file.
            lnk_atime (datetime): Access time of the link (.lnk) file.
            lnk_ctime (datetime): Creation time of the link (.lnk) file.
            lnk_relativepath (path): Relative path of target file to the link (.lnk) file.
            lnk_workdir (path): Path of the working directory the link (.lnk) file will execute from.
            lnk_iconlocation (path): Path of the display icon used for the link (.lnk) file.
            lnk_arguments (string): Command-line arguments passed to the target (linked) file.
            local_base_path (string): Absolute path of the target (linked) file.
            common_path_suffix (string): Suffix of the local_base_path.
            lnk_full_path (string): Full path of the linked file. Made from local_base_path and common_path_suffix.
            lnk_net_name (string): Specifies a server share path; for example, "\\\\server\\share".
            lnk_device_name (string): Specifies a device; for example, the drive letter "D:"
            machine_id (string): The NetBIOS name of the machine where the linked file was last known to reside.
            target_mtime (datetime): Modification time of the target (linked) file.
            target_atime (datetime): Access time of the target (linked) file.
            target_ctime (datetime): Creation time of the target (linked) file.
        """
        yield from self._generate_records(self.automatic_destinations, AutomaticDestinationFile)

    def _generate_records(
        self,
        destinations: list,
        destination_file: AutomaticDestinationFile | CustomDestinationFile,
    ) -> Iterator[JumpListRecord]:
        for destination, user in destinations:
            fh = destination.open("rb")

            try:
                jumplist = destination_file(fh, destination.name)
            except OleError:
                continue
            except Exception as e:
                self.target.log.warning("Failed to parse Jump List file: %s", destination)
                self.target.log.debug("", exc_info=e)
                continue

            for lnk in jumplist:
                if lnk := parse_lnk_file(self.target, lnk, destination):
                    yield JumpListRecord(
                        type=jumplist.type,
                        application_name=jumplist.name,
                        application_id=jumplist.id,
                        **lnk._asdict(),
                        _user=user,
                        _target=self.target,
                    )
