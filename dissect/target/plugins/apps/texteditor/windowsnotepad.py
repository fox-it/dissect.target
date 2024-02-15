import io
import zlib
from typing import BinaryIO, Iterator

from dissect import cstruct

from dissect.target.exceptions import CRCMismatchException, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorTabPlugin,
)

c_def = """
struct data_entry_multi_block {
    uint16    offset;
    uleb128   len;
    char      data[len * 2];
    char      crc32[4];
};

struct data_entry_single_block {
    uint16    offset;
    uleb128   len;
    char      data[len * 2];
    char      unk1;
    char      crc32[4];
};

struct tab_header {
    char      magic[3];         // NP\x00
    char      header_start[2];  // \x00\x01
    uleb128   len1;
    uleb128   len2;
    char      header_end[2];    // \x01\x00
};

struct tab_crc {
    char      unk[4];
    char      crc32[4];
};
"""

c_windowstab = cstruct.cstruct()
c_windowstab.load(c_def)


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as a big-endian uint32"""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


def seek_size(fh: BinaryIO) -> int:
    """
    Find the size of a file on disk.

    Args:
        fh: A file-like object that we want to calculate the size of.

    Returns:
        An integer representing the size (in bytes) of the file.
    """
    pos = fh.tell()
    fh.seek(0, io.SEEK_END)
    size = fh.tell()
    fh.seek(pos)
    return size


class WindowsNotepadPlugin(TexteditorTabPlugin):
    """Windows notepad tab content plugin."""

    __namespace__ = "windowsnotepad"

    DIRECTORY = "AppData/Local/Packages/Microsoft.WindowsNotepad_8wekyb3d8bbwe/LocalState/TabState"
    TextEditorTabRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
        "texteditor/windowsnotepad/tab", GENERIC_TAB_CONTENTS_RECORD_FIELDS
    )

    def __init__(self, target):
        super().__init__(target)
        self.users_dirs = []
        for user_details in self.target.user_details.all_with_home():
            cur_dir = user_details.home_path.joinpath(self.DIRECTORY)
            if not cur_dir.exists():
                continue
            self.users_dirs.append((user_details.user, cur_dir))

    def check_compatible(self) -> None:
        if not len(self.users_dirs):
            raise UnsupportedPluginError("No tabs directories found")

    def _process_tab_file(self, file: TargetPath) -> TextEditorTabRecord:
        """
        Function that parses a binary tab file and reconstructs the contents.

        Args:
            file: The binary file on disk that needs to be parsed.

        Returns:
            A TextEditorTabRecord containing information that is in the tab.
        """
        fh: BinaryIO = file.open(mode="rb")

        # There is always a 4 byte value at the end. The offset is always 2 bytes, and the length is always at
        # least 1 byte. That means that if we reach the end of a data section, and we have equal or less
        # than 4 + 2 + 1 = 7 bytes left, we should stop parsing new data blobs.
        data_threshold = seek_size(fh) - 4 - 2 - 1

        # Parse the generic header
        header = c_windowstab.tab_header(fh)

        # Some tabs are stored as one big block. In this case, the data is contiguous and the file
        # only contains one CRC32 at the end which checksums the entire file (excluding the file magic).
        # It is likely stored as a single block whenever a length field is nonzero in the header.
        is_single_blob = header.len1 != 0

        if is_single_blob:
            # In this case, we parse the single block
            data_entry = c_windowstab.data_entry_single_block(fh)

            # The header (minus the magic) plus all data (exluding the CRC32 at the end) is included
            actual_crc32 = _calc_crc32(header.dumps()[3:] + data_entry.dumps()[:-4])

            if data_entry.crc32 != actual_crc32:
                raise CRCMismatchException(
                    f"CRC32 mismatch in single-block file. "
                    f"expected={data_entry.crc32.hex()}, actual={actual_crc32.hex()} "
                )

            # Finally, decode the block using UTF16-LE, common for Windows.
            text = data_entry.data.decode("utf-16-le")

        else:
            # In this case, the header contains a separate CRC32 checksum as well
            header_crc = c_windowstab.tab_crc(fh)

            # The header, minus the file magic, plus some bytes from the extra header are
            # required in the calculation
            assert header_crc.crc32 == _calc_crc32(header.dumps()[3:] + header_crc.unk.dumps())

            # We don't know how many blocks there will be beforehand. So we also don't know the exact file
            # size, since the file, next to data, also contains quite some metadata and checksums.
            # Also, because blocks can possibly be present in a non-contiguous order, a list is used
            # that gradually increases in size. This allows for quick and flexible insertion of chars.
            text = ["\x00"] * 100

            while fh.tell() < data_threshold:
                data_entry = c_windowstab.data_entry_multi_block(fh)

                # Check for CRC mismatch in a data block
                actual_crc32 = _calc_crc32(data_entry.dumps()[:-4])
                if data_entry.crc32 != actual_crc32:
                    raise CRCMismatchException(
                        f"CRC32 mismatch in single-block file. "
                        f"expected={data_entry.crc32.hex()}, actual={actual_crc32.hex()} "
                    )

                # Since we don't know the size of the file in the beginning, gradually increase the size
                # of the list that holds the data if there is not enough room
                while data_entry.offset + data_entry.len > len(text) and data_entry.len > 0:
                    text += ["\x00"] * 100

                # Place the text at the correct offset. UTF16-LE consumes two bytes for one character.
                for i in range(data_entry.len):
                    text[data_entry.offset + i] = data_entry.data[(2 * i) : (2 * i) + 2].decode("utf-16-le")

            # Join the chars and strip off excess null bytes that may be present
            text = "".join(text).rstrip("\x00")

        return self.TextEditorTabRecord(content=text, content_length=len(text), filename=file.name)

    @export(record=TextEditorTabRecord)
    def tabs(self) -> Iterator[TextEditorTabRecord]:
        """Return contents from the notepad tab.

        Yields TextEditorTabRecord with the following fields:
            contents (string): The contents of the tab.
            title (string): The title of the tab.
        """
        for user, directory in self.users_dirs:
            for file in self.target.fs.path(directory).iterdir():
                if file.name.endswith(".1.bin") or file.name.endswith(".0.bin"):
                    continue

                try:
                    yield self._process_tab_file(file)
                except CRCMismatchException as e:
                    self.target.log.warning("CRC32 checksum mismatch in file: %s", file.name, exc_info=e)
                    continue
