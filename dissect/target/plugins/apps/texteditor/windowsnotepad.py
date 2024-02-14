import zlib
from typing import BinaryIO, Iterator

from dissect.target.exceptions import CRCMismatchException, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import export
from dissect.target.plugins.apps.texteditor.texteditor import (
    GENERIC_TAB_CONTENTS_RECORD_FIELDS,
    TexteditorTabPlugin,
)


def parse_large_structure_data_length(fh: BinaryIO) -> (int, bytes):
    """
    Read a variable-length representation of a length field. Acts much like a ``varint`` object
    from ``dissect.ntfs``, however it introduces some additional bit shifts and masking.

    The position of ``fh`` will be restored before returning.

    Args:
        fh: A file-like object where we want to read the length bytes from.

    Returns:
        Length of the data as an integer
        The original bytes that have been processed to determine the length
    """
    offset = fh.tell()
    original_bytes = b""
    modified_bytes = b""

    while True:
        # Read the original byte
        bt = fh.read(1)

        # Transform into an integer
        bt_int = int.from_bytes(bt)

        # Shift this new byte a few places to the right, depending on the number of bytes that have already
        # been processed
        new_bt = bt_int >> len(original_bytes)

        # Add this byte back to
        modified_bytes += new_bt.to_bytes(length=1)

        # Add the processed byte to the list of original by tes
        original_bytes += bt

        # If the first bit of the original byte is a zero, this is the final byte
        # Otherwise, continue until we find the zero-led byte
        if not bt_int & 128:
            break

    # Convert it to an integer
    f = int.from_bytes(bytes=modified_bytes, byteorder="little")

    # Apply the mask
    f = f ^ (2 ** ((len(original_bytes) - 1) * 8) >> 1)

    # Restore to original cursor
    fh.seek(offset)

    return f, original_bytes


def _calc_crc32(data: bytes) -> bytes:
    """Perform a CRC32 checksum on the data and return it as a big-endian uint32"""
    return zlib.crc32(data).to_bytes(length=4, byteorder="big")


def _parse_large_structure_tab(handle: BinaryIO, header_has_crc: bool, header: bytes) -> str:
    # A dictionary where the data will be stored in the correct order
    content = dict()

    while True:
        offset_bytes = handle.read(2)

        # If we reach the end of the file, break
        if offset_bytes == b"":
            break

        offset = int.from_bytes(offset_bytes, byteorder="big")

        # Parse the length field based on the first one, two, three or four bytes.
        data_length, data_length_bytes = parse_large_structure_data_length(handle)

        # Move the cursor past the length bytes
        handle.seek(handle.tell() + len(data_length_bytes))

        chunk_data = b""
        for i in range(data_length):
            r = handle.read(2)
            chunk_data += r

        # Insert the chunk data into the correct offset. I have not yet encountered a file
        # where the chunks were placed in a non-sequential order, but you never know.
        for i in range(len(chunk_data)):
            content[offset + i] = chunk_data[i].to_bytes(length=1)

        # CRC32 consists of the following data
        crc_data_reconstructed = offset_bytes + data_length_bytes + chunk_data

        # If the header did not have a CRC, this means that it is combined with the only data entry
        # in the file. So we need to prepend this extra header data.
        if not header_has_crc:
            # Furthermore, if the header does not have its own CRC32 it
            # places a byte at the end to indicate the start
            # of the CRC32. This should be included in the CRC32 calculation
            crc_data_reconstructed = header + crc_data_reconstructed + handle.read(1)

        # Finally, read the CRC32 from disk and compare it
        crc32_on_disk = handle.read(4)

        crc32_calculated = _calc_crc32(crc_data_reconstructed)

        if not crc32_on_disk == crc32_calculated:
            raise CRCMismatchException(message=f"data, calculated={crc32_calculated}, expected={crc32_on_disk}")

    # Reconstruct the text
    text_reconstructed = b"".join(content.values())
    text = text_reconstructed.decode("utf-16-le")
    return text


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
        handle: BinaryIO = file.open(mode="rb")

        # Skip the presumed magic bytes 0x4e5000 (NP\x00)
        handle.read(3)

        # Read some of the info in the header. Not entirely sure at this point what info is in there,
        # there seems to be an indication of the length of the file.
        header = handle.read(6)

        # Whenever the bytes between the two \x01 bytes in the header are zeroed out, it means that the
        # header itself has a CRC32 checksum
        header_has_crc32 = True if header[2:4] == b"\x00\x00" else False

        if header_has_crc32:
            # Header CRC32 is composed of the header, plus four more bytes.
            header_crc_data = header + handle.read(4)
            # After that, the CRC32 of the header is stored.
            header_crc_on_disk = handle.read(4)

            # This should match
            header_crc_calculated = _calc_crc32(header_crc_data)
            if not header_crc_on_disk == header_crc_calculated:
                raise CRCMismatchException(
                    message=f"header, calculated={header_crc_calculated}, " f"expected={header_crc_on_disk}"
                )

        text = _parse_large_structure_tab(handle, header_has_crc32, header)

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
