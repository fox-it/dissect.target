from dissect.util.stream import AlignedStream

from dissect.target.filesystem import VirtualFilesystem, VirtualFile
from dissect.target.helpers import fsutil


class ITunesFilesystem(VirtualFilesystem):
    def __init__(self, backup):
        super().__init__()
        self.backup = backup

        for file in self.backup.files():
            if file.flags != 2:
                self.map_file_entry(file.translated_path, ITunesFile(self, file.translated_path, file))

    @staticmethod
    def detect(fh):
        raise TypeError("Detect is not allowed on ITunesFilesystem class")


class ITunesFile(VirtualFile):
    def open(self):
        if self.entry.backup.encrypted:
            return EncryptedFileStream(self.entry)
        return self.entry.get().open("rb")

    def stat(self):
        metadata = self.entry.metadata
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                metadata["Mode"],
                metadata["InodeNumber"],
                id(self.fs),
                0,
                metadata["UserID"],
                metadata["GroupID"],
                metadata["Size"],
                0,
                metadata["LastModified"],
                metadata["Birth"],
            ]
        )


class EncryptedFileStream(AlignedStream):
    """Transparently decrypted AES-CBC decrypted stream."""

    def __init__(self, file_info):
        super().__init__(file_info.size)
        self.file_info = file_info
        self.fh = file_info.get().open("rb")

        self.cipher = None
        self.cipher_offset = 0

        self._reset_cipher()

    def _reset_cipher(self):
        self.cipher = self.file_info.create_cipher()
        self.cipher_offset = 0

    def _seek_cipher(self, offset):
        """CBC is dependent on previous blocks so to seek the cipher, decrypt and discard to the wanted offset."""
        if offset < self.cipher_offset:
            self._reset_cipher()
            self.fh.seek(0)

        while self.cipher_offset < offset:
            read_size = min(offset - self.cipher_offset, self.align)
            self.cipher.decrypt(self.fh.read(read_size))
            self.cipher_offset += read_size

    def _read(self, offset, length):
        self._seek_cipher(offset)

        data = self.cipher.decrypt(self.fh.read(length))
        self.cipher_offset += length

        return data
