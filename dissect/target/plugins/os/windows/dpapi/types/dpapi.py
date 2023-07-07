import struct

from typing import BinaryIO
from dissect.target.plugins.os.windows.dpapi.types.masterkey import _CUUID, _RestOfData

from dissect import cstruct as _cstruct

_dpapi_def = """
struct DPAPIBlob
{
    DWORD dwVersion;
    UUID provider;
    DWORD mkVersion;
    UUID guid;
    DWORD flags;
    BYTES_WITH_LEN description;
    DWORD CipherAlgId;
    DWORD keyLen;
    BYTES_WITH_LEN salt;
    BYTES_WITH_LEN strong;
    DWORD CryptAlgId;
    DWORD hashLen;
    BYTES_WITH_LEN hmac;
    BYTES_WITH_LEN cipherText;
    DPAPI_BLOB blob;
    BYTES_WITH_LEN sign;
};

"""


class _BytesWithLen(_cstruct.BaseType):
    alignment = 0

    def _read(stream, _context):
        (byte_len,) = struct.unpack("<L", stream.read(4))
        return stream.read(byte_len)

    def _write(self, stream: BinaryIO, data) -> int:
        return stream.write(data)


class _Blob(_cstruct.BaseType):
    alignment = 0

    def _read(stream: BinaryIO, _context):
        orig_index = stream.tell()

        blobStart = _cstruct.cstruct().uint32.size + _CUUID.size
        stream.seek(blobStart)

        res = stream.read(orig_index - blobStart)
        assert stream.tell() == orig_index
        return res

    def _write(self, stream: BinaryIO, data) -> int:
        pass


_c_dpapi = _cstruct.cstruct()
_c_dpapi.addtype("UUID", _CUUID)
_c_dpapi.addtype("Bytes", _RestOfData)
_c_dpapi.addtype("BYTES_WITH_LEN", _BytesWithLen)
_c_dpapi.addtype("DPAPI_BLOB", _Blob)
_c_dpapi.load(_dpapi_def)

DPAPIBlobStruct = _c_dpapi.DPAPIBlob
