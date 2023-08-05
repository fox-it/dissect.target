from typing import BinaryIO

from dissect import cstruct as _cstruct

from dissect.target.plugins.os.windows.dpapi.types.masterkey import _CUUID

_dpapi_def = """
struct DPAPIBlob
{
    DWORD dwVersion;
    UUID provider;
    DPAPI_START_CAPTURE _start_capture;
    DWORD mkVersion;
    UUID guid;
    DWORD flags;
    DWORD descriptionLength;
    char description[descriptionLength];
    DWORD CipherAlgId;
    DWORD keyLen;
    DWORD saltLength;
    char salt[saltLength];
    DWORD strongLength;
    char strong[strongLength];
    DWORD CryptAlgId;
    DWORD hashLen;
    DWORD hmacLength;
    char hmac[hmacLength];
    DWORD cipherTextLength;
    char cipherText[cipherTextLength];
    DPAPI_END_CAPTURE blob[_start_capture];
    DWORD signLength;
    char sign[signLength];
};

"""


class _StartCapture(_cstruct.BaseType):
    """This records the current position of the seek. To be used later with `_EndCapture`"""

    alignment = 0

    def _read(stream: BinaryIO, *args, **kwargs) -> int:
        return stream.tell()

    def _write(self, stream: BinaryIO, *args, **kwargs) -> int:
        return 0


class _EndCapture(_cstruct.BaseType):
    """This captures a byte range.
    It returns all bytes between the passed offset (Which may be static, or the result of a `_StartCapture`).
    This is useful in case we need to extract a part of the struct as raw bytes, without parsing,
    in addition to the parsed version (For example, verifying content hash).
    """

    alignment = 0

    def _read_array(stream: BinaryIO, start_index: int, _context) -> bytes:
        curr_index = stream.tell()

        # Read all bytes from start_index until the current position
        stream.seek(start_index)
        res = stream.read(curr_index - start_index)

        # Make sure that our math is correct
        assert stream.tell() == curr_index
        return res

    def _read(stream: BinaryIO, *args, **kwargs) -> None:
        raise NotImplementedError

    def _write(self, stream: BinaryIO, *args, **kwargs) -> int:
        return 0


_c_dpapi = _cstruct.cstruct()
_c_dpapi.addtype("UUID", _CUUID)

# The capture classes allow for capturing all data between start and end.
# This is used for calculating the HMAC of the struct.
_c_dpapi.addtype("DPAPI_START_CAPTURE", _StartCapture)
_c_dpapi.addtype("DPAPI_END_CAPTURE", _EndCapture)

_c_dpapi.load(_dpapi_def)

DPAPIBlobStruct = _c_dpapi.DPAPIBlob
