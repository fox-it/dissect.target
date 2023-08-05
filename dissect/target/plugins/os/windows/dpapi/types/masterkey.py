from typing import BinaryIO
from uuid import UUID

from dissect import cstruct as _cstruct

_dpapi_def = """
struct DomainKey
{
    DWORD dwVersion;
    DWORD secretLen;
    DWORD accessCheckLen;
    UUID guid;
    BYTE encryptedSecret[secretLen];
    BYTE accessCheckLen[accessCheckLen];
};

struct CredHist
{
    DWORD dwVersion;
    UUID guid;
};

struct MasterKey
{
    DWORD dwVersion;
    BYTE pSalt[0x10];
    DWORD dwPBKDF2IterationCount;
    // This is actually ALG_ID
    DWORD HMACAlgId;
    // This is actually ALG_ID
    DWORD CryptAlgId;
    Bytes pKey;
};

struct CredSystem
{
    DWORD dwRevision;
    BYTE pMachine[0x14];
    BYTE pUser[0x14];
};

struct MasterKeyFileHeader
{
    // Masterkey version. Should be 1 or 2
    DWORD dwVersion;
    DWORD dwReserved1;
    DWORD dwReserved2;
    // Guid of master key. Should match filename
    WCHAR szGuid[0x24];
    DWORD dwUnused1;
    DWORD dwUnused2;
    DWORD dwPolicy;
    QWORD qwUserKeySize;
    QWORD qwLocalEncKeySize;
    QWORD qwLocalKeySize;
    QWORD qwDomainKeySize;
};
"""


class _RestOfData(_cstruct.BaseType):
    alignment = 0

    def _read(stream, _context):
        return stream.read()

    @staticmethod
    def _write(stream: BinaryIO, data: bytes) -> int:
        return stream.write(data)


class _CUUID(_cstruct.BaseType):
    alignment = 0
    size = 16

    def _read(stream, _context):
        return str(UUID(bytes_le=stream.read(16)))

    def _write(self, stream: BinaryIO, data) -> int:
        stream.write(data.bytes_le)


_c_dpapi = _cstruct.cstruct()
_c_dpapi.addtype("UUID", _CUUID)
_c_dpapi.addtype("Bytes", _RestOfData)
_c_dpapi.load(_dpapi_def)

CredHist = _c_dpapi.CredHist
CredSystem = _c_dpapi.CredSystem
DomainKey = _c_dpapi.DomainKey
MasterKeyFileHeader = _c_dpapi.MasterKeyFileHeader
MasterKey = _c_dpapi.MasterKey
