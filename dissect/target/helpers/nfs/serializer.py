from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar, Union

from dissect.target.helpers.nfs.nfs3 import (
    CookieVerf,
    DirOpArgs,
    EntryPlus,
    FileAttributes,
    FileHandle,
    FileType,
    LookupResult,
    MountOK,
    MountStat,
    NfsStat,
    NfsTime,
    ReadDirPlusParams,
    ReadDirPlusResult,
    ReadlinkResult,
    ReadParams,
    ReadResult,
    SpecData,
)
from dissect.target.helpers.sunrpc.serializer import (
    Int32Serializer,
    OpaqueVarLengthSerializer,
    XdrDeserializer,
    XdrSerializer,
)
from dissect.target.helpers.sunrpc.sunrpc import Bool

if TYPE_CHECKING:
    import io


# Used Union because 3.9 does not support '|' here even with future annotations
class MountResultDeserializer(XdrDeserializer[Union[MountOK, MountStat]]):
    def deserialize(self, payload: io.BytesIO) -> MountOK | MountStat:
        mount_stat = self._read_enum(payload, MountStat)
        if mount_stat != MountStat.OK:
            return mount_stat

        filehandle_bytes = self._read_var_length_opaque(payload)
        auth_flavors = self._read_var_length(payload, Int32Serializer())

        return MountOK(FileHandle(filehandle_bytes), auth_flavors)


class ReadDirPlusParamsSerializer(XdrSerializer[ReadDirPlusParams]):
    def serialize(self, params: ReadDirPlusParams) -> bytes:
        result = self._write_var_length_opaque(params.dir.opaque)
        result += self._write_uint64(params.cookie)
        result += self._write_var_length_opaque(params.cookieverf.opaque)
        result += self._write_uint32(params.dir_count)
        result += self._write_uint32(params.max_count)

        return result


class SpecDataSerializer(XdrDeserializer[SpecData]):
    def deserialize(self, payload: io.BytesIO) -> bytes:
        specdata1 = self._read_uint32(payload)
        specdata2 = self._read_uint32(payload)

        return SpecData(specdata1, specdata2)


class NfsTimeSerializer(XdrDeserializer[NfsTime]):
    def deserialize(self, payload: io.BytesIO) -> bytes:
        seconds = self._read_uint32(payload)
        nseconds = self._read_uint32(payload)

        return NfsTime(seconds, nseconds)


class FileAttributesSerializer(XdrDeserializer[FileAttributes]):
    def deserialize(self, payload: io.BytesIO) -> FileAttributes:
        type = self._read_enum(payload, FileType)
        mode = self._read_uint32(payload)
        nlink = self._read_uint32(payload)
        uid = self._read_uint32(payload)
        gid = self._read_uint32(payload)
        size = self._read_uint64(payload)
        used = self._read_uint64(payload)
        rdev = SpecDataSerializer().deserialize(payload)
        fsid = self._read_uint64(payload)
        fileid = self._read_uint64(payload)
        time_deserializer = NfsTimeSerializer()
        atime = time_deserializer.deserialize(payload)
        mtime = time_deserializer.deserialize(payload)
        ctime = time_deserializer.deserialize(payload)

        return FileAttributes(type, mode, nlink, uid, gid, size, used, rdev, fsid, fileid, atime, mtime, ctime)


class EntryPlusSerializer(XdrDeserializer[EntryPlus]):
    def deserialize(self, payload: io.BytesIO) -> EntryPlus:
        fileid = self._read_uint64(payload)
        name = self._read_string(payload)
        cookie = self._read_uint64(payload)
        attributes = self._read_optional(payload, FileAttributesSerializer())
        handle_bytes = self._read_optional(payload, OpaqueVarLengthSerializer())
        handle = FileHandle(handle_bytes) if handle_bytes is not None else None

        return EntryPlus(fileid, name, cookie, attributes, handle)


# Used Union because 3.9 does not support '|' here even with future annotations
class ReadDirPlusResultDeserializer(XdrDeserializer[ReadDirPlusResult]):
    def deserialize(self, payload: io.BytesIO) -> ReadDirPlusResult:
        dir_attributes = self._read_optional(payload, FileAttributesSerializer())
        cookieverf = self._read_var_length_opaque(payload)

        entries = list[EntryPlus]()
        while True:
            entry = self._read_optional(payload, EntryPlusSerializer())
            if entry is None:
                break

            entries.append(entry)

        eof = self._read_enum(payload, Bool) == Bool.TRUE

        return ReadDirPlusResult(dir_attributes, CookieVerf(cookieverf), entries, eof)


class Read3ArgsSerializer(XdrSerializer[ReadDirPlusParams]):
    def serialize(self, args: ReadParams) -> bytes:
        result = self._write_var_length_opaque(args.file.opaque)
        result += self._write_uint64(args.offset)
        result += self._write_uint32(args.count)
        return result


# In contrast to rfc we do not return file attributes on failure
class Read3ResultDeserializer(XdrDeserializer[ReadResult]):
    def deserialize(self, payload: io.BytesIO) -> ReadResult:
        file_attributes = self._read_optional(payload, FileAttributesSerializer())
        count = self._read_uint32(payload)
        eof = self._read_enum(payload, Bool) == Bool.TRUE
        data = self._read_var_length_opaque(payload)
        return ReadResult(file_attributes, count, eof, data)


class DirOpArgs3Serializer(XdrSerializer[DirOpArgs]):
    def serialize(self, args: DirOpArgs) -> bytes:
        result = self._write_var_length_opaque(args.handle.opaque)
        result += self._write_string(args.filename)
        return result


class Lookup3ResultDeserializer(XdrDeserializer[LookupResult]):
    def deserialize(self, payload: io.BytesIO) -> LookupResult:
        handle_bytes = self._read_var_length_opaque(payload)
        attribute_serializer = FileAttributesSerializer()
        object_attributes = self._read_optional(payload, attribute_serializer)
        dir_attributes = self._read_optional(payload, attribute_serializer)

        return LookupResult(
            object=FileHandle(handle_bytes), obj_attributes=object_attributes, dir_attributes=dir_attributes
        )


class ReadLink3ResultDeserializer(XdrDeserializer[ReadlinkResult]):
    def deserialize(self, payload: io.BytesIO) -> ReadlinkResult:
        attributes = self._read_optional(payload, FileAttributesSerializer())
        target = self._read_string(payload)

        return ReadlinkResult(attributes, target)


ResultType = TypeVar("ResultType")


# RdJ: Consider implementing in terms of a monadic bind, using generators
class ResultDeserializer(XdrDeserializer[Union[ResultType, NfsStat]]):
    """A higher order deserializer that returns a result or an NFS status."""

    def __init__(self, deserializer: XdrDeserializer[ResultType]):
        self._deserializer = deserializer

    def deserialize(self, payload: io.BytesIO) -> ResultType | NfsStat:
        stat = self._read_enum(payload, NfsStat)
        if stat != NfsStat.OK:
            return stat

        return self._deserializer.deserialize(payload)
