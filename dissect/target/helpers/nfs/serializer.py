from __future__ import annotations

import io
from typing import Union

from dissect.target.helpers.nfs.nfs3 import (
    CookieVerf3,
    EntryPlus3,
    FileAttributes3,
    FileHandle3,
    FileType3,
    MountOK,
    MountStat3,
    Nfs3Stat,
    NfsTime3,
    Read3args,
    Read3resok,
    ReadDirPlusParams,
    ReadDirPlusResult3,
    SpecData3,
)
from dissect.target.helpers.sunrpc.serializer import (
    Int32Serializer,
    OpaqueVarLengthSerializer,
    XdrDeserializer,
    XdrSerializer,
)
from dissect.target.helpers.sunrpc.sunrpc import Bool


# Used Union because 3.9 does not support '|' here even with future annotations
class MountResultDeserializer(XdrDeserializer[Union[MountOK, MountStat3]]):
    def deserialize(self, payload: io.BytesIO) -> MountOK | MountStat3:
        mount_stat = self._read_enum(payload, MountStat3)
        if mount_stat != MountStat3.OK:
            return mount_stat
        filehandle_bytes = self._read_var_length_opaque(payload)
        auth_flavors = self._read_var_length(payload, Int32Serializer())

        return MountOK(FileHandle3(filehandle_bytes), auth_flavors)


class ReadDirPlusParamsSerializer(XdrSerializer[ReadDirPlusParams]):
    def serialize(self, params: ReadDirPlusParams) -> bytes:
        result = self._write_var_length_opaque(params.dir.opaque)
        result += self._write_uint64(params.cookie)
        result += self._write_var_length_opaque(params.cookieverf.opaque)
        result += self._write_uint32(params.dir_count)
        result += self._write_uint32(params.max_count)

        return result


class SpecDataSerializer(XdrDeserializer[SpecData3]):
    def deserialize(self, payload: io.BytesIO) -> bytes:
        specdata1 = self._read_uint32(payload)
        specdata2 = self._read_uint32(payload)

        return SpecData3(specdata1, specdata2)


class NfsTimeSerializer(XdrDeserializer[NfsTime3]):
    def deserialize(self, payload: io.BytesIO) -> bytes:
        seconds = self._read_uint32(payload)
        nseconds = self._read_uint32(payload)

        return NfsTime3(seconds, nseconds)


class FileAttributesSerializer(XdrDeserializer[FileAttributes3]):
    def deserialize(self, payload: io.BytesIO) -> FileAttributes3:
        type = self._read_enum(payload, FileType3)
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

        return FileAttributes3(type, mode, nlink, uid, gid, size, used, rdev, fsid, fileid, atime, mtime, ctime)


class EntryPlusSerializer(XdrDeserializer[EntryPlus3]):
    def deserialize(self, payload: io.BytesIO) -> EntryPlus3:
        fileid = self._read_uint64(payload)
        name = self._read_string(payload)
        cookie = self._read_uint64(payload)
        attributes = self._read_optional(payload, FileAttributesSerializer())
        handle_bytes = self._read_optional(payload, OpaqueVarLengthSerializer())
        handle = FileHandle3(handle_bytes) if handle_bytes is not None else None

        return EntryPlus3(fileid, name, cookie, attributes, handle)


# Used Union because 3.9 does not support '|' here even with future annotations
class ReadDirPlusResultDeserializer(XdrDeserializer[Union[ReadDirPlusResult3, Nfs3Stat]]):
    def deserialize(self, payload: io.BytesIO) -> ReadDirPlusResult3:
        stat = self._read_enum(payload, Nfs3Stat)
        if stat != Nfs3Stat.OK:
            return stat

        dir_attributes = self._read_optional(payload, FileAttributesSerializer())
        cookieverf = self._read_var_length_opaque(payload)

        entries = list[EntryPlus3]()
        while True:
            entry = self._read_optional(payload, EntryPlusSerializer())
            if entry is None:
                break

            entries.append(entry)

        eof = self._read_enum(payload, Bool) == Bool.TRUE

        return ReadDirPlusResult3(dir_attributes, CookieVerf3(cookieverf), entries, eof)


class Read3ArgsSerializer(XdrSerializer[ReadDirPlusParams]):
    def serialize(self, args: Read3args) -> bytes:
        result = self._write_var_length_opaque(args.file.opaque)
        result += self._write_uint64(args.offset)
        result += self._write_uint32(args.count)
        return result


class Read3ResultDeserializer(XdrDeserializer[Read3resok]):
    def deserialize(self, payload: io.BytesIO) -> Read3resok:
        stat = self._read_enum(payload, Nfs3Stat)
        if stat != Nfs3Stat.OK:
            return stat

        file_attributes = self._read_optional(payload, FileAttributesSerializer())
        count = self._read_uint32(payload)
        eof = self._read_enum(payload, Bool) == Bool.TRUE
        data = self._read_var_length_opaque(payload)
        return Read3resok(file_attributes, count, eof, data)
