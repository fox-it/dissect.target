import io

from dissect.target.helpers.nfs.nfs import (
    CookieVerf3,
    EntryPlus3,
    FileAttributes3,
    FileHandle3,
    FileType3,
    MountOK,
    MountStat,
    NfsStat,
    NfsTime3,
    ReadDirPlusParams,
    ReadDirPlusResult3,
    SpecData3,
)
from dissect.target.helpers.sunrpc.serializer import (
    Deserializer,
    Int32Serializer,
    OpaqueVarLengthSerializer,
    Serializer,
)
from dissect.target.helpers.sunrpc.sunrpc import Bool


class MountResultDeserializer(Deserializer[MountOK | MountStat]):
    def deserialize(self, payload: io.BytesIO) -> MountOK | None:
        mountStat = self._read_enum(payload, MountStat)
        if mountStat != MountStat.MNT3_OK:
            return mountStat
        filehandle_bytes = self._read_var_length_opaque(payload)
        authFlavors = self._read_var_length(payload, Int32Serializer())

        return MountOK(FileHandle3(filehandle_bytes), authFlavors)


class ReadDirPlusParamsSerializer(Serializer[ReadDirPlusParams]):
    def serialize(self, params: ReadDirPlusParams) -> bytes:
        result = self._write_var_length_opaque(params.dir.opaque)
        result += self._write_uint64(params.cookie)
        result += self._write_var_length_opaque(params.cookieverf.opaque)
        result += self._write_uint32(params.dir_count)
        result += self._write_uint32(params.max_count)

        return result


class SpecDataSerializer(Deserializer[SpecData3]):
    def deserialize(self, payload: io.BytesIO) -> bytes:
        specdata1 = self._read_uint32(payload)
        specdata2 = self._read_uint32(payload)

        return SpecData3(specdata1, specdata2)


class NfsTimeSerializer(Deserializer[NfsTime3]):
    def deserialize(self, payload: io.BytesIO) -> bytes:
        seconds = self._read_uint32(payload)
        nseconds = self._read_uint32(payload)

        return NfsTime3(seconds, nseconds)


class FileAttributesSerializer(Deserializer[FileAttributes3]):
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
        timeDeserializer = NfsTimeSerializer()
        atime = timeDeserializer.deserialize(payload)
        mtime = timeDeserializer.deserialize(payload)
        ctime = timeDeserializer.deserialize(payload)

        return FileAttributes3(type, mode, nlink, uid, gid, size, used, rdev, fsid, fileid, atime, mtime, ctime)


class EntryPlusSerializer(Deserializer[EntryPlus3]):
    def deserialize(self, payload: io.BytesIO) -> EntryPlus3:
        fileid = self._read_uint64(payload)
        name = self._read_string(payload)
        cookie = self._read_uint64(payload)
        attributes = self._read_optional(payload, FileAttributesSerializer())
        handleBytes = self._read_optional(payload, OpaqueVarLengthSerializer())
        handle = FileHandle3(handleBytes) if handleBytes is not None else None

        return EntryPlus3(fileid, name, cookie, attributes, handle)


class ReadDirPlusResultDeserializer(Deserializer[ReadDirPlusResult3 | NfsStat]):
    def deserialize(self, payload: io.BytesIO) -> ReadDirPlusResult3:
        stat = self._read_enum(payload, NfsStat)
        if stat != NfsStat.NFS3_OK:
            return stat

        dir_attributes = self._read_optional(payload, FileAttributesSerializer())
        cookieverf = self._read_var_length_opaque(payload)

        entries = list[EntryPlus3]()
        while True:
            entry = self._read_optional(payload, EntryPlusSerializer())
            if entry is None:
                break

            entries.append(entry)

        eof = self._read_enum(payload, Bool)

        return ReadDirPlusResult3(dir_attributes, CookieVerf3(cookieverf), entries, eof)
