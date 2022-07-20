import hashlib

from flow.record import GroupedRecord, Record, RecordDescriptor
from flow.record.fieldtypes import uri

from dissect.target.exceptions import FileNotFoundError, IsADirectoryError
from dissect.target.plugins.filesystem.resolver import ResolverPlugin

BUFFER_SIZE = 32768

HashRecord = RecordDescriptor(
    "filesystem/file/digest",
    [
        ("uri[]", "paths"),
        ("digest[]", "digests"),
    ],
)


def _hash(fh, ctx):
    if not isinstance(ctx, list):
        ctx = [ctx]

    ctx = [c() for c in ctx]
    data = fh.read(BUFFER_SIZE)
    while data:
        [c.update(data) for c in ctx]
        data = fh.read(BUFFER_SIZE)

    return tuple(c.hexdigest() for c in ctx)


def md5(fh):
    return _hash(fh, hashlib.md5)[0]


def sha1(fh):
    return _hash(fh, hashlib.sha1)[0]


def sha256(fh):
    return _hash(fh, hashlib.sha256)[0]


def common(fh):
    return _hash(fh, [hashlib.md5, hashlib.sha1, hashlib.sha256])


def custom(fh, algos):
    if isinstance(algos[0], str):
        ctx = [getattr(hashlib, h) for h in algos]
    else:
        ctx = algos

    return _hash(fh, ctx)


def hash_uri_records(target, record: Record) -> Record:
    """Hash uri paths inside the record."""
    uri_fields = (field for field in record._field_types.items() if issubclass(field[1], uri))

    hashed_uri_records = []
    for name, _ in uri_fields:
        try:
            uri_record = hash_uri(target, getattr(record, name))
            hashed_uri_records.append(uri_record)
        except (FileNotFoundError, IsADirectoryError):
            pass

    if not hashed_uri_records:
        return record

    hashed_uri_records = list(zip(*hashed_uri_records))
    hashed_holder = HashRecord(paths=hashed_uri_records[0], digests=hashed_uri_records[1])

    return GroupedRecord(record._desc.name, [record, hashed_holder])


def hash_uri(target, uri: str) -> Record:
    """Hash the target uri."""
    if uri is None:
        raise FileNotFoundError()

    path = ResolverPlugin(target).resolve(uri)
    return (path, target.fs.hash(path))
