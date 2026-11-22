from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.logging import get_logger
from dissect.target.plugins.os.windows.cng.bcrypt import BCRYPT_KEY_MAP, BCryptKey
from dissect.target.plugins.os.windows.cng.c_key import c_key
from dissect.target.plugins.os.windows.dpapi.blob import DPAPI_BLOB_MAGIC
from dissect.target.plugins.os.windows.dpapi.blob import Blob as DPAPIBlob

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

log = get_logger(__name__)


class CNGKey:
    """Represents a Microsoft Windows Cryptograpgy Next Generation (CNG) Key."""

    def __init__(self, target: Target, file: Path | BytesIO, sid: str | None = None) -> None:
        """Initialize the CNG key by :class:`Path` or :class:`BytesIO`."""
        if isinstance(file, Path):
            self.path = file
            self.fh = file.open("rb")
        else:
            self.path = None
            self.fh = file

        self.target = target
        self.sid = sid

        self.key = c_key.KEY_FILE(self.fh)
        self.name = self.key.Name
        self.version = self.key.Version
        self.type = self.key.Type

        self.offset_properties = self.fh.tell()
        self.offset_data = self.offset_properties + sum(self.key.PropertySizes)

        self.properties, self.keys, self.encrypted = self.parse()

    def __repr__(self) -> str:
        return (
            f"<CNGKey version={self.version} type={self.type} name={self.name} properties=#{len(self.properties)} "
            f"keys=#{len(self.keys)} encrypted=#{len(self.encrypted)} path='{self.path}' sid={self.sid}>"
        )

    def decrypt(self, **kwargs) -> None:
        """Decrypt any encrypted properties or keys within this CNG Key that could not be decrypted before."""
        for i, encrypted in enumerate(self.encrypted):
            # Attempt to decrypt with new arguments.
            try:
                plaintext = encrypted.decrypt(self.target, **kwargs)
            except ValueError:
                continue

            # Iterate over possible properties and key values in the plaintext.
            for item in parse_properties(plaintext, encrypted.blob.description):
                if isinstance(item, CNGKeyProperty):
                    self.properties.append(item)
                else:
                    self.keys.append(item)

            # Remove the encrypted property as it is now decrypted.
            self.encrypted.pop(i)

    def parse(self, **kwargs) -> tuple[list[CNGKeyProperty], list[BCryptKey], list[CNGEncryptedProperty]]:
        """Return (decrypted) properties and key data of this key. Kwargs are passed to ``DPAPIPlugin.decrypt_blob``."""
        self.fh.seek(self.offset_properties)
        properties = []
        keys = []
        encrypted = []

        for size in (*self.key.PropertySizes, self.key.KeyPropertiesSize, self.key.KeySize):
            data = self.fh.read(size)
            blob = None

            if data.startswith(DPAPI_BLOB_MAGIC):
                blob = DPAPIBlob(data)
                try:
                    data = self.target.dpapi.decrypt_blob(
                        data, entropy=DPAPI_ENTROPY_MAP.get(blob.description), **kwargs
                    )
                except (ValueError, UnsupportedPluginError):
                    encrypted.append(CNGEncryptedProperty(blob, data))
                    continue

            for item in parse_properties(data, blob.description if blob else None):
                if isinstance(item, CNGKeyProperty):
                    properties.append(item)
                else:
                    keys.append(item)

        return properties, keys, encrypted

    def get_property(self, name: str) -> bytes | None:
        """Return the property value of the given name."""
        for property in self.properties:
            if isinstance(property, CNGKeyProperty) and property.name == name:
                return property.value
        return None

    def get_key(self, name: str, type: str) -> BCryptKey | None:
        """Return a :class:`BCryptKey` instance for the given key name and type."""
        for key in self.keys:
            if key.name == name and key.type == type:
                return key
        return None

    @property
    def data(self) -> bytes:
        """Some keys can contain additional unparsed data, which is returned by this property."""
        self.fh.seek(self.offset_data)
        return self.fh.read()


class CNGKeyProperty:
    """CNG Key Property."""

    def __init__(self, name: str, value: bytes, property: c_key.KEY_PROPERTY | None = None) -> None:
        self.property = property
        self.name = name.strip("\00")

        # Apply normalization to known fields.
        if name == "Modified":
            self.value = wintimestamp(int.from_bytes(value, "little"))
        elif name == "CreatorProcessName":
            self.value = value.decode("utf-16-le").strip("\00")
        elif name == "NgcSoftwareKeyPbkdf2Round":
            self.value = int.from_bytes(value, "little")
        else:
            self.value = value

    def __repr__(self) -> str:
        return f"<CNGKeyProperty name={self.name} value={self.value}>"


class CNGEncryptedProperty:
    """Represents a CNG Key Property or BCryptKey that we could not (yet) decrypt."""

    def __init__(self, blob: DPAPIBlob, data: bytes) -> None:
        self.blob = blob
        self.data = data
        self.plaintext = None

    def __repr__(self) -> str:
        return f"<CNGEncryptedProperty size={len(self.data)}>"

    def decrypt(self, target: Target, **kwargs) -> bytes:
        """Attempt to decrypt the encrypted property using the DPAPI plugin and the provided DPAPI kwargs."""
        if self.plaintext:
            return self.plaintext

        self.plaintext = target.dpapi.decrypt_blob(
            self.data, entropy=DPAPI_ENTROPY_MAP.get(self.blob.description), **kwargs
        )
        return self.plaintext


DPAPI_ENTROPY_MAP = {
    "Private Key Properties\x00": b"6jnkd5J3ZdQDtrsu\x00",
    "Private Key\x00": b"xT5rZW5qVVbrvpuA\x00",
}


def parse_properties(data: bytes, blob_description: str | None) -> Iterator[CNGKeyProperty | BCryptKey]:
    """Parse CNG Key properties contained in plaintext key data."""
    # Iterate over the plaintext buffer and yield any properties.
    buf = BytesIO(data)
    while buf.tell() < len(data):
        # Peek for bcrypt magic.
        offset = buf.tell()
        magic = buf.read(4)
        buf.seek(offset)

        # The plaintext could directly hold a bcrypt key.
        if struct := BCRYPT_KEY_MAP.get(magic):
            yield BCryptKey(struct=struct(buf))
            continue

        # Most plaintexts contain one or more key properties.
        try:
            property = c_key.KEY_PROPERTY(buf)

        # This might be some other structure controlled by a third party application.
        # We attempt to derive a sane name from the DPAPI Blob description and break.
        except EOFError:
            yield CNGKeyProperty(name=blob_description or "Raw Property", value=data)
            break

        # A bcrypt key could be *inside* the property value.
        if len(property.Value) >= 4 and (struct := BCRYPT_KEY_MAP.get(property.Value[0:4])):
            yield BCryptKey(struct=struct(property.Value))
            continue

        # Otherwise this looks like a regular property.
        yield CNGKeyProperty(property.Name, property.Value, property)
