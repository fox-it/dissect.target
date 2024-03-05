import hashlib
from io import BytesIO

from Crypto.Hash import MD4

from dissect.target.plugins.os.windows.dpapi.credhist import CredHistFile
from tests._utils import absolute_path


def test_credhist() -> None:
    """The provided CREDHIST file has the following password history: ``user -> password -> password3``.
    The current password of the user is ``password4``.
    """
    with open(absolute_path("_data/plugins/os/windows/dpapi/credhist/CREDHIST"), "rb") as fh:
        ch = CredHistFile(fh)

    assert len(ch.entries) == 3

    for entry in ch.entries:
        assert ch.entries[0].version == 1
        assert entry.user_sid.upper() == "S-1-5-21-1342509979-482553916-3960431919-1000"

    ch.decrypt(password_hash=hashlib.sha1("password4".encode("utf-16-le")).digest())

    assert ch.entries[0].guid.upper() == "99EC7176-D16C-41BD-9C94-D3A4C5B94232"
    assert ch.entries[0].hash_sha == sha1("user")
    assert ch.entries[0].hash_nt == md4("user")

    assert ch.entries[1].guid.upper() == "120A3A30-309C-4FDA-BFB8-06F44EA93CB2"
    assert ch.entries[1].hash_nt == md4("password")
    assert ch.entries[1].hash_sha == sha1("password")

    assert ch.entries[2].guid.upper() == "5657891F-28DD-4F69-BABA-95E44BCD178A"
    assert ch.entries[2].hash_nt == md4("password3")
    assert ch.entries[2].hash_sha == sha1("password3")


def md4(plaintext: str) -> str:
    return MD4.new(plaintext.encode("utf-16-le")).digest().hex()


def sha1(plaintext: str) -> str:
    return hashlib.sha1(plaintext.encode("utf-16-le")).digest().hex()
