from __future__ import annotations

import pytest
from dissect.evidence.ad1.ad1 import find_files

from dissect.target.filesystems.ad1 import AD1Filesystem
from dissect.target.helpers import keychain
from tests._utils import absolute_path


def test_ad1_encrypted() -> None:
    """Test if we can mount and AD1 ADCRYPT encrypted image using the keychain."""

    path = absolute_path("_data/filesystems/ad1/encrypted-small.ad1")
    segments = find_files(path)

    with pytest.raises(ValueError, match=r"Failed to unlock ADCRYPT: no key\(s\) provided"):
        AD1Filesystem(segments)

    keychain.register_wildcard_value("invalid")

    with pytest.raises(ValueError, match=r"Failed to unlock ADCRYPT using provided key\(s\)"):
        AD1Filesystem(segments)

    keychain.register_wildcard_value("password")
    fs = AD1Filesystem(segments)

    assert not fs.ad1.is_locked()
    assert list(fs.get("C:/Users/user/Desktop/Data").iterdir()) == [
        "hello.txt",
        "philipp-pilz-QZ2EQuPpQJs-unsplash.jpg",
    ]
