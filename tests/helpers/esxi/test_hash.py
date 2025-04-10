from dissect.target.helpers.esxi.hash import hash


def test_hash_remainder() -> None:
    ip = b"192.168.1.109"
    volume = b"/home/roel/nfstest"
    h1 = hash(ip, 42)
    h2 = hash(volume, h1)
    assert h2 == 5364432747070711354


def test_hash_full() -> None:
    h1 = hash(b"Het implementeren van hashfuncties in Python is lastiger dan je zou denken,", 42)
    h2 = hash(b"met name door de ontbrekende ondersteuning voor unsigned integer arithmetic", h1)
    assert h2 == 2809036171121327430


def test_hash_empty_key() -> None:
    h = hash(b"", 666)
    assert h == 8664614747486377173
