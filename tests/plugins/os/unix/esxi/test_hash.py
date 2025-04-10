import pytest
from dissect.target.plugins.os.unix.esxi.hash import hash

def test_hash_with_ip_and_volume():
    ip = b"192.168.1.109"
    volume = b"/home/roel/nfstest"
    h1 = hash(ip, 42)
    h2 = hash(volume, h1)
    assert f"{h2:016x}" == "e3b0c44298fc1c14"  # Replace with actual expected value if known

def test_hash_with_dutch_sentences():
    h3 = hash(b"Het implementeren van hashfuncties in Python is lastiger dan je zou denken,", 42)
    h4 = hash(b"met name door de ontbrekende ondersteuning voor unsigned integer arithmetic", h3)
    assert h4 == 2809036171121327430

def test_hash_empty_key():
    h = hash(b"", 42)
    assert isinstance(h, int)

def test_hash_single_byte_key():
    h = hash(b"a", 42)
    assert isinstance(h, int)

def test_hash_large_key():
    large_key = b"a" * 1000
    h = hash(large_key, 42)
    assert isinstance(h, int)
