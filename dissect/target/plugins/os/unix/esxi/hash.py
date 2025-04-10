mask = 0xFFFFFFFFFFFFFFFF  # 64-bit mask for wrapping around


def mix64(a: int, b: int, c: int):
    """
    Mixes three 64-bit values reversibly.
    """
    a = ((a - b - c) & mask) ^ ((c & mask) >> 43)
    b = ((b - c - a) & mask) ^ (a << 9 & mask)
    c = ((c - a - b) & mask) ^ ((b & mask) >> 8)
    a = ((a - b - c) & mask) ^ ((c & mask) >> 38)
    b = ((b - c - a) & mask) ^ (a << 23 & mask)
    c = ((c - a - b) & mask) ^ ((b & mask) >> 5)
    a = ((a - b - c) & mask) ^ ((c & mask) >> 35)
    b = ((b - c - a) & mask) ^ (a << 49 & mask)
    c = ((c - a - b) & mask) ^ ((b & mask) >> 11)
    a = ((a - b - c) & mask) ^ ((c & mask) >> 12)
    b = ((b - c - a) & mask) ^ (a << 18 & mask)
    c = ((c - a - b) & mask) ^ ((b & mask) >> 22)
    return a, b, c


def hash(key: bytes, level: int) -> int:
    """
    Hashes a variable-length key into a 64-bit value.
    """
    a: int = level
    b: int = level
    c: int = 0x9e3779b97f4a7c13  # Golden ratio, arbitrary value
    bytes_left: int = len(key)
    i: int = 0

    # Process the key in 24-byte chunks
    while bytes_left >= 24:
        a = (a + int.from_bytes(key[i:i+8], 'little')) & mask
        b = (b + int.from_bytes(key[i+8:i+16], 'little')) & mask
        c = (c + int.from_bytes(key[i+16:i+24], 'little')) & mask
        a, b, c = mix64(a, b, c)
        i += 24
        bytes_left -= 24

    # Handle the last 23 bytes
    c = c + len(key) & mask
    if bytes_left > 0:
        for shift, byte in enumerate(key[i:]):
            if shift < 8:
                a = (a + (byte << (shift * 8))) & mask
            elif shift < 16:
                b = (b + (byte << ((shift - 8) * 8))) & mask
            else:
                c = (c + (byte << ((shift - 15) * 8))) & mask

    _, _, c = mix64(a, b, c)
    return c


ip = b"192.168.1.109"
volume = b"/home/roel/nfstest"
h1 = hash(ip, 42)
h2 = hash(volume, h1)
print(f"{h2:016x}")

h3 = hash(b"Het implementeren van hashfuncties in Python is lastiger dan je zou denken,", 42)
h4 = hash(b"met name door de ontbrekende ondersteuning voor unsigned integer arithmetic", h3)  # noqa: E501
print(h4)
