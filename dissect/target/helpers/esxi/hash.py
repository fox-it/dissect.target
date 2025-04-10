def mix64(a: int, b: int, c: int):
    """
    Mixes three 64-bit values reversibly.
    """
    # Simulate logical right shift by masking first
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 43)
    b = (b - c - a) ^ (a << 9)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 8)
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 38)
    b = (b - c - a) ^ (a << 23)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 5)
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 35)
    b = (b - c - a) ^ (a << 49)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 11)
    a = (a - b - c) ^ ((c & 0xFFFFFFFFFFFFFFFF) >> 12)
    b = (b - c - a) ^ (a << 18)
    c = (c - a - b) ^ ((b & 0xFFFFFFFFFFFFFFFF) >> 22)
    # Normalize to 64 bits
    return a & 0xFFFFFFFFFFFFFFFF, b & 0xFFFFFFFFFFFFFFFF, c & 0xFFFFFFFFFFFFFFFF


def hash(key: bytes, level: int) -> int:
    """
    Hashes a variable-length key into a 64-bit value.

    This hash function is used in the ESXi kernel.
    It is an exact implementation of the hash3 function defined here: http://burtleburtle.net/bob/c/lookup8.c
    """
    a: int = level
    b: int = level
    c: int = 0x9E3779B97F4A7C13  # Golden ratio, arbitrary value
    bytes_left: int = len(key)
    i: int = 0

    # Process the key in 24-byte chunks
    while bytes_left >= 24:
        a += int.from_bytes(key[i : i + 8], "little")
        b += int.from_bytes(key[i + 8 : i + 16], "little")
        c += int.from_bytes(key[i + 16 : i + 24], "little")
        a, b, c = mix64(a, b, c)
        i += 24
        bytes_left -= 24

    # Handle the last 23 bytes
    c = c + len(key)
    if bytes_left > 0:
        for shift, byte in enumerate(key[i:]):
            if shift < 8:
                a += byte << (shift * 8)
            elif shift < 16:
                b += byte << ((shift - 8) * 8)
            else:
                # c takes 23 - 8 - 8 = 7 bytes (length is added to LSB)
                c += byte << ((shift - 15) * 8)

    _, _, c = mix64(a, b, c)
    return c
