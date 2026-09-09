from __future__ import annotations

from Crypto.PublicKey import ECC, RSA

from dissect.target.plugins.os.windows.cng.c_bcrypt import c_bcrypt

BCRYPT_RSA_MAGIC = (
    c_bcrypt.BCRYPT_RSAPUBLIC_MAGIC,
    c_bcrypt.BCRYPT_RSAPRIVATE_MAGIC,
)

BCRYPT_ECDSA_MAGIC = (
    c_bcrypt.BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    c_bcrypt.BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
    c_bcrypt.BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
    c_bcrypt.BCRYPT_ECDSA_PRIVATE_P384_MAGIC,
    c_bcrypt.BCRYPT_ECDSA_PUBLIC_P521_MAGIC,
    c_bcrypt.BCRYPT_ECDSA_PRIVATE_P521_MAGIC,
)

BCRYPT_ECDH_MAGIC = (
    c_bcrypt.BCRYPT_ECDH_PUBLIC_P256_MAGIC,
    c_bcrypt.BCRYPT_ECDH_PRIVATE_P256_MAGIC,
    c_bcrypt.BCRYPT_ECDH_PUBLIC_P384_MAGIC,
    c_bcrypt.BCRYPT_ECDH_PRIVATE_P384_MAGIC,
    c_bcrypt.BCRYPT_ECDH_PUBLIC_P521_MAGIC,
    c_bcrypt.BCRYPT_ECDH_PRIVATE_P521_MAGIC,
)

BCRYPT_KEY_MAP = {
    # RSA
    c_bcrypt.BCRYPT_RSAPRIVATE_MAGIC: c_bcrypt.BCRYPT_RSAKEY_BLOB,
    c_bcrypt.BCRYPT_RSAPUBLIC_MAGIC: c_bcrypt.BCRYPT_RSAPUBLIC_BLOB,
    # Elliptic curve Diffie-Hellman (DH)
    c_bcrypt.BCRYPT_ECDH_PUBLIC_P256_MAGIC: c_bcrypt.BCRYPT_ECCPUBLIC_BLOB,
    c_bcrypt.BCRYPT_ECDH_PRIVATE_P256_MAGIC: c_bcrypt.BCRYPT_ECCKEY_BLOB,
    c_bcrypt.BCRYPT_ECDH_PUBLIC_P384_MAGIC: c_bcrypt.BCRYPT_ECCPUBLIC_BLOB,
    c_bcrypt.BCRYPT_ECDH_PRIVATE_P384_MAGIC: c_bcrypt.BCRYPT_ECCKEY_BLOB,
    c_bcrypt.BCRYPT_ECDH_PUBLIC_P521_MAGIC: c_bcrypt.BCRYPT_ECCPUBLIC_BLOB,
    c_bcrypt.BCRYPT_ECDH_PRIVATE_P521_MAGIC: c_bcrypt.BCRYPT_ECCKEY_BLOB,
    # Elliptic curve Digital Signature Algorithm (DSA)
    c_bcrypt.BCRYPT_ECDSA_PUBLIC_P256_MAGIC: c_bcrypt.BCRYPT_ECCPUBLIC_BLOB,
    c_bcrypt.BCRYPT_ECDSA_PRIVATE_P256_MAGIC: c_bcrypt.BCRYPT_ECCKEY_BLOB,
    c_bcrypt.BCRYPT_ECDSA_PUBLIC_P384_MAGIC: c_bcrypt.BCRYPT_ECCPUBLIC_BLOB,
    c_bcrypt.BCRYPT_ECDSA_PRIVATE_P384_MAGIC: c_bcrypt.BCRYPT_ECCKEY_BLOB,
    c_bcrypt.BCRYPT_ECDSA_PUBLIC_P521_MAGIC: c_bcrypt.BCRYPT_ECCPUBLIC_BLOB,
    c_bcrypt.BCRYPT_ECDSA_PRIVATE_P521_MAGIC: c_bcrypt.BCRYPT_ECCKEY_BLOB,
}

BCryptKeyType = type[
    c_bcrypt.BCRYPT_RSAKEY_BLOB
    | c_bcrypt.BCRYPT_RSAPUBLIC_BLOB
    | c_bcrypt.BCRYPT_ECCPUBLIC_BLOB
    | c_bcrypt.BCRYPT_ECCKEY_BLOB
]


class BCryptKey:
    """Microsoft windows BCRYPT Key implementation."""

    def __init__(self, raw: bytes | None = None, struct: BCryptKeyType | None = None) -> None:
        if raw and (_struct := BCRYPT_KEY_MAP.get(raw[0:4])):
            struct = _struct(raw)
        elif not struct:
            raise ValueError("Unable to determine bcrypt key type")

        self.struct = struct
        self.key = None
        self.type = None
        self.name = None

        if isinstance(struct, c_bcrypt.BCRYPT_RSAKEY_BLOB):
            n = int.from_bytes(struct.Modulus, byteorder="big")
            e = int.from_bytes(struct.PublicExponent, byteorder="big")
            p = int.from_bytes(struct.Prime1, byteorder="big")
            q = int.from_bytes(struct.Prime2, byteorder="big")
            d = calcPrivateKey(e, p, q)

            self.key = RSA.construct((n, e, d, p, q))
            self.type = "RSA"
            self.name = "Private Key"

        elif isinstance(struct, c_bcrypt.BCRYPT_ECCKEY_BLOB):
            self.key = ECC.construct(
                curve="NIST P-256",  # TODO: Infer curve from magic
                d=int.from_bytes(struct.d, byteorder="big"),
                point_x=int.from_bytes(struct.X, byteorder="big"),
                point_y=int.from_bytes(struct.Y, byteorder="big"),
            )
            self.type = "ECC"
            self.name = "Private Key"

        elif isinstance(struct, c_bcrypt.BCRYPT_RSAPUBLIC_BLOB):
            n = int.from_bytes(struct.Modulus, byteorder="big")
            e = int.from_bytes(struct.PublicExponent, byteorder="big")
            self.key = RSA.construct((n, e))
            self.type = "RSA"
            self.name = "Public Key"

        elif isinstance(struct, c_bcrypt.BCRYPT_ECCPUBLIC_BLOB):
            self.key = ECC.construct(
                curve="NIST P-256",  # TODO: Infer curve from magic
                point_x=int.from_bytes(struct.X, byteorder="big"),
                point_y=int.from_bytes(struct.Y, byteorder="big"),
            )
            self.type = "ECC"
            self.name = "Public Key"

    def __repr__(self) -> str:
        return f"<BCryptKey type={self.type} name={self.name}>"


def calcPrivateKey(e: int, p: int, q: int) -> int:
    """Calculate an RSA private key using Euler's totient, given ``e``, ``p`` and ``q``.

    Resources:
        - https://github.com/tijldeneut/diana/blob/main/diana-ngcpinpassdec.py#L50
    """

    def recurseFunction(a: int, b: int) -> tuple[int, int]:
        if b == 0:
            return (1, 0)
        (q, r) = (a // b, a % b)
        (s, t) = recurseFunction(b, r)
        return (t, s - (q * t))

    t = (p - 1) * (q - 1)
    inv = recurseFunction(e, t)[0]
    if inv < 1:
        inv += t
    return inv
