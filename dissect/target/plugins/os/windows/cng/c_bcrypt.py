from __future__ import annotations

from dissect.cstruct import cstruct

# Resources:
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/540b7b8b-2232-45c8-9d7c-af7a5d5218ed
# - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/cba27df5-4880-4f95-a879-783f8657e53b
# - https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
# - https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
bcrypt_def = """
#define BCRYPT_RSAPUBLIC_MAGIC                              b"RSA1"
#define BCRYPT_RSAPRIVATE_MAGIC                             b"RSA2"

#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC                      b"ECS1"
#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC                     b"ECS2"
#define BCRYPT_ECDSA_PUBLIC_P384_MAGIC                      b"ECS3"
#define BCRYPT_ECDSA_PRIVATE_P384_MAGIC                     b"ECS4"
#define BCRYPT_ECDSA_PUBLIC_P521_MAGIC                      b"ECS5"
#define BCRYPT_ECDSA_PRIVATE_P521_MAGIC                     b"ECS6"

#define BCRYPT_ECDH_PUBLIC_P256_MAGIC                       b"ECK1"
#define BCRYPT_ECDH_PRIVATE_P256_MAGIC                      b"ECK2"
#define BCRYPT_ECDH_PUBLIC_P384_MAGIC                       b"ECK3"
#define BCRYPT_ECDH_PRIVATE_P384_MAGIC                      b"ECK4"
#define BCRYPT_ECDH_PUBLIC_P521_MAGIC                       b"ECK5"
#define BCRYPT_ECDH_PRIVATE_P521_MAGIC                      b"ECK6"

struct BCRYPT_RSAKEY_BLOB {
    DWORD               dwMagic;
    ULONG               BitLength;
    ULONG               cbPublicExponent;
    ULONG               cbModulus;
    ULONG               cbPrime1;
    ULONG               cbPrime2;
    CHAR                PublicExponent[cbPublicExponent];
    CHAR                Modulus[cbModulus];
    CHAR                Prime1[cbPrime1];                   // p
    CHAR                Prime2[cbPrime2];                   // q
};

struct BCRYPT_RSAPUBLIC_BLOB {
    DWORD               dwMagic;
    ULONG               BitLength;
    ULONG               cbPublicExponent;
    ULONG               cbModulus;
    ULONG               cbPrime1;
    ULONG               cbPrime2;
    CHAR                PublicExponent[cbPublicExponent];
    CHAR                Modulus[cbModulus];
};

struct BCRYPT_ECCKEY_BLOB {
    DWORD               dwMagic;
    ULONG               cbKey;
    CHAR                X[cbKey];
    CHAR                Y[cbKey];
    CHAR                d[cbKey];
};

struct BCRYPT_ECCPUBLIC_BLOB {
    DWORD               dwMagic;
    ULONG               cbKey;
    CHAR                X[cbKey];
    CHAR                Y[cbKey];
};
"""

c_bcrypt = cstruct().load(bcrypt_def)
