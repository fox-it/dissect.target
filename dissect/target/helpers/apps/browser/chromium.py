from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def remove_padding(decrypted: bytes) -> bytes:
    number_of_padding_bytes = decrypted[-1]
    return decrypted[:-number_of_padding_bytes]


def decrypt_v10(encrypted_password: bytes) -> str:
    encrypted_password = encrypted_password[3:]

    salt = b"saltysalt"
    iv = b" " * 16
    pbkdf_password = "peanuts"

    key = PBKDF2(pbkdf_password, salt, 16, 1)
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)

    decrypted = cipher.decrypt(encrypted_password)
    return remove_padding(decrypted).decode()


def decrypt_v10_2(encrypted_password: bytes, key: bytes) -> str:
    """
    struct chrome_pass {
        byte signature[3] = 'v10';
        byte iv[12];
        byte ciphertext[EOF];
    }
    """
    iv = encrypted_password[3:15]
    ciphertext = encrypted_password[15:]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext[:-16].decode(errors="backslashreplace")
