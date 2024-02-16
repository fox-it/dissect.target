from dissect.target.helpers.apps.browser.chromium import decrypt_v10


def test_decrypt_v10():
    encrypted = b"v10\xd0&E\xbb\x85\xe7_\xfd\xf8\x93\x90/\x08{'\xa9"
    decrypted = decrypt_v10(encrypted)
    assert decrypted == "password"
