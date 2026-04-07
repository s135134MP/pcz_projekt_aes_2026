from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrpyt_file_gcm(input_file, output_file, key):
    aes = AES.new(key, AES.MODE_GCM)

    with open(input_file, "rb") as f:
        data = f.read()

    cipertext, tag =  aes.encrypt_and_digest(data)

    with open(output_file, "wb") as f:
        f.write(aes.nonce)
        f.write(tag)
        f.write(cipertext)

def decrypt_file_gcm(input_file, output_file, key):
    with open(input_file, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        cipertext = f.read()

    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)

    data = aes.decrypt_and_verify(cipertext, tag)

    with open(output_file, "wb") as f:
        f.write(data)


def get_key(file_path, key_size):
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            key = f.read()

        if len(key) != key_size:
            raise ValueError("Invalid key size in file")
        return key
    else:
        key = get_random_bytes(key_size)

        with open(file_path, "wb") as f:
            f.write(key)

        return key