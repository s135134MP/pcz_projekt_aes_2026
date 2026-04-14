from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_file_gcm(input_file, output_file, key):
    aes = AES.new(key, AES.MODE_GCM)

    with open(input_file, "rb") as f:
        data = f.read()

    ciphertext, tag =  aes.encrypt_and_digest(data)

    with open(output_file, "wb") as f:
        f.write(aes.nonce)
        f.write(tag)
        f.write(ciphertext)

def decrypt_file_gcm(input_file, output_file, key):
    with open(input_file, "rb") as f:
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    aes = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        data = aes.decrypt_and_verify(ciphertext, tag)

        with open(output_file, "wb") as f:
            f.write(data)
    except ValueError as e:
        print("decrypt_file_gcm error: ", e)

def encrypt_file_cbc(input_file, output_file, key):
    aes = AES.new(key, AES.MODE_CBC)

    with open(input_file, "rb") as f:
        data = f.read()

    padded_data = pad(data, AES.block_size)
    ciphertext = aes.encrypt(padded_data)

    with open(output_file, "wb") as f:
        f.write(aes.iv)
        f.write(ciphertext)

def decrypt_file_cbc(input_file, output_file, key):
    with open(input_file, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = aes.decrypt(ciphertext)

    data = unpad(padded_data, AES.block_size)

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