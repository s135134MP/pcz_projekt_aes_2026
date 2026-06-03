import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from time import perf_counter
from src.aes_pcz import AES_PCZ
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def time_op(fn, repeat=2000):
    start = perf_counter()
    out = None
    for _ in range(repeat):
        out = fn()
    return perf_counter() - start, out


# ---------------- ECB ----------------
def bench_ecb_pcz(plaintext, key):
    aes = AES_PCZ(mode="ECB", key=key)

    enc_t, ct = time_op(lambda: aes.encrypt(plaintext, add_pad=True))
    dec_t, pt = time_op(lambda: aes.decrypt(ct, pad_data=True))

    return enc_t, dec_t, pt


def bench_ecb_pycrypto(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)

    enc_t, ct = time_op(lambda: cipher.encrypt(pad(plaintext, 16)))
    dec_t, pt = time_op(lambda: unpad(cipher.decrypt(ct), 16))

    return enc_t, dec_t, pt


# ---------------- CBC ----------------
def bench_cbc_pcz(plaintext, key):
    aes = AES_PCZ(mode="CBC", key=key)

    enc_t, res = time_op(lambda: aes.encrypt(plaintext, add_pad=True))
    ct, iv = res

    dec_t, pt = time_op(lambda: aes.decrypt(ct, iv=iv, pad_data=True))

    return enc_t, dec_t, pt


def bench_cbc_pycrypto(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    enc_t, ct = time_op(lambda: cipher.encrypt(pad(plaintext, 16)))

    cipher_dec = AES.new(key, AES.MODE_CBC, iv=iv)
    dec_t, pt = time_op(lambda: unpad(cipher_dec.decrypt(ct), 16))

    return enc_t, dec_t, pt


# ---------------- CTR ----------------
def bench_ctr_pcz(plaintext, key, nonce, counter):
    aes = AES_PCZ(mode="CTR", key=key)

    enc_t, res = time_op(lambda: aes.encrypt(plaintext, counter, nonce))
    ct, nonce_out = res

    dec_t, pt = time_op(lambda: aes.decrypt(ct, counter, nonce_out))

    return enc_t, dec_t, pt


def bench_ctr_pycrypto(plaintext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    enc_t, ct = time_op(lambda: cipher.encrypt(plaintext))

    cipher_dec = AES.new(key, AES.MODE_CTR, nonce=nonce)
    dec_t, pt = time_op(lambda: cipher_dec.decrypt(ct))

    return enc_t, dec_t, pt


# ---------------- GCM ----------------
def bench_gcm_pcz(plaintext, key):
    aes = AES_PCZ(mode="GCM", key=key)

    enc_t, res = time_op(lambda: aes.encrypt(plaintext))
    ct, nonce, tag = res

    dec_t, pt = time_op(lambda: aes.decrypt(ct, nonce=nonce, tag=tag))

    return enc_t, dec_t, pt


def bench_gcm_pycrypto(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)

    enc_t, ct, tag = time_op(lambda: cipher.encrypt_and_digest(plaintext))

    cipher_dec = AES.new(key, AES.MODE_GCM, nonce=cipher.nonce)
    dec_t, pt = time_op(lambda: cipher_dec.decrypt_and_verify(ct, tag))

    return enc_t, dec_t, pt


# ---------------- MAIN ----------------
def main():
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    ecb_cases = [
        ("AES-128", bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")),
        ("AES-192", bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")),
        ("AES-256", bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")),
    ]

    print("\n================ ECB ================")
    for label, key in ecb_cases:
        p1, d1, pt1 = bench_ecb_pcz(plaintext, key)
        p2, d2, pt2 = bench_ecb_pycrypto(plaintext, key)

        print(label)
        print("AES_PCZ     ENC:", p1, "DEC:", d1, "OK:", pt1 == plaintext)
        print("PyCryptodome ENC:", p2, "DEC:", d2, "OK:", pt2 == plaintext)
        print()

    print("\n================ CBC ================")
    for label, key in ecb_cases:
        p1, d1, pt1 = bench_cbc_pcz(plaintext, key)
        p2, d2, pt2 = bench_cbc_pycrypto(plaintext, key)

        print(label)
        print("AES_PCZ     ENC:", p1, "DEC:", d1)
        print("PyCryptodome ENC:", p2, "DEC:", d2)
        print()

    print("\n================ CTR ================")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    nonce = bytes.fromhex("f0f1f2f3f4f5f6f7")
    counter = int.from_bytes(bytes.fromhex("f8f9fafbfcfdfeff"), "big")

    p1, d1, _ = bench_ctr_pcz(plaintext * 8, key, nonce, counter)
    p2, d2, _ = bench_ctr_pycrypto(plaintext * 8, key, nonce)

    print("AES_PCZ     ENC:", p1, "DEC:", d1)
    print("PyCryptodome ENC:", p2, "DEC:", d2)

    print("\n================ GCM ================")
    for label, key in ecb_cases:
        p1, d1, _ = bench_gcm_pcz(plaintext * 8, key)
        p2, d2, _ = bench_gcm_pycrypto(plaintext * 8, key)

        print(label)
        print("AES_PCZ     ENC:", p1, "DEC:", d1)
        print("PyCryptodome ENC:", p2, "DEC:", d2)
        print()


if __name__ == "__main__":
    main()