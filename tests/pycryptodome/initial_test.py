import time
from tests.pycryptodome import dome_lib
from utils.path import path

def main():
    start = time.perf_counter()
    key = dome_lib.get_key(path("files/key.bin"), 32)
    dome_lib.encrypt_file_gcm(
        path("files/plik.txt"), 
        path("output/plik_dome.txt"), key)
    dome_lib.decrypt_file_gcm(
        path("output/plik_dome.txt"), 
        path("output/decrypted_plik_dome.txt"), key)
    end = time.perf_counter()
    print(f"PyCryptoDome AES GCM Time taken: {end - start:.6f} seconds")


    start = time.perf_counter()
    key = dome_lib.get_key(path("files/key.bin"), 32)
    dome_lib.encrypt_file_cbc(
        path("files/plik.txt"),
        path("output/plik_dome_cbc.txt"), key)
    dome_lib.decrypt_file_cbc(
        path("output/plik_dome_cbc.txt"),
        path("output/decrypted_plik_dome_cbc.txt"), key)
    end = time.perf_counter()
    print(f"PyCryptoDome AES CBC Time taken: {end - start:.6f} seconds")

