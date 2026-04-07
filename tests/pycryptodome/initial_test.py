import time
from tests.pycryptodome import dome_lib
from utils.path import path

def main():
    start = time.perf_counter()

    key = dome_lib.get_key(path("files/key.bin"), 32)

    dome_lib.encrpyt_file_gcm(path("files/plik.txt"), path("output/plik_dome.txt"), key)

    dome_lib.decrypt_file_gcm(path("output/plik_dome.txt"), path("output/decrypted_plik_dome.txt"), key)

    end = time.perf_counter()
    print(f"Time taken: {end - start:.6f} sedasdasdconds")

