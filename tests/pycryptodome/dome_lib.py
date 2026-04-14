import os
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def ensure_directory(path):
    """Create the directory if it does not exist yet."""
    os.makedirs(path, exist_ok=True)


def write_random_file(file_path, size_bytes):
    """Create a file filled with random bytes for benchmarking."""
    ensure_directory(os.path.dirname(file_path))

    chunk_size = 1024 * 1024

    with open(file_path, "wb") as file:
        remaining = size_bytes

        while remaining > 0:
            chunk_length = min(chunk_size, remaining)
            file.write(get_random_bytes(chunk_length))
            remaining -= chunk_length


def generate_benchmark_files(directory, large_size_mb=50):
    """Generate the default benchmark files and return their paths."""
    sizes = {
        "small": 1024,
        "medium": 1024 * 1024,
        "large": large_size_mb * 1024 * 1024,
    }
    files = {}

    for label, size_bytes in sizes.items():
        file_path = os.path.join(directory, f"{label}_{size_bytes}.bin")
        write_random_file(file_path, size_bytes)
        files[label] = {
            "path": file_path,
            "size_bytes": size_bytes,
        }

    return files


def read_file(file_path):
    """Read the full benchmark file content."""
    with open(file_path, "rb") as file:
        return file.read()


def encrypt_payload(mode_name, data, key):
    """Encrypt raw bytes for the selected AES mode."""
    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return {
            "ciphertext": cipher.encrypt(pad(data, AES.block_size)),
        }

    if mode_name == "CBC":
        cipher = AES.new(key, AES.MODE_CBC)
        return {
            "iv": cipher.iv,
            "ciphertext": cipher.encrypt(pad(data, AES.block_size)),
        }

    if mode_name == "CTR":
        cipher = AES.new(key, AES.MODE_CTR)
        return {
            "nonce": cipher.nonce,
            "ciphertext": cipher.encrypt(data),
        }

    if mode_name == "GCM":
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return {
            "nonce": cipher.nonce,
            "tag": tag,
            "ciphertext": ciphertext,
        }

    raise ValueError(f"Unsupported AES mode: {mode_name}")


def decrypt_payload(mode_name, payload, key):
    """Decrypt raw bytes for the selected AES mode."""
    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(payload["ciphertext"]), AES.block_size)

    if mode_name == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=payload["iv"])
        return unpad(cipher.decrypt(payload["ciphertext"]), AES.block_size)

    if mode_name == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=payload["nonce"])
        return cipher.decrypt(payload["ciphertext"])

    if mode_name == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=payload["nonce"])
        return cipher.decrypt_and_verify(payload["ciphertext"], payload["tag"])

    raise ValueError(f"Unsupported AES mode: {mode_name}")


def measure_execution(callable_object, *args):
    """Measure the execution time of a function call."""
    start = time.perf_counter()
    result = callable_object(*args)
    end = time.perf_counter()
    return result, end - start


def benchmark_mode(mode_name, data, key):
    """Benchmark encryption and decryption for one AES mode."""
    encrypted_payload, encryption_time = measure_execution(encrypt_payload, mode_name, data, key)
    decrypted_data, decryption_time = measure_execution(decrypt_payload, mode_name, encrypted_payload, key)

    return {
        "mode": mode_name,
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "correct": decrypted_data == data,
    }


def benchmark_file(file_path, key, modes):
    """Benchmark all AES modes for a single file."""
    data = read_file(file_path)
    results = []

    for mode_name in modes:
        result = benchmark_mode(mode_name, data, key)
        result["file"] = os.path.basename(file_path)
        result["size_bytes"] = len(data)
        results.append(result)

    return results


def run_benchmarks(test_directory, key, large_size_mb=50):
    """Generate benchmark files and return structured AES results."""
    generated_files = generate_benchmark_files(test_directory, large_size_mb=large_size_mb)
    modes = ("ECB", "CBC", "CTR", "GCM")
    benchmark_results = {}

    for label, file_info in generated_files.items():
        benchmark_results[label] = benchmark_file(file_info["path"], key, modes)

    return benchmark_results


def format_benchmark_results(results):
    """Format benchmark results into a short readable table."""
    header = f"{'File':<20}{'Mode':<8}{'Size':>12}{'Encrypt(s)':>14}{'Decrypt(s)':>14}{'OK':>6}"
    lines = [header, "-" * len(header)]

    for file_results in results.values():
        for result in file_results:
            lines.append(
                f"{result['file']:<20}"
                f"{result['mode']:<8}"
                f"{result['size_bytes']:>12}"
                f"{result['encryption_time']:>14.6f}"
                f"{result['decryption_time']:>14.6f}"
                f"{str(result['correct']):>6}"
            )

    return "\n".join(lines)


def get_key(file_path, key_size):
    """Load an AES key from disk or generate a new one."""
    if os.path.exists(file_path):
        with open(file_path, "rb") as file:
            key = file.read()

        if len(key) != key_size:
            raise ValueError("Invalid key size in file")

        return key

    ensure_directory(os.path.dirname(file_path))
    key = get_random_bytes(key_size)

    with open(file_path, "wb") as file:
        file.write(key)

    return key
