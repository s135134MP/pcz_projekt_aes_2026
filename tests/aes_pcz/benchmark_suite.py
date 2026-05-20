import hashlib
import sys
import time
import tracemalloc
from pathlib import Path

# Allow direct script execution without changing the existing project layout.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_pcz import AES_PCZ
from utils.path import path

try:
  from Crypto.Cipher import AES as CryptoAES
  from Crypto.Util.Padding import pad
except ImportError:  # pragma: no cover - optional dependency in runtime
  CryptoAES = None
  pad = None


# Deterministic benchmark configuration used across the whole suite.
BENCHMARK_DIR = Path(path("files/benchmarks")).resolve()
DEFAULT_MAX_FILE_SIZE_BYTES = 64 * 1024
SUPPORTED_KEY_SIZES = (128, 192, 256)
IMPLEMENTED_MODES = ("ECB", "CTR", "GCM")
REQUIRED_BENCHMARK_FILES = (
  "sample_text.txt",
  "structured_payload.json",
  "tabular_dataset.csv",
  "binary_pattern.bin",
  "image_like_64x64.rgb.bin",
  "empty_file.bin",
)
DETERMINISTIC_KEYS = {
  128: bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
  192: bytes.fromhex("000102030405060708090A0B0C0D0E0F1011121314151617"),
  256: bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
}
DEFAULT_CTR_NONCE = bytes.fromhex("F0F1F2F3F4F5F6F7")
DEFAULT_CTR_COUNTER = int.from_bytes(bytes.fromhex("F8F9FAFBFCFDFEFF"), "big")
DEFAULT_GCM_IV = bytes.fromhex("00112233445566778899AABB")


def _format_seconds(value):
  return f"{value * 1000:.3f} ms"


def _format_bytes(value):
  if value >= 1024 * 1024:
    return f"{value / (1024 * 1024):.2f} MiB"
  if value >= 1024:
    return f"{value / 1024:.2f} KiB"
  return f"{value} B"


def _format_kib(value):
  return f"{value / 1024:.2f} KiB"


def _format_throughput(value):
  return f"{value:.3f} MiB/s"


def _format_delta(value):
  sign = "+" if value > 0 else ""
  return f"{sign}{value} B"


def _chunk_bytes(data, block_size=16):
  return [data[index:index + block_size] for index in range(0, len(data), block_size)]


def _build_gcm_aad(file_name, file_size):
  return f"pcz-benchmark::{file_name}::{file_size}".encode("utf-8")


def _infer_file_type(file_path):
  suffix = file_path.suffix.lower()
  name = file_path.name.lower()

  if "image_like" in name:
    return "image-like binary"
  if suffix == ".txt":
    return "plain text"
  if suffix == ".json":
    return "json"
  if suffix == ".csv":
    return "csv"
  if suffix == ".bin":
    return "binary"
  return "other"


def _hash_bytes(data):
  return hashlib.sha256(data).hexdigest()


# Table rendering stays local to keep the module dependency-free.
def _render_table(columns, rows):
  widths = []

  for key, header, formatter in columns:
    width = len(header)
    for row in rows:
      width = max(width, len(formatter(row.get(key))))
    widths.append(width)

  header = " | ".join(header.ljust(widths[index]) for index, (_, header, _) in enumerate(columns))
  separator = "-+-".join("-" * width for width in widths)
  lines = [header, separator]

  for row in rows:
    lines.append(
      " | ".join(
        formatter(row.get(key)).ljust(widths[index])
        for index, (key, _, formatter) in enumerate(columns)
      )
    )

  return "\n".join(lines)


def _measure_operation(callable_object, *args, **kwargs):
  tracemalloc.start()
  start_time = time.perf_counter()
  try:
    result = callable_object(*args, **kwargs)
    error = ""
  except Exception as exc:  # pragma: no cover - exercised through integration flows
    result = None
    error = f"{type(exc).__name__}: {exc}"
  end_time = time.perf_counter()
  _, peak_bytes = tracemalloc.get_traced_memory()
  tracemalloc.stop()

  return {
    "result": result,
    "error": error,
    "duration": end_time - start_time,
    "peak_bytes": peak_bytes,
  }


def _encrypt_gcm_with_private_adapter(aes_instance, data, aad, iv):
  aes_instance._prepare_data(data, add_pad=False)
  aes_instance.iv = iv
  ciphertext, generated_iv, tag = aes_instance._encrypt_gcm(aad)
  return ciphertext, generated_iv, tag


def _decrypt_gcm_with_private_adapter(aes_instance, ciphertext, aad, tag, iv):
  aes_instance.blocks = _chunk_bytes(ciphertext, 16)
  aes_instance.iv = iv
  return aes_instance._decrypt_gcm(aad, tag)


# The wrappers below keep all integration quirks inside the benchmark layer.
def _encrypt_with_project_aes(mode, key, data, file_name):
  if not isinstance(data, (bytes, bytearray)):
    raise TypeError("Benchmark input must be bytes-like")

  normalized_data = bytes(data)
  aes_instance = AES_PCZ(mode=mode, key=key)

  if mode == "ECB":
    ciphertext = aes_instance.encrypt(normalized_data)
    return {
      "ciphertext": ciphertext,
      "adapter": "public",
    }

  if mode == "CTR":
    ciphertext, nonce = aes_instance.encrypt(
      normalized_data,
      counter=DEFAULT_CTR_COUNTER,
      nonce=DEFAULT_CTR_NONCE,
    )
    return {
      "ciphertext": ciphertext,
      "nonce": nonce,
      "counter": DEFAULT_CTR_COUNTER,
      "adapter": "public",
    }

  if mode == "GCM":
    aad = _build_gcm_aad(file_name, len(normalized_data))

    try:
      ciphertext, iv, tag = aes_instance.encrypt(normalized_data, aad=aad, iv=DEFAULT_GCM_IV)
      adapter = "public"
    except Exception as public_error:
      ciphertext, iv, tag = _encrypt_gcm_with_private_adapter(
        AES_PCZ(mode=mode, key=key),
        normalized_data,
        aad,
        DEFAULT_GCM_IV,
      )
      adapter = f"private-fallback ({type(public_error).__name__})"

    return {
      "ciphertext": ciphertext,
      "iv": iv,
      "tag": tag,
      "aad": aad,
      "adapter": adapter,
    }

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def _decrypt_with_project_aes(mode, key, payload):
  aes_instance = AES_PCZ(mode=mode, key=key)

  if mode == "ECB":
    return aes_instance.decrypt(payload["ciphertext"])

  if mode == "CTR":
    plaintext, _ = aes_instance.encrypt(
      payload["ciphertext"],
      counter=payload["counter"],
      nonce=payload["nonce"],
    )
    return plaintext

  if mode == "GCM":
    try:
      return aes_instance.decrypt(
        payload["ciphertext"],
        aad=payload["aad"],
        tag=payload["tag"],
        iv=payload["iv"],
      )
    except Exception:
      return _decrypt_gcm_with_private_adapter(
        AES_PCZ(mode=mode, key=key),
        payload["ciphertext"],
        payload["aad"],
        payload["tag"],
        payload["iv"],
      )

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def _reference_encrypt(mode, key, data, payload):
  if CryptoAES is None or pad is None:
    return None

  if mode == "ECB":
    cipher = CryptoAES.new(key, CryptoAES.MODE_ECB)
    return {
      "ciphertext": cipher.encrypt(pad(data, CryptoAES.block_size)),
    }

  if mode == "CTR":
    cipher = CryptoAES.new(
      key,
      CryptoAES.MODE_CTR,
      nonce=payload["nonce"],
      initial_value=payload["counter"],
    )
    return {
      "ciphertext": cipher.encrypt(data),
    }

  if mode == "GCM":
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce=payload["iv"])
    cipher.update(payload["aad"])
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
      "ciphertext": ciphertext,
      "tag": tag,
    }

  return None


def _compatibility_result(mode, key, plaintext, payload):
  reference_payload = _reference_encrypt(mode, key, plaintext, payload)

  if reference_payload is None:
    return "N/A", "pycryptodome unavailable"

  if mode == "GCM":
    if (
      reference_payload["ciphertext"] == payload["ciphertext"]
      and reference_payload["tag"] == payload["tag"]
    ):
      return "PASS", ""
    return "FAIL", "ciphertext/tag mismatch"

  if reference_payload["ciphertext"] == payload["ciphertext"]:
    return "PASS", ""

  return "FAIL", "ciphertext mismatch"


def _discover_benchmark_files(max_file_size_bytes=DEFAULT_MAX_FILE_SIZE_BYTES):
  if not BENCHMARK_DIR.exists():
    raise FileNotFoundError("Benchmark directory does not exist: " + str(BENCHMARK_DIR))

  missing_files = [name for name in REQUIRED_BENCHMARK_FILES if not (BENCHMARK_DIR / name).exists()]
  if missing_files:
    raise FileNotFoundError("Missing benchmark fixtures: " + ", ".join(missing_files))

  selected_files = []
  skipped_files = []
  managed_names = set(REQUIRED_BENCHMARK_FILES)

  for file_name in REQUIRED_BENCHMARK_FILES:
    file_path = BENCHMARK_DIR / file_name
    file_size = file_path.stat().st_size
    entry = {
      "path": file_path,
      "size_bytes": file_size,
      "file_type": _infer_file_type(file_path),
      "reason": "",
    }

    if file_size <= max_file_size_bytes:
      selected_files.append(entry)
    else:
      entry["reason"] = "managed fixture above default size cap"
      skipped_files.append(entry)

  for file_path in sorted(BENCHMARK_DIR.iterdir(), key=lambda item: (item.stat().st_size, item.name.lower())):
    if not file_path.is_file() or file_path.name in managed_names:
      continue

    skipped_files.append({
      "path": file_path,
      "size_bytes": file_path.stat().st_size,
      "file_type": _infer_file_type(file_path),
      "reason": "legacy fixture not included in default matrix",
    })

  return selected_files, skipped_files


def test_file(file_path, mode, key_size):
  benchmark_path = Path(file_path)
  result = {
    "mode": mode,
    "key_size": key_size,
    "file_name": benchmark_path.name,
    "file_type": _infer_file_type(benchmark_path),
    "file_size_bytes": 0,
    "encryption_status": "NOT RUN",
    "decryption_status": "NOT RUN",
    "integrity_status": "FAIL",
    "compatibility_status": "NOT RUN",
    "encryption_time": 0.0,
    "decryption_time": 0.0,
    "total_time": 0.0,
    "peak_bytes": 0,
    "ciphertext_size_bytes": 0,
    "size_delta_bytes": 0,
    "throughput_mib_s": 0.0,
    "adapter": "",
    "error": "",
  }

  if key_size not in DETERMINISTIC_KEYS:
    result["error"] = "Unsupported benchmark key size"
    return result

  if mode not in IMPLEMENTED_MODES:
    result["error"] = "Unsupported benchmark mode"
    return result

  if not benchmark_path.exists() or not benchmark_path.is_file():
    result["error"] = "File not found"
    return result

  with benchmark_path.open("rb") as benchmark_file:
    plaintext = benchmark_file.read()

  result["file_size_bytes"] = len(plaintext)
  key = DETERMINISTIC_KEYS[key_size]

  encryption = _measure_operation(_encrypt_with_project_aes, mode, key, plaintext, benchmark_path.name)
  result["encryption_time"] = encryption["duration"]
  result["peak_bytes"] = max(result["peak_bytes"], encryption["peak_bytes"])

  if encryption["error"]:
    result["encryption_status"] = "FAIL"
    result["error"] = encryption["error"]
    result["total_time"] = result["encryption_time"]
    return result

  payload = encryption["result"]
  result["encryption_status"] = "PASS"
  result["adapter"] = payload.get("adapter", "")
  result["ciphertext_size_bytes"] = len(payload["ciphertext"])
  result["size_delta_bytes"] = result["ciphertext_size_bytes"] - result["file_size_bytes"]

  decryption = _measure_operation(_decrypt_with_project_aes, mode, key, payload)
  result["decryption_time"] = decryption["duration"]
  result["peak_bytes"] = max(result["peak_bytes"], decryption["peak_bytes"])
  result["total_time"] = result["encryption_time"] + result["decryption_time"]

  if decryption["error"]:
    result["decryption_status"] = "FAIL"
    result["error"] = decryption["error"]
    return result

  decrypted_plaintext = decryption["result"]
  result["decryption_status"] = "PASS"

  if decrypted_plaintext == plaintext and _hash_bytes(decrypted_plaintext) == _hash_bytes(plaintext):
    result["integrity_status"] = "PASS"
  else:
    result["integrity_status"] = "FAIL"
    result["error"] = "Decrypted data does not match the original input"

  compatibility_status, compatibility_note = _compatibility_result(mode, key, plaintext, payload)
  result["compatibility_status"] = compatibility_status

  if compatibility_note:
    result["error"] = compatibility_note if not result["error"] else result["error"] + " | " + compatibility_note

  if result["total_time"] > 0:
    result["throughput_mib_s"] = (result["file_size_bytes"] / (1024 * 1024)) / result["total_time"]

  return result


def benchmark_mode(mode, key_size, max_file_size_bytes=DEFAULT_MAX_FILE_SIZE_BYTES):
  benchmark_files, _ = _discover_benchmark_files(max_file_size_bytes=max_file_size_bytes)
  return [test_file(file_info["path"], mode, key_size) for file_info in benchmark_files]


def _run_validation_checks(sample_file_path):
  checks = []

  try:
    AES_PCZ("ECB", b"short-key")
    checks.append({"check": "Invalid key size", "status": "FAIL", "details": "Expected ValueError was not raised"})
  except ValueError:
    checks.append({"check": "Invalid key size", "status": "PASS", "details": "ValueError raised safely"})

  try:
    AES_PCZ("XYZ", DETERMINISTIC_KEYS[128])
    checks.append({"check": "Invalid mode", "status": "FAIL", "details": "Expected ValueError was not raised"})
  except ValueError:
    checks.append({"check": "Invalid mode", "status": "PASS", "details": "ValueError raised safely"})

  missing_file_result = test_file(BENCHMARK_DIR / "missing_fixture.bin", "ECB", 128)
  checks.append({
    "check": "Missing file path",
    "status": "PASS" if missing_file_result["error"] == "File not found" else "FAIL",
    "details": missing_file_result["error"] or "Unexpected result",
  })

  try:
    _encrypt_with_project_aes("ECB", DETERMINISTIC_KEYS[128], "not-bytes", "invalid.txt")
    checks.append({"check": "Incorrect binary/text handling", "status": "FAIL", "details": "Expected TypeError was not raised"})
  except TypeError:
    checks.append({"check": "Incorrect binary/text handling", "status": "PASS", "details": "TypeError raised safely"})

  try:
    _encrypt_with_project_aes("CBC", DETERMINISTIC_KEYS[128], sample_file_path.read_bytes(), sample_file_path.name)
    checks.append({"check": "Unsupported CBC integration", "status": "FAIL", "details": "Expected failure was not raised"})
  except (NotImplementedError, ValueError):
    checks.append({"check": "Unsupported CBC integration", "status": "PASS", "details": "Unsupported mode rejected safely"})

  try:
    payload = _encrypt_with_project_aes("GCM", DETERMINISTIC_KEYS[128], sample_file_path.read_bytes(), sample_file_path.name)
    corrupted_payload = dict(payload)
    if corrupted_payload["ciphertext"]:
      corrupted_bytes = bytearray(corrupted_payload["ciphertext"])
      corrupted_bytes[0] ^= 0x01
      corrupted_payload["ciphertext"] = bytes(corrupted_bytes)
    else:
      corrupted_tag = bytearray(corrupted_payload["tag"])
      corrupted_tag[0] ^= 0x01
      corrupted_payload["tag"] = bytes(corrupted_tag)
    _decrypt_with_project_aes("GCM", DETERMINISTIC_KEYS[128], corrupted_payload)
    checks.append({"check": "Corrupted GCM output", "status": "FAIL", "details": "Corruption was not detected"})
  except Exception as exc:
    checks.append({"check": "Corrupted GCM output", "status": "PASS", "details": type(exc).__name__})

  return checks


def _build_summary_rows(results, group_key):
  grouped = {}

  for result in results:
    group_value = result[group_key]
    grouped.setdefault(group_value, []).append(result)

  summary_rows = []

  for group_value in sorted(grouped):
    entries = grouped[group_value]
    successful = [entry for entry in entries if entry["integrity_status"] == "PASS"]

    if successful:
      avg_encryption = sum(entry["encryption_time"] for entry in successful) / len(successful)
      avg_decryption = sum(entry["decryption_time"] for entry in successful) / len(successful)
      avg_total = sum(entry["total_time"] for entry in successful) / len(successful)
      avg_peak = sum(entry["peak_bytes"] for entry in successful) / len(successful)
      avg_throughput = sum(entry["throughput_mib_s"] for entry in successful) / len(successful)
    else:
      avg_encryption = 0.0
      avg_decryption = 0.0
      avg_total = 0.0
      avg_peak = 0.0
      avg_throughput = 0.0

    summary_rows.append({
      "group": str(group_value),
      "tests": f"{len(successful)}/{len(entries)}",
      "avg_encryption_time": avg_encryption,
      "avg_decryption_time": avg_decryption,
      "avg_total_time": avg_total,
      "avg_peak_bytes": avg_peak,
      "avg_throughput_mib_s": avg_throughput,
    })

  return summary_rows


def _build_extremes_rows(results):
  successful = [entry for entry in results if entry["integrity_status"] == "PASS"]
  if not successful:
    return []

  fastest = min(successful, key=lambda entry: entry["total_time"])
  slowest = max(successful, key=lambda entry: entry["total_time"])
  heaviest = max(successful, key=lambda entry: entry["peak_bytes"])
  best_throughput = max(successful, key=lambda entry: entry["throughput_mib_s"])

  return [
    {
      "label": "Fastest combination",
      "value": f"{fastest['mode']} / {fastest['key_size']} / {fastest['file_name']}",
      "metric": _format_seconds(fastest["total_time"]),
    },
    {
      "label": "Slowest combination",
      "value": f"{slowest['mode']} / {slowest['key_size']} / {slowest['file_name']}",
      "metric": _format_seconds(slowest["total_time"]),
    },
    {
      "label": "Highest traced memory",
      "value": f"{heaviest['mode']} / {heaviest['key_size']} / {heaviest['file_name']}",
      "metric": _format_kib(heaviest["peak_bytes"]),
    },
    {
      "label": "Best throughput",
      "value": f"{best_throughput['mode']} / {best_throughput['key_size']} / {best_throughput['file_name']}",
      "metric": _format_throughput(best_throughput["throughput_mib_s"]),
    },
  ]


def _print_results(results, skipped_files, validation_checks):
  detail_columns = [
    ("mode", "Mode", str),
    ("key_size", "Key", lambda value: f"AES-{value}"),
    ("file_name", "File", str),
    ("file_type", "Type", str),
    ("file_size_bytes", "Size", _format_bytes),
    ("encryption_status", "Encrypt", str),
    ("decryption_status", "Decrypt", str),
    ("integrity_status", "Integrity", str),
    ("compatibility_status", "Compat", str),
    ("encryption_time", "Enc Time", _format_seconds),
    ("decryption_time", "Dec Time", _format_seconds),
    ("total_time", "Total", _format_seconds),
    ("peak_bytes", "Peak Mem", _format_kib),
    ("size_delta_bytes", "Delta", _format_delta),
    ("throughput_mib_s", "Throughput", _format_throughput),
    ("adapter", "Adapter", str),
    ("error", "Notes", str),
  ]
  summary_columns = [
    ("group", "Group", str),
    ("tests", "Passed", str),
    ("avg_encryption_time", "Avg Enc", _format_seconds),
    ("avg_decryption_time", "Avg Dec", _format_seconds),
    ("avg_total_time", "Avg Total", _format_seconds),
    ("avg_peak_bytes", "Avg Peak", _format_kib),
    ("avg_throughput_mib_s", "Avg Throughput", _format_throughput),
  ]
  skipped_columns = [
    ("path", "Skipped File", str),
    ("size_bytes", "Size", _format_bytes),
    ("file_type", "Type", str),
    ("reason", "Reason", str),
  ]
  validation_columns = [
    ("check", "Validation Check", str),
    ("status", "Status", str),
    ("details", "Details", str),
  ]
  extremes_columns = [
    ("label", "Category", str),
    ("value", "Combination", str),
    ("metric", "Metric", str),
  ]

  print("AES benchmark directory:", BENCHMARK_DIR)
  print("Tested combinations:", len(results))
  print("Detailed benchmark results")
  print(_render_table(detail_columns, results))
  print()
  print("Summary by mode")
  print(_render_table(summary_columns, _build_summary_rows(results, "mode")))
  print()
  print("Summary by key size")
  print(_render_table(summary_columns, _build_summary_rows(results, "key_size")))
  print()
  print("Extremes")
  print(_render_table(extremes_columns, _build_extremes_rows(results)))
  print()
  print("Validation checks")
  print(_render_table(validation_columns, validation_checks))

  if skipped_files:
    print()
    print("Skipped files")
    print(_render_table(skipped_columns, skipped_files))


def run_all_benchmarks(max_file_size_bytes=DEFAULT_MAX_FILE_SIZE_BYTES):
  benchmark_files, skipped_files = _discover_benchmark_files(max_file_size_bytes=max_file_size_bytes)
  results = []

  for mode in IMPLEMENTED_MODES:
    for key_size in SUPPORTED_KEY_SIZES:
      for file_info in benchmark_files:
        results.append(test_file(file_info["path"], mode, key_size))

  sample_file = BENCHMARK_DIR / "sample_text.txt"
  validation_checks = _run_validation_checks(sample_file)

  _print_results(
    results,
    [
      {
        "path": file_info["path"].name,
        "size_bytes": file_info["size_bytes"],
        "file_type": file_info["file_type"],
        "reason": file_info["reason"],
      }
      for file_info in skipped_files
    ],
    validation_checks,
  )

  return {
    "results": results,
    "validation_checks": validation_checks,
    "skipped_files": skipped_files,
  }


def main():
  return run_all_benchmarks()


if __name__ == "__main__":
  main()


# --- Manual Tests ---
# run_all_benchmarks()
# benchmark_mode("GCM", 256)
# test_file(path("files/benchmarks/sample_text.txt"), "CTR", 128)
