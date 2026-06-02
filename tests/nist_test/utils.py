import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))

from src.aes_pcz import AES_PCZ
import src.helpers as helpers
import src.transformations as tr

try:
  from Crypto.Cipher import AES as CryptoAES
  from Crypto.Util.Padding import pad as crypto_pad
  from Crypto.Util.Padding import unpad as crypto_unpad
except ImportError:
  CryptoAES = None
  crypto_pad = None
  crypto_unpad = None

from tests.nist_test.performance_metrics import measure_operation


BLOCK_SIZE = 16
SUPPORTED_MODES = ("ECB", "CBC", "CTR")
SUPPORTED_KEY_SIZES = (128, 192, 256)
DEFAULT_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
DEFAULT_COUNTER_BLOCK = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
DETERMINISTIC_KEYS = {
  128: bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
  192: bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
  256: bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
  ),
}


def validate_bytes_input(data, field_name="data", allow_empty=False):
  if not isinstance(data, (bytes, bytearray)):
    raise TypeError(field_name + " must be bytes-like")

  normalized_data = bytes(data)

  if not allow_empty and len(normalized_data) == 0:
    raise ValueError(field_name + " cannot be empty")

  return normalized_data


def validate_iv(iv):
  normalized_iv = validate_bytes_input(iv, "IV")

  if len(normalized_iv) != BLOCK_SIZE:
    raise ValueError("IV must contain exactly 16 bytes")

  return normalized_iv


def validate_counter_block(counter_block):
  normalized_counter_block = validate_bytes_input(counter_block, "Counter block")

  if len(normalized_counter_block) != BLOCK_SIZE:
    raise ValueError("Counter block must contain exactly 16 bytes")

  return normalized_counter_block


def split_counter_block(counter_block):
  normalized_counter_block = validate_counter_block(counter_block)
  return normalized_counter_block[:8], int.from_bytes(normalized_counter_block[8:], "big")


def chunk_bytes(data, block_size=BLOCK_SIZE):
  return [data[index:index + block_size] for index in range(0, len(data), block_size)]


def xor_bytes(left, right):
  return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right))


def pkcs7_pad(data, block_size=BLOCK_SIZE):
  normalized_data = validate_bytes_input(data, allow_empty=True)
  pad_length = block_size - (len(normalized_data) % block_size)
  return normalized_data + bytes([pad_length] * pad_length)


def pkcs7_unpad(data, block_size=BLOCK_SIZE):
  normalized_data = validate_bytes_input(data, allow_empty=False)

  if len(normalized_data) % block_size != 0:
    raise ValueError("Invalid padded data length")

  pad_length = normalized_data[-1]

  if pad_length < 1 or pad_length > block_size:
    raise ValueError("Invalid padding")

  if normalized_data[-pad_length:] != bytes([pad_length] * pad_length):
    raise ValueError("Invalid padding")

  return normalized_data[:-pad_length]


def encrypt_block(key, block):
  normalized_key = helpers.validate_aes_key(key)
  normalized_block = validate_bytes_input(block, "AES block")

  if len(normalized_block) != BLOCK_SIZE:
    raise ValueError("AES block must contain exactly 16 bytes")

  aes_instance = AES_PCZ("ECB", normalized_key)
  aes_instance.blocks = [normalized_block]
  return aes_instance._encrypt_ecb()


def decrypt_block(key, block):
  normalized_key = helpers.validate_aes_key(key)
  normalized_block = validate_bytes_input(block, "AES block")

  if len(normalized_block) != BLOCK_SIZE:
    raise ValueError("AES block must contain exactly 16 bytes")

  round_keys = tr.key_schedule(normalized_key)
  round_count = helpers.get_round_number(normalized_key)
  state = tr.bytes_to_state(normalized_block)
  state = tr.add_round_key(state, round_keys[round_count])

  for round_number in range(round_count - 1, 0, -1):
    state = tr.inv_shift_rows(state)
    state = tr.inv_sub_bytes(state)
    state = tr.add_round_key(state, round_keys[round_number])
    state = tr.inv_mix_columns(state)

  state = tr.inv_shift_rows(state)
  state = tr.inv_sub_bytes(state)
  state = tr.add_round_key(state, round_keys[0])
  return tr.state_to_bytes(state)


def encrypt_raw_mode(mode, key, data, iv=DEFAULT_IV, counter_block=DEFAULT_COUNTER_BLOCK):
  normalized_key = helpers.validate_aes_key(key)
  normalized_data = validate_bytes_input(data)

  if mode == "ECB":
    if len(normalized_data) % BLOCK_SIZE != 0:
      raise ValueError("ECB raw input must be aligned to 16 bytes")

    return b"".join(encrypt_block(normalized_key, block) for block in chunk_bytes(normalized_data))

  if mode == "CBC":
    normalized_iv = validate_iv(iv)

    if len(normalized_data) % BLOCK_SIZE != 0:
      raise ValueError("CBC raw input must be aligned to 16 bytes")

    encrypted_blocks = []
    previous_block = normalized_iv

    for block in chunk_bytes(normalized_data):
      encrypted_block = encrypt_block(normalized_key, xor_bytes(block, previous_block))
      encrypted_blocks.append(encrypted_block)
      previous_block = encrypted_block

    return b"".join(encrypted_blocks)

  if mode == "CTR":
    nonce, counter = split_counter_block(counter_block)
    ciphertext, _ = AES_PCZ("CTR", normalized_key).encrypt(normalized_data, counter=counter, nonce=nonce)
    return ciphertext

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def decrypt_raw_mode(mode, key, data, iv=DEFAULT_IV, counter_block=DEFAULT_COUNTER_BLOCK):
  normalized_key = helpers.validate_aes_key(key)
  normalized_data = validate_bytes_input(data)

  if mode == "ECB":
    if len(normalized_data) % BLOCK_SIZE != 0:
      raise ValueError("ECB raw input must be aligned to 16 bytes")

    return b"".join(decrypt_block(normalized_key, block) for block in chunk_bytes(normalized_data))

  if mode == "CBC":
    normalized_iv = validate_iv(iv)

    if len(normalized_data) % BLOCK_SIZE != 0:
      raise ValueError("CBC raw input must be aligned to 16 bytes")

    decrypted_blocks = []
    previous_block = normalized_iv

    for block in chunk_bytes(normalized_data):
      decrypted_block = xor_bytes(decrypt_block(normalized_key, block), previous_block)
      decrypted_blocks.append(decrypted_block)
      previous_block = block

    return b"".join(decrypted_blocks)

  if mode == "CTR":
    nonce, counter = split_counter_block(counter_block)
    plaintext, _ = AES_PCZ("CTR", normalized_key).encrypt(normalized_data, counter=counter, nonce=nonce)
    return plaintext

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def encrypt_sample_mode(mode, key, data, iv=DEFAULT_IV, counter_block=DEFAULT_COUNTER_BLOCK):
  normalized_key = helpers.validate_aes_key(key)
  normalized_data = validate_bytes_input(data)

  if mode == "ECB":
    ciphertext = AES_PCZ("ECB", normalized_key).encrypt(normalized_data)
    return {
      "ciphertext": ciphertext,
      "adapter": "public-api",
    }

  if mode == "CBC":
    padded_data = pkcs7_pad(normalized_data)
    ciphertext = encrypt_raw_mode(mode, normalized_key, padded_data, iv=iv)
    return {
      "ciphertext": ciphertext,
      "iv": validate_iv(iv),
      "adapter": "raw-cbc-adapter",
    }

  if mode == "CTR":
    nonce, counter = split_counter_block(counter_block)
    ciphertext, generated_nonce = AES_PCZ("CTR", normalized_key).encrypt(
      normalized_data,
      counter=counter,
      nonce=nonce,
    )
    return {
      "ciphertext": ciphertext,
      "nonce": generated_nonce,
      "counter": counter,
      "adapter": "public-api",
    }

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def decrypt_sample_mode(mode, key, payload, iv=DEFAULT_IV, counter_block=DEFAULT_COUNTER_BLOCK):
  normalized_key = helpers.validate_aes_key(key)

  if "ciphertext" not in payload:
    raise ValueError("Payload must contain ciphertext")

  ciphertext = validate_bytes_input(payload["ciphertext"], "ciphertext")

  if mode == "ECB":
    return AES_PCZ("ECB", normalized_key).decrypt(ciphertext)

  if mode == "CBC":
    plaintext = decrypt_raw_mode(mode, normalized_key, ciphertext, iv=payload.get("iv", iv))
    return pkcs7_unpad(plaintext)

  if mode == "CTR":
    if "nonce" in payload and "counter" in payload:
      nonce = payload["nonce"]
      counter = payload["counter"]
    else:
      nonce, counter = split_counter_block(counter_block)

    plaintext, _ = AES_PCZ("CTR", normalized_key).encrypt(ciphertext, counter=counter, nonce=nonce)
    return plaintext

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def reference_encrypt(mode, key, data, iv=DEFAULT_IV, counter_block=DEFAULT_COUNTER_BLOCK, add_padding=False):
  if CryptoAES is None:
    return None

  normalized_key = helpers.validate_aes_key(key)
  normalized_data = validate_bytes_input(data, allow_empty=add_padding)

  if mode == "ECB":
    cipher = CryptoAES.new(normalized_key, CryptoAES.MODE_ECB)
    plaintext = crypto_pad(normalized_data, BLOCK_SIZE) if add_padding else normalized_data
    return {
      "ciphertext": cipher.encrypt(plaintext),
    }

  if mode == "CBC":
    normalized_iv = validate_iv(iv)
    cipher = CryptoAES.new(normalized_key, CryptoAES.MODE_CBC, iv=normalized_iv)
    plaintext = crypto_pad(normalized_data, BLOCK_SIZE) if add_padding else normalized_data
    return {
      "ciphertext": cipher.encrypt(plaintext),
      "iv": normalized_iv,
    }

  if mode == "CTR":
    nonce, counter = split_counter_block(counter_block)
    cipher = CryptoAES.new(
      normalized_key,
      CryptoAES.MODE_CTR,
      nonce=nonce,
      initial_value=counter,
    )
    return {
      "ciphertext": cipher.encrypt(normalized_data),
      "nonce": nonce,
      "counter": counter,
    }

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def reference_decrypt(mode, key, payload, iv=DEFAULT_IV, counter_block=DEFAULT_COUNTER_BLOCK, add_padding=False):
  if CryptoAES is None:
    return None

  normalized_key = helpers.validate_aes_key(key)
  ciphertext = validate_bytes_input(payload["ciphertext"], "ciphertext")

  if mode == "ECB":
    cipher = CryptoAES.new(normalized_key, CryptoAES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return crypto_unpad(plaintext, BLOCK_SIZE) if add_padding else plaintext

  if mode == "CBC":
    normalized_iv = validate_iv(payload.get("iv", iv))
    cipher = CryptoAES.new(normalized_key, CryptoAES.MODE_CBC, iv=normalized_iv)
    plaintext = cipher.decrypt(ciphertext)
    return crypto_unpad(plaintext, BLOCK_SIZE) if add_padding else plaintext

  if mode == "CTR":
    nonce = payload.get("nonce")
    counter = payload.get("counter")

    if nonce is None or counter is None:
      nonce, counter = split_counter_block(counter_block)

    cipher = CryptoAES.new(
      normalized_key,
      CryptoAES.MODE_CTR,
      nonce=nonce,
      initial_value=counter,
    )
    return cipher.decrypt(ciphertext)

  raise ValueError("Unsupported AES mode. Found: " + str(mode))


def build_result(
  mode,
  key_size,
  operation,
  sample_name,
  sample_type,
  category,
  data_size,
  measurement,
  validation_passed,
  adapter,
  note="",
):
  if measurement["error"] and not note:
    note = measurement["error_type"] + ": " + measurement["error"]

  status = "PASS" if validation_passed else "FAIL"

  throughput = 0.0
  if data_size > 0 and measurement["duration"] > 0:
    throughput = (data_size / (1024 * 1024)) / measurement["duration"]

  return {
    "mode": mode,
    "key_size": key_size,
    "operation": operation,
    "sample_name": sample_name,
    "sample_type": sample_type,
    "category": category,
    "status": status,
    "validation_result": "PASS" if validation_passed else "FAIL",
    "duration": measurement["duration"],
    "peak_bytes": measurement["peak_bytes"],
    "throughput_mib_s": throughput,
    "adapter": adapter,
    "data_size": data_size,
    "note": note,
  }


def run_vector_tests(mode, vectors):
  results = []

  for key_size, vector in vectors.items():
    encrypt_measurement = measure_operation(
      encrypt_raw_mode,
      mode,
      vector["key"],
      vector["plaintext"],
      vector.get("iv", DEFAULT_IV),
      vector.get("counter_block", DEFAULT_COUNTER_BLOCK),
    )
    results.append(
      build_result(
        mode,
        key_size,
        "Encryption",
        f"nist_{mode.lower()}_{key_size}.hex",
        "vector",
        "NIST Vector",
        len(vector["plaintext"]),
        encrypt_measurement,
        encrypt_measurement["result"] == vector["ciphertext"],
        "project-raw",
      )
    )

    decrypt_measurement = measure_operation(
      decrypt_raw_mode,
      mode,
      vector["key"],
      vector["ciphertext"],
      vector.get("iv", DEFAULT_IV),
      vector.get("counter_block", DEFAULT_COUNTER_BLOCK),
    )
    results.append(
      build_result(
        mode,
        key_size,
        "Decryption",
        f"nist_{mode.lower()}_{key_size}.hex",
        "vector",
        "NIST Vector",
        len(vector["ciphertext"]),
        decrypt_measurement,
        decrypt_measurement["result"] == vector["plaintext"],
        "project-raw",
      )
    )

  return results


def run_mmt_tests(mode, samples):
  results = []

  for key_size in SUPPORTED_KEY_SIZES:
    key = DETERMINISTIC_KEYS[key_size]

    for sample in samples:
      reference_payload = reference_encrypt(
        mode,
        key,
        sample["data"],
        add_padding=False,
      )

      encrypt_measurement = measure_operation(
        encrypt_raw_mode,
        mode,
        key,
        sample["data"],
      )
      results.append(
        build_result(
          mode,
          key_size,
          "Encryption",
          sample["name"],
          sample["type"],
          "MMT",
          len(sample["data"]),
          encrypt_measurement,
          reference_payload is not None and encrypt_measurement["result"] == reference_payload["ciphertext"],
          "project-raw",
          "" if reference_payload is not None else "Reference cipher unavailable",
        )
      )

      if reference_payload is None:
        decrypt_payload = {
          "ciphertext": sample["data"],
        }
      else:
        decrypt_payload = reference_payload

      decrypt_measurement = measure_operation(
        decrypt_raw_mode,
        mode,
        key,
        decrypt_payload["ciphertext"],
      )
      results.append(
        build_result(
          mode,
          key_size,
          "Decryption",
          sample["name"],
          sample["type"],
          "MMT",
          len(sample["data"]),
          decrypt_measurement,
          reference_payload is not None and decrypt_measurement["result"] == sample["data"],
          "project-raw",
          "" if reference_payload is not None else "Reference cipher unavailable",
        )
      )

  return results


def run_file_sample_tests(mode, samples):
  results = []

  for key_size in SUPPORTED_KEY_SIZES:
    key = DETERMINISTIC_KEYS[key_size]

    for sample in samples:
      reference_payload = reference_encrypt(
        mode,
        key,
        sample["data"],
        add_padding=mode in ("ECB", "CBC"),
      )
      encrypt_measurement = measure_operation(
        encrypt_sample_mode,
        mode,
        key,
        sample["data"],
      )

      encryption_valid = (
        reference_payload is not None
        and not encrypt_measurement["error"]
        and encrypt_measurement["result"]["ciphertext"] == reference_payload["ciphertext"]
      )
      results.append(
        build_result(
          mode,
          key_size,
          "Encryption",
          sample["name"],
          sample["type"],
          "File Sample",
          len(sample["data"]),
          encrypt_measurement,
          encryption_valid,
          encrypt_measurement["result"]["adapter"] if encrypt_measurement["result"] else "",
          "" if reference_payload is not None else "Reference cipher unavailable",
        )
      )

      decrypt_payload = reference_payload
      if decrypt_payload is None:
        continue

      decrypt_measurement = measure_operation(
        decrypt_sample_mode,
        mode,
        key,
        decrypt_payload,
      )
      results.append(
        build_result(
          mode,
          key_size,
          "Decryption",
          sample["name"],
          sample["type"],
          "File Sample",
          len(sample["data"]),
          decrypt_measurement,
          decrypt_measurement["result"] == sample["data"],
          "public-api" if mode in ("ECB", "CTR") else "raw-cbc-adapter",
        )
      )

  return results


def run_validation_tests(mode):
  key = DETERMINISTIC_KEYS[128]
  results = []

  invalid_key_measurement = measure_operation(AES_PCZ, mode, b"short-key")
  results.append(
    build_result(
      mode,
      None,
      "Initialization",
      "invalid_key.bin",
      "validation",
      "Validation",
      0,
      invalid_key_measurement,
      invalid_key_measurement["error_type"] == "ValueError",
      "public-api",
    )
  )

  invalid_type_measurement = measure_operation(
    encrypt_sample_mode,
    mode,
    key,
    "not-bytes",
  )
  results.append(
    build_result(
      mode,
      128,
      "Encryption",
      "invalid_type.txt",
      "validation",
      "Validation",
      0,
      invalid_type_measurement,
      invalid_type_measurement["error_type"] == "TypeError",
      "public-api" if mode in ("ECB", "CTR") else "raw-cbc-adapter",
    )
  )

  empty_measurement = measure_operation(
    encrypt_sample_mode,
    mode,
    key,
    b"",
  )
  results.append(
    build_result(
      mode,
      128,
      "Encryption",
      "empty_input.bin",
      "validation",
      "Validation",
      0,
      empty_measurement,
      empty_measurement["error_type"] == "ValueError",
      "public-api" if mode in ("ECB", "CTR") else "raw-cbc-adapter",
    )
  )

  if mode == "CBC":
    invalid_iv_measurement = measure_operation(
      encrypt_sample_mode,
      mode,
      key,
      b"cbc-iv-check",
      b"\x00" * 8,
    )
    results.append(
      build_result(
        mode,
        128,
        "Encryption",
        "invalid_iv.bin",
        "validation",
        "Validation",
        0,
        invalid_iv_measurement,
        invalid_iv_measurement["error_type"] == "ValueError",
        "raw-cbc-adapter",
      )
    )

    invalid_length_measurement = measure_operation(
      decrypt_raw_mode,
      mode,
      key,
      b"\x00" * 15,
    )
    results.append(
      build_result(
        mode,
        128,
        "Decryption",
        "invalid_ciphertext_length.bin",
        "validation",
        "Validation",
        15,
        invalid_length_measurement,
        invalid_length_measurement["error_type"] == "ValueError",
        "project-raw",
      )
    )

  if mode == "CTR":
    invalid_counter_measurement = measure_operation(
      encrypt_raw_mode,
      mode,
      key,
      b"ctr-check",
      DEFAULT_IV,
      b"\x00" * 15,
    )
    results.append(
      build_result(
        mode,
        128,
        "Encryption",
        "invalid_counter_block.bin",
        "validation",
        "Validation",
        0,
        invalid_counter_measurement,
        invalid_counter_measurement["error_type"] == "ValueError",
        "public-api",
      )
    )

  if mode == "ECB":
    invalid_length_measurement = measure_operation(
      decrypt_raw_mode,
      mode,
      key,
      b"\x00" * 15,
    )
    results.append(
      build_result(
        mode,
        128,
        "Decryption",
        "invalid_ciphertext_length.bin",
        "validation",
        "Validation",
        15,
        invalid_length_measurement,
        invalid_length_measurement["error_type"] == "ValueError",
        "project-raw",
      )
    )

  sample_payload = encrypt_sample_mode(mode, key, b"corruption-check-payload")
  corrupted_payload = dict(sample_payload)
  corrupted_bytes = bytearray(corrupted_payload["ciphertext"])
  corrupted_bytes[0] ^= 0x01
  corrupted_payload["ciphertext"] = bytes(corrupted_bytes)

  corrupted_measurement = measure_operation(
    decrypt_sample_mode,
    mode,
    key,
    corrupted_payload,
  )
  corruption_detected = False

  if corrupted_measurement["error"]:
    corruption_detected = True
  elif corrupted_measurement["result"] != b"corruption-check-payload":
    corruption_detected = True

  results.append(
    build_result(
      mode,
      128,
      "Decryption",
      "corrupted_payload.bin",
      "validation",
      "Validation",
      len(corrupted_payload["ciphertext"]),
      corrupted_measurement,
      corruption_detected,
      "public-api" if mode in ("ECB", "CTR") else "raw-cbc-adapter",
      "" if corruption_detected else "Corrupted payload was accepted as valid",
    )
  )

  return results


# --- Manual Test ---
# print(encrypt_raw_mode("ECB", DETERMINISTIC_KEYS[128], bytes.fromhex("00112233445566778899aabbccddeeff")).hex())
