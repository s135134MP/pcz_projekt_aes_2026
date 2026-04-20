import src.helpers as h
import src.transformations as tr


# Keep the existing AES class API and extend it for all supported key sizes.
class AES_PCZ:
  BLOCK_SIZE = 16
  SUPPORTED_MODES = {"CTR", "GCM", "ECB", "CBC"}
  SUPPORTED_KEY_SIZES = {16, 24, 32}

  # Validate constructor inputs and store the normalized AES key.
  def __init__(self, mode, key):
    if not isinstance(mode, str):
      raise TypeError("AES mode must be a string")

    if not isinstance(key, (bytes, bytearray)):
      raise TypeError("AES key must be bytes-like")

    normalized_key = bytes(key)
    if len(normalized_key) not in self.SUPPORTED_KEY_SIZES:
      raise ValueError("Unsupported key size. Expected 16, 24, or 32 bytes")

    if mode not in self.SUPPORTED_MODES:
      raise ValueError("Unsupported AES mode. Found: " + mode)

    self.key = normalized_key
    self.mode = mode
    self.blocks = []

  # Validate and normalize byte input for encryption or decryption.
  def _validate_bytes_input(self, data, field_name):
    if not isinstance(data, (bytes, bytearray)):
      raise TypeError(field_name + " must be bytes-like")

    normalized_data = bytes(data)
    if not normalized_data:
      raise ValueError(field_name + " must not be empty")

    return normalized_data

  # Pad plaintext with PKCS#7 and split it into AES-sized blocks.
  def _prepare_data(self, data, block_size=BLOCK_SIZE):
    normalized_data = self._validate_bytes_input(data, "Plaintext")
    pad_len = block_size - (len(normalized_data) % block_size)
    padded_data = normalized_data + bytes([pad_len] * pad_len)
    self.blocks = [padded_data[index:index + block_size] for index in range(0, len(padded_data), block_size)]

  # Validate PKCS#7 padding after ECB decryption.
  def _prepare_output(self, data):
    if not data or len(data) % self.BLOCK_SIZE != 0:
      raise ValueError("Invalid decrypted data length")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > self.BLOCK_SIZE:
      raise ValueError("Invalid PKCS#7 padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
      raise ValueError("Invalid PKCS#7 padding")

    return data[:-pad_len]

  # Split ciphertext into AES-sized blocks after validation.
  def _prepare_data_decrypt(self, data, block_size=BLOCK_SIZE):
    normalized_data = self._validate_bytes_input(data, "Ciphertext")
    if len(normalized_data) % block_size != 0:
      raise ValueError("Invalid ciphertext length")

    self.blocks = [normalized_data[index:index + block_size] for index in range(0, len(normalized_data), block_size)]

  # Encrypt the prepared blocks in ECB mode using the expanded round keys.
  def _encrypt_ecb(self):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)
    encrypted_blocks = []

    for block in self.blocks:
      state = tr.bytes_to_state(block)
      state = tr.add_round_key(state, round_keys[0])

      for round_index in range(1, n_r):
        state = tr.sub_bytes(state)
        state = tr.shift_rows(state)
        state = tr.mix_columns(state)
        state = tr.add_round_key(state, round_keys[round_index])

      state = tr.sub_bytes(state)
      state = tr.shift_rows(state)
      state = tr.add_round_key(state, round_keys[n_r])
      encrypted_blocks.append(tr.state_to_bytes(state))

    return b"".join(encrypted_blocks)

  # Decrypt the prepared blocks in ECB mode using the expanded round keys.
  def _decrypt_ecb(self):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)
    decrypted_blocks = []

    for block in self.blocks:
      state = tr.bytes_to_state(block)
      state = tr.add_round_key(state, round_keys[n_r])

      for round_index in range(n_r - 1, 0, -1):
        state = tr.inv_shift_rows(state)
        state = tr.inv_sub_bytes(state)
        state = tr.add_round_key(state, round_keys[round_index])
        state = tr.inv_mix_columns(state)

      state = tr.inv_shift_rows(state)
      state = tr.inv_sub_bytes(state)
      state = tr.add_round_key(state, round_keys[0])
      decrypted_blocks.append(tr.state_to_bytes(state))

    return self._prepare_output(b"".join(decrypted_blocks))

  # Encrypt plaintext with the configured AES mode.
  def encrypt(self, bytes):
    self._prepare_data(bytes)

    if self.mode == "ECB":
      return self._encrypt_ecb()

    raise NotImplementedError("AES mode " + self.mode + " is not implemented yet")

  # Decrypt ciphertext with the configured AES mode.
  def decrypt(self, bytes):
    self._prepare_data_decrypt(bytes)

    if self.mode == "ECB":
      return self._decrypt_ecb()

    raise NotImplementedError("AES mode " + self.mode + " is not implemented yet")


# --- Manual Tests ---
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
#
# key_128 = b"1234567890123456"
# key_192 = b"123456789012345678901234"
# key_256 = b"12345678901234567890123456789012"
# plaintext = b"HelloAES12345678"
#
# aes_128 = AES_PCZ(mode="ECB", key=key_128)
# aes_192 = AES_PCZ(mode="ECB", key=key_192)
# aes_256 = AES_PCZ(mode="ECB", key=key_256)
#
# cipher_128 = aes_128.encrypt(plaintext)
# cipher_192 = aes_192.encrypt(plaintext)
# cipher_256 = aes_256.encrypt(plaintext)
#
# assert aes_128.decrypt(cipher_128) == plaintext
# assert aes_192.decrypt(cipher_192) == plaintext
# assert aes_256.decrypt(cipher_256) == plaintext
#
# ref_128 = AES.new(key_128, AES.MODE_ECB).encrypt(pad(plaintext, 16))
# ref_192 = AES.new(key_192, AES.MODE_ECB).encrypt(pad(plaintext, 16))
# ref_256 = AES.new(key_256, AES.MODE_ECB).encrypt(pad(plaintext, 16))
#
# assert cipher_128 == ref_128
# assert cipher_192 == ref_192
# assert cipher_256 == ref_256
#
# try:
#   AES_PCZ(mode="ECB", key=b"short")
# except ValueError:
#   pass
#
# try:
#   aes_128.encrypt(b"")
# except ValueError:
#   pass
