import src.transformations as tr
import src.helpers as h
import os


class AES_PCZ:
  """def __init__(self, mode, key):
    keySize = len(key) * 8
    if keySize not in [128, 192, 256]:
      raise ValueError("Unsupported key size. Found: " + str(keySize) + ", expected: [128, 192, 256]")
    self.key = key

    if mode in ["CTR", "GCM", "ECB", "CBC"]:
      self.mode = mode
    else:
      raise ValueError("Unsupported AES mode. Found: " + mode)

  def _prepare_data(self, data, add_pad=True, block_size=16):
    if add_pad:
      pad_len = block_size - (len(data) % block_size)
      pad_data = data + bytes([pad_len] * pad_len)

      self.blocks = [pad_data[i:i + 16] for i in range(0, len(pad_data), 16)]
    else:
      self.blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]"""

  def __init__(self, mode, key):
    if not isinstance(mode, str):
      raise TypeError("AES mode must be a string")
    self.key = h.validate_aes_key(key)

    if mode in ["CTR", "GCM", "ECB", "CBC"]:
      self.mode = mode
    else:
      raise ValueError("Unsupported AES mode. Found: " + mode)

  def _validate_bytes_input(self, data, field_name):
    if not isinstance(data, (bytes, bytearray)):
      raise TypeError(field_name + " must be bytes-like")
    normalized_data = bytes(data)
    if len(normalized_data) == 0:
      raise ValueError(field_name + " cannot be empty")
    return normalized_data

  def _validate_counter(self, counter):
    if not isinstance(counter, int):
      raise TypeError("Counter must be an integer")
    if counter < 0 or counter > ((1 << 64) - 1):
      raise ValueError("Counter must fit into 8 bytes")
    return counter

  def _validate_nonce(self, nonce):
    if nonce == "":
      return ""

    if not isinstance(nonce, (bytes, bytearray)):
      raise TypeError("Nonce must be bytes-like")

    normalized_nonce = bytes(nonce)
    if len(normalized_nonce) != 8:
      raise ValueError("Nonce must contain exactly 8 bytes")
    return normalized_nonce

  def _prepare_data(self, data, add_pad=True, block_size=16):
    if add_pad:
      pad_len = block_size - (len(data) % block_size)
      pad_data = data + bytes([pad_len] * pad_len)
      self.blocks = [pad_data[i:i + 16] for i in range(0, len(pad_data), 16)]
    else:
      self.blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]

  def _prepare_output(self, data):
    pad_len = data[-1]
    return data[:-pad_len]

  def _prepare_data_decrypt(self, data, block_size=16):
    if len(data) % block_size != 0:
      raise ValueError("Invalid data length")

    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    self.blocks = blocks
  
  def _generate_nonce(self):
    self.nonce = os.urandom(8)
  
  def _generate_counter_block(self, counter):
    return self.nonce + counter.to_bytes(8, 'big') 

  def _encrypt_ecb(self):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)

    encrypted_blocks = []

    for block in self.blocks:
      state = tr.bytes_to_state(block)
      state = tr.add_round_key(state, round_keys[0])

      for round in range(1, n_r):
        state = tr.sub_bytes(state)
        state = tr.shift_rows(state)
        state = tr.mix_columns(state)
        state = tr.add_round_key(state, round_keys[round])

      state = tr.sub_bytes(state)
      state = tr.shift_rows(state)
      state = tr.add_round_key(state, round_keys[n_r])
      encrypted_blocks.append(tr.state_to_bytes(state))

    result = b''.join(encrypted_blocks)

    return result

  def _encrypt_counter_block(self, block):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)

    state = tr.bytes_to_state(block)
    state = tr.add_round_key(state, round_keys[0])

    for round in range(1, n_r):
        state = tr.sub_bytes(state)
        state = tr.shift_rows(state)
        state = tr.mix_columns(state)
        state = tr.add_round_key(state, round_keys[round])

    state = tr.sub_bytes(state)
    state = tr.shift_rows(state)
    state = tr.add_round_key(state, round_keys[n_r])

    return tr.state_to_bytes(state)

  def _encrypt_ctr(self, counter = 0):
    counter = counter

    encrypted_blocks = []

    for block in self.blocks:
      counter_block = self._generate_counter_block(counter)

      encrypted_counter_block = self._encrypt_counter_block(counter_block)
      encrypted_block = bytes(a ^ b for a, b in zip(block, encrypted_counter_block))

      encrypted_blocks.append(encrypted_block)
      counter += 1

    result = b''.join(encrypted_blocks)

    return (result, self.nonce)

  def _decrypt_ecb(self):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)

    decrypted_blocks = []

    for block in self.blocks:
      state = tr.bytes_to_state(block)
      state = tr.add_round_key(state, round_keys[n_r])

      for round in range(n_r - 1, 0, -1):
        state = tr.inv_shift_rows(state)
        state = tr.inv_sub_bytes(state)
        state = tr.add_round_key(state, round_keys[round])
        state = tr.inv_mix_columns(state)

      state = tr.inv_shift_rows(state)
      state = tr.inv_sub_bytes(state)
      state = tr.add_round_key(state, round_keys[0])

      decrypted_blocks.append(tr.state_to_bytes(state))

    result = b''.join(decrypted_blocks)

    return self._prepare_output(result)

  def encrypt(self, bytes, counter=0, nonce=""):
    data = self._validate_bytes_input(bytes, "Plaintext")

    if self.mode == "ECB":
      self._prepare_data(data, add_pad=True)
      result = self._encrypt_ecb()

    elif self.mode == "CTR":
      self._prepare_data(data, add_pad=False)
      counter = self._validate_counter(counter)
      nonce = self._validate_nonce(nonce)

      # Check if user passed a nonce
      # If not generate a random one
      if nonce != "":
        self.nonce = nonce
      else:
        self._generate_nonce()

      result = self._encrypt_ctr(counter)
    else:
      raise NotImplementedError("Encryption is not implemented for mode: " + self.mode)

    return result

  def decrypt(self, bytes, nonce=""):
    data = self._validate_bytes_input(bytes, "Ciphertext")
    self._prepare_data_decrypt(data)

    if self.mode == "ECB":
      result = self._decrypt_ecb()

    elif self.mode == "CTR":
      raise NotImplementedError("CTR decryption is not implemented")
    else:
      raise NotImplementedError("Decryption is not implemented for mode: " + self.mode)

    return result
