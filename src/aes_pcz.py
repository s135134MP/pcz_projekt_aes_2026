# from src.transformations import bytes_to_state, state_to_bytes, sub_bytes, key_schedule, add_round_key, mix_columns, shift_rows, get_round_number

import src.transformations as tr
import src.helpers as h


class AES_PCZ:
  def __init__(self, mode, key):
    keySize = len(key) * 8
    if keySize not in [128, 192, 256]:
      raise ValueError("Unsupported key size. Found: " + str(keySize) + ", expected: [128, 192, 256]")
    self.key = key

    if mode in ["CTR", "GCM", "ECB", "CBC"]:
      self.mode = mode
    else:
      raise ValueError("Unsupported AES mode. Found: " + mode)
  
  def _prepare_data(self, data, block_size=16):
    # pad data
    pad_len = block_size - (len(data) % block_size)
    pad_data = data + bytes([pad_len] * pad_len)

    # split to blocks
    blocks = [pad_data[i:i+16] for i in range(0, len(pad_data), 16)]
    self.blocks = blocks
  
  def _prepare_output(self, data):
    pad_len = data[-1]
    return data[:-pad_len]

  def _prepare_data_decrypt(self, data, block_size=16):
    if len(data) % block_size != 0:
      raise ValueError("Invalid data length")

    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    self.blocks = blocks

  def _encrypt_ecb(self):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)

    encrypted_block = []

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
      encrypted_block.append(tr.state_to_bytes(state))

    result = b''.join(encrypted_block)

    return result

  def _decrypt_ecb(self):
    round_keys = tr.key_schedule(self.key)
    n_r = h.get_round_number(self.key)

    decrypted_block = []

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

      decrypted_block.append(tr.state_to_bytes(state))

    result = b''.join(decrypted_block)

    return self._prepare_output(result)

  def encrypt(self, bytes):
    self._prepare_data(bytes)

    if self.mode == "ECB":
      result = self._encrypt_ecb()

    return result


  def decrypt(self, bytes):
    self._prepare_data_decrypt(bytes)

    if self.mode == "ECB":
      result = self._decrypt_ecb()
    
    return result
    