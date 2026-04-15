from src.transformations import bytes_to_state, state_to_bytes, SubBytes, KeySchedule, AddRoundKey, getNr


from aes_transformations import mix_columns, shift_rows

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
  
  def _prepare_data(self, block_size=16):
    # pad data
    pad_len = block_size - (len(self.bytes) % block_size)
    pad_data = self.bytes + bytes([pad_len] * pad_len)

    # split to blocks
    blocks = [pad_data[i:i+16] for i in range(0, len(pad_data), 16)]
    self.blocks = blocks

  def encrypt(self, bytes):
    self.bytes = bytes
    self._prepare_data()

    round_keys = KeySchedule(self.key)
    n_r = getNr(self.key)

    encrypted_block = []

    for block in self.blocks:
      state = bytes_to_state(block)
      state = AddRoundKey(state, round_keys[0])

      for round in range(1, n_r):
        state = SubBytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = AddRoundKey(state, round_keys[round])

      state = SubBytes(state)
      state = shift_rows(state)
      state = AddRoundKey(state, round_keys[n_r])

      encrypted_block.append(state_to_bytes(state))

    result = b''.join(encrypted_block)

    return result