import src.transformations as tr
import src.helpers as h
import os

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
  
  def _prepare_data(self, data, add_pad = True, block_size=16):
    if add_pad:
      pad_len = block_size - (len(data) % block_size)
      pad_data = data + bytes([pad_len] * pad_len)

      self.blocks = [pad_data[i:i+16] for i in range(0, len(pad_data), 16)]
    else:
      self.blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

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

  # ---------------------------------------------------------------------------
  # GCM – szyfrowanie z uwierzytelnianiem
  # ---------------------------------------------------------------------------

  def _gcm_generate_iv(self):
    """Generuje losowy 96-bitowy (12-bajtowy) IV dla GCM."""
    self.iv = os.urandom(12)

  def _gcm_counter_block(self, counter: int) -> bytes:
    """
    Buduje 128-bitowy blok licznika GCM:
      J_i = IV (96 bitów) || counter (32 bity, big-endian)

    Parametry:
        counter: wartość licznika (J0 = 1, kolejne bloki = 2, 3, …)

    Zwraca:
        16-bajtowy blok licznika.
    """
    return self.iv + counter.to_bytes(4, 'big')

  def _gcm_compute_H(self) -> bytes:
    """
    Oblicza klucz GHASH: H = AES_K(0^128).
    H jest używany jako element GF(2^128) przez funkcję GHASH.

    Zwraca:
        16-bajtowy klucz H.
    """
    return self._encrypt_counter_block(b'\x00' * 16)

  def _encrypt_gcm(self, aad: bytes = b'') -> tuple[bytes, bytes, bytes]:
    """
    Szyfrowanie w trybie GCM (Galois/Counter Mode).

    Schemat działania:
      1. H = AES_K(0^128)                          – klucz GHASH
      2. J0 = IV || 0x00000001                     – blok bazowy licznika
      3. E0 = AES_K(J0)                            – do ochrony tagu
      4. Dla i = 1..n: C_i = P_i XOR AES_K(J_i)  – szyfrowanie CTR od J1
      5. T = GHASH(H, AAD, C) XOR E0              – tag uwierzytelniający

    Parametry:
        aad: Additional Authenticated Data (dane uwierzytelniane, nie szyfrowane)

    Zwraca:
        (ciphertext, iv, tag) – szyfrogram, IV oraz 16-bajtowy tag GCM.
    """
    H = self._gcm_compute_H()

    # J0 = IV || 1  (counter = 1 dla bloku bazowego)
    J0 = self._gcm_counter_block(1)
    E0 = self._encrypt_counter_block(J0)  # AES_K(J0) – służy do XOR z tagiem

    # Szyfrowanie CTR: licznik startuje od 2 (J1 = IV || 2, J2 = IV || 3, …)
    encrypted_blocks = []
    counter = 2
    for block in self.blocks:
      Ji = self._gcm_counter_block(counter)
      keystream = self._encrypt_counter_block(Ji)
      # XOR tylko tyle bajtów ile ma blok (ostatni blok może być krótszy)
      encrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
      encrypted_blocks.append(encrypted_block)
      counter += 1

    ciphertext = b''.join(encrypted_blocks)

    # GHASH(H, AAD, C) XOR E(K, J0)
    ghash_result = tr.ghash(H, aad, ciphertext)
    tag = bytes(a ^ b for a, b in zip(ghash_result, E0))

    return ciphertext, self.iv, tag

  def _decrypt_gcm(self, aad: bytes = b'', tag: bytes = b'') -> bytes:
    """
    Deszyfrowanie i weryfikacja integralności w trybie GCM.

    Schemat działania:
      1. H = AES_K(0^128)
      2. J0 = IV || 0x00000001
      3. E0 = AES_K(J0)
      4. T' = GHASH(H, AAD, C) XOR E0   – obliczenie oczekiwanego tagu
      5. Porównanie T' z otrzymanym tagiem (constant-time)
      6. Deszyfrowanie CTR (identyczne jak szyfrowanie)

    Parametry:
        aad : Additional Authenticated Data (te same co przy szyfrowaniu)
        tag : 16-bajtowy tag uwierzytelniający otrzymany razem z szyfrogramem

    Zwraca:
        Odszyfrowany plaintext.

    Wyjątki:
        ValueError – jeśli tag jest niepoprawny (naruszenie integralności).
    """
    H = self._gcm_compute_H()

    J0 = self._gcm_counter_block(1)
    E0 = self._encrypt_counter_block(J0)

    # Ciphertext = wszystkie bloki złączone
    ciphertext = b''.join(self.blocks)

    # Weryfikacja tagu przed deszyfrowaniem (fail-fast)
    ghash_result = tr.ghash(H, aad, ciphertext)
    expected_tag = bytes(a ^ b for a, b in zip(ghash_result, E0))

    # Porównanie constant-time (ochrona przed timing attacks)
    if not _constant_time_compare(expected_tag, tag):
      raise ValueError("GCM authentication tag mismatch – data integrity compromised!")

    # Deszyfrowanie CTR (licznik startuje od 2, identycznie jak przy szyfrowaniu)
    decrypted_blocks = []
    counter = 2
    for block in self.blocks:
      Ji = self._gcm_counter_block(counter)
      keystream = self._encrypt_counter_block(Ji)
      decrypted_block = bytes(a ^ b for a, b in zip(block, keystream))
      decrypted_blocks.append(decrypted_block)
      counter += 1

    return b''.join(decrypted_blocks)

  def encrypt(self, bytes, counter = 0, nonce = "", aad: bytes = b'', iv: bytes = b''):

    if self.mode == "ECB":
      self._prepare_data(bytes, add_pad=True)
      result = self._encrypt_ecb()
    
    if self.mode == "CTR":
      self._prepare_data(bytes, add_pad=False)

      # Check if user passed a nonce
      # If not generate a random one
      if nonce != "":
        self.nonce = nonce
      else:
        self._generate_nonce()

      result = self._encrypt_ctr(counter)

    if self.mode == "GCM":
      # GCM działa bez paddingu – szyfruje dokładną ilość bajtów
      self._prepare_data(bytes, add_pad=False)

      if iv != b'':
        if len(iv) != 12:
          raise ValueError("GCM IV must be exactly 12 bytes")
        self.iv = iv
      else:
        self._gcm_generate_iv()

      result = self._encrypt_gcm(aad)

    return result


  def decrypt(self, bytes, nonce = "", aad: bytes = b'', tag: bytes = b'', iv: bytes = b''):
    self._prepare_data_decrypt(bytes)

    if self.mode == "ECB":
      result = self._decrypt_ecb()

    if self.mode == "CTR":
      raise NotImplementedError("TODO")

    if self.mode == "GCM":
      if len(iv) != 12:
        raise ValueError("GCM IV must be exactly 12 bytes")
      if len(tag) != 16:
        raise ValueError("GCM tag must be exactly 16 bytes")
      self.iv = iv
      result = self._decrypt_gcm(aad, tag)
    
    return result


# ---------------------------------------------------------------------------
# Funkcja pomocnicza – porównanie stałoczasowe
# ---------------------------------------------------------------------------

def _constant_time_compare(a: bytes, b: bytes) -> bool:
  """
  Porównuje dwa ciągi bajtów w czasie stałym (niezależnym od zawartości).
  Zabezpiecza przed atakami typu timing attack na weryfikację tagu GCM.

  Zwraca True tylko gdy a == b i oba mają tę samą długość.
  """
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b):
    result |= x ^ y
  return result == 0
