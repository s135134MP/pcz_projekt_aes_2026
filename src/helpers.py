def validate_aes_key(key):
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes-like")
    normalized_key = bytes(key)
    if len(normalized_key) not in AES_ROUNDS:
        raise ValueError("AES key must be 16, 24, or 32 bytes long")
    return normalized_key


def get_round_number(key):
    normalized_key = validate_aes_key(key)
    return AES_ROUNDS[len(normalized_key)]

AES_ROUNDS = {
    16: 10,
    24: 12,
    32: 14,
}