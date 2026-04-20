def get_round_number(key):
    keySize = len(key) * 8
    if keySize == 128:
        return 10
    elif keySize == 192:
        return 12
    elif keySize == 256:
        return 14
    else:
        raise ValueError("Wrong key size")