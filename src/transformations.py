import src.helpers as h

S_BOX = (
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = (
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
)

RCON = (
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
)

# ---------------------------------------------------------------------------
# Pomocnicze operacje na ciałem GF(2^8)
# ---------------------------------------------------------------------------
def xtime(a: int) -> int:
    """
    Mnożenie przez 2 w ciele GF(2^8) z wielomianem nierozkładalnym x^8+x^4+x^3+x+1.
    Odpowiada przesunięciu bitowemu w lewo i ewentualnemu XOR z 0x1B.
    """
    result = (a << 1) & 0xFF
    if a & 0x80:
        result ^= 0x1B
    return result


def gmul(a: int, b: int) -> int:
    """
    Mnożenie dwóch elementów w ciele GF(2^8) metodą 'Russian peasant multiplication'.
    Używane przez MixColumns do mnożenia przez stałe 2 i 3.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


# ---------------------------------------------------------------------------
# Reprezentacja stanu AES
# ---------------------------------------------------------------------------
# Stan AES to macierz 4x4 bajtów (16 bajtów łącznie).
# Reprezentujemy ją jako listę 4 wierszy, każdy to lista 4 int (0-255).
#
#   state[wiersz][kolumna]
#
# Przykład:
#   state = [
#       [b0,  b4,  b8,  b12],   # wiersz 0
#       [b1,  b5,  b9,  b13],   # wiersz 1
#       [b2,  b6,  b10, b14],   # wiersz 2
#       [b3,  b7,  b11, b15],   # wiersz 3
#   ]
# ---------------------------------------------------------------------------

def bytes_to_state(data: bytes) -> list[list[int]]:
    """Konwertuje 16 bajtów na macierz stanu 4x4 (kolumna-główna kolejność)."""
    assert len(data) == 16, "Blok AES musi mieć dokładnie 16 bajtów."
    return [[data[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state: list[list[int]]) -> bytes:
    """Konwertuje macierz stanu 4x4 z powrotem do 16 bajtów."""
    return bytes(state[r][c] for c in range(4) for r in range(4))


def print_state(state: list[list[int]], label: str = "Stan") -> None:
    """Wyświetla macierz stanu w czytelnym formacie hex."""
    print(f"\n{label}:")
    for row in state:
        print("  " + "  ".join(f"{b:02X}" for b in row))


# ---------------------------------------------------------------------------
# ShiftRows
# ---------------------------------------------------------------------------

def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    Transformacja ShiftRows (szyfrowanie).

    Każdy wiersz macierzy stanu jest cyklicznie przesuwany w lewo o:
      - wiersz 0: 0 pozycji (bez zmian)
      - wiersz 1: 1 pozycja
      - wiersz 2: 2 pozycje
      - wiersz 3: 3 pozycje

    Parametry:
        state: macierz stanu 4x4

    Zwraca:
        Nowa macierz stanu po transformacji ShiftRows.
    """
    new_state = [row[:] for row in state]  # kopia głęboka
    for r in range(4):
        new_state[r] = state[r][r:] + state[r][:r]
    return new_state


def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    Odwrotna transformacja ShiftRows (deszyfrowanie).

    Każdy wiersz jest cyklicznie przesuwany w prawo o:
      - wiersz 0: 0 pozycji
      - wiersz 1: 1 pozycja
      - wiersz 2: 2 pozycje
      - wiersz 3: 3 pozycje
    """
    new_state = [row[:] for row in state]
    for r in range(4):
        new_state[r] = state[r][-r:] + state[r][:-r] if r > 0 else state[r][:]
    return new_state


# ---------------------------------------------------------------------------
# MixColumns
# ---------------------------------------------------------------------------

def mix_single_column(col: list[int]) -> list[int]:
    """
    Transformacja MixColumns dla jednej kolumny.

    Kolumna jest traktowana jako wielomian nad GF(2^8) i mnożona przez
    stały wielomian a(x) = {03}x^3 + {01}x^2 + {01}x + {02} modulo x^4+1.

    Macierz mnożenia (MDS):
        | 2 3 1 1 |   | s0 |
        | 1 2 3 1 | x | s1 |
        | 1 1 2 3 |   | s2 |
        | 3 1 1 2 |   | s3 |

    Parametry:
        col: lista 4 bajtów (jedna kolumna stanu)

    Zwraca:
        Nowa kolumna po transformacji.
    """
    s0, s1, s2, s3 = col
    return [
        gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2           ^ s3,
        s0           ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3,
        s0           ^ s1           ^ gmul(0x02, s2) ^ gmul(0x03, s3),
        gmul(0x03, s0) ^ s1           ^ s2           ^ gmul(0x02, s3),
    ]


def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    Transformacja MixColumns (szyfrowanie).

    Każda z czterech kolumn macierzy stanu jest niezależnie przetwarzana
    przez funkcję mix_single_column.

    Parametry:
        state: macierz stanu 4x4

    Zwraca:
        Nowa macierz stanu po transformacji MixColumns.
    """
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            new_state[r][c] = mixed[r]
    return new_state


def inv_mix_single_column(col: list[int]) -> list[int]:
    """
    Odwrotna transformacja MixColumns dla jednej kolumny.

    Macierz odwrotna (MDS^-1):
        | 14  11  13   9 |
        |  9  14  11  13 |
        | 13   9  14  11 |
        | 11  13   9  14 |
    """
    s0, s1, s2, s3 = col
    return [
        gmul(0x0E, s0) ^ gmul(0x0B, s1) ^ gmul(0x0D, s2) ^ gmul(0x09, s3),
        gmul(0x09, s0) ^ gmul(0x0E, s1) ^ gmul(0x0B, s2) ^ gmul(0x0D, s3),
        gmul(0x0D, s0) ^ gmul(0x09, s1) ^ gmul(0x0E, s2) ^ gmul(0x0B, s3),
        gmul(0x0B, s0) ^ gmul(0x0D, s1) ^ gmul(0x09, s2) ^ gmul(0x0E, s3),
    ]


def inv_mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    Odwrotna transformacja MixColumns (deszyfrowanie).
    """
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            new_state[r][c] = mixed[r]
    return new_state

def round_key_to_state(round_key):
    """Convert a 16-byte round key into the project state matrix."""
    if len(round_key) != 16:
        raise ValueError("Round key must contain exactly 16 bytes")

    return bytes_to_state(round_key)


def add_round_key(state, round_key):
    """XOR the current AES state with the round key."""
    round_key_state = round_key_to_state(round_key) if isinstance(round_key, (bytes, bytearray)) else round_key

    for row in range(4):
        for column in range(4):
            state[row][column] ^= round_key_state[row][column]

    return state

def rot_word(word):
    """Rotate a 4-byte word one byte to the left."""
    return word[1:] + word[:1]


def sub_word(word):
    """Apply the AES S-Box to a 4-byte word."""
    return [S_BOX[value] for value in word]

def xor_words(left, right):
    """XOR two 4-byte words."""
    return [left[index] ^ right[index] for index in range(4)]

def sub_bytes(state):
    return [[S_BOX[value] for value in row] for row in state]

def inv_sub_bytes(state):
    return [[INV_S_BOX[value] for value in row] for row in state]

def key_schedule(key):
    key = h.validate_aes_key(key)
    nk = len(key) // 4
    nr = h.get_round_number(key)
    total_words = 4 * (nr + 1)

    words = [list(key[index:index + 4]) for index in range(0, len(key), 4)]

    while len(words) < total_words:
        temp = words[-1][:]
        word_index = len(words)

        if word_index % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[(word_index // nk) - 1]
        elif nk > 6 and word_index % nk == 4:
            temp = sub_word(temp)

        words.append(xor_words(words[-nk], temp))

    return [bytes(sum(words[index:index + 4], [])) for index in range(0, len(words), 4)]