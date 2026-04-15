"""
Implementacja funkcji ShiftRows oraz MixColumns algorytmu AES
Projekt: Implementacja i analiza algorytmu szyfrującego AES w różnych trybach pracy
Autorzy: Kacper Dziembek, Eduard Prudnikow, Marcin Ptok (Grupa 2)
"""

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


# ---------------------------------------------------------------------------
# Testy
# ---------------------------------------------------------------------------

def test_shift_rows():
    """
    Testuje ShiftRows na przykładzie z oficjalnej specyfikacji FIPS 197 AES.
    Stan zapisany jako macierz wierszy (row-major), zgodnie z notacją FIPS 197.
    """
    print("=" * 55)
    print("TEST: ShiftRows")
    print("=" * 55)

    # Stan wejściowy (po SubBytes, przed ShiftRows) - FIPS 197 Appendix B
    # Zapisany jako lista wierszy: state[wiersz][kolumna]
    state = [
        [0xD4, 0xE0, 0xB8, 0x1E],
        [0x27, 0xBF, 0xB4, 0x41],
        [0x11, 0x98, 0x5D, 0x52],
        [0xAE, 0xF1, 0xE5, 0x30],
    ]
    # Oczekiwane wyjście po ShiftRows (z FIPS 197 Appendix B)
    expected = [
        [0xD4, 0xE0, 0xB8, 0x1E],
        [0xBF, 0xB4, 0x41, 0x27],
        [0x5D, 0x52, 0x11, 0x98],
        [0x30, 0xAE, 0xF1, 0xE5],
    ]

    print_state(state, "Wejście")

    result = shift_rows(state)
    print_state(result, "Wyjście (ShiftRows)")
    print_state(expected, "Oczekiwane")

    ok = result == expected
    print(f"\n  Wynik: {'✓ POPRAWNY' if ok else '✗ BŁĘDNY'}")

    # Sprawdzenie odwrotności
    restored = inv_shift_rows(result)
    inv_ok = restored == state
    print(f"  InvShiftRows(ShiftRows(x)) == x: {'✓ TAK' if inv_ok else '✗ NIE'}")


def test_mix_columns():
    """
    Testuje MixColumns na przykładach z oficjalnej specyfikacji FIPS 197.
    Stan wejściowy to wynik ShiftRows z Appendix B.
    """
    print("\n" + "=" * 55)
    print("TEST: MixColumns")
    print("=" * 55)

    # Stan wejściowy (po ShiftRows, przed MixColumns) - FIPS 197 Appendix B
    state = [
        [0xD4, 0xE0, 0xB8, 0x1E],
        [0xBF, 0xB4, 0x41, 0x27],
        [0x5D, 0x52, 0x11, 0x98],
        [0x30, 0xAE, 0xF1, 0xE5],
    ]
    # Oczekiwane wyjście po MixColumns (z FIPS 197 Appendix B)
    expected = [
        [0x04, 0xE0, 0x48, 0x28],
        [0x66, 0xCB, 0xF8, 0x06],
        [0x81, 0x19, 0xD3, 0x26],
        [0xE5, 0x9A, 0x7A, 0x4C],
    ]

    print_state(state, "Wejście")

    result = mix_columns(state)
    print_state(result, "Wyjście (MixColumns)")
    print_state(expected, "Oczekiwane")

    ok = result == expected
    print(f"\n  Wynik: {'✓ POPRAWNY' if ok else '✗ BŁĘDNY'}")

    # Sprawdzenie odwrotności
    restored = inv_mix_columns(result)
    inv_ok = restored == state
    print(f"  InvMixColumns(MixColumns(x)) == x: {'✓ TAK' if inv_ok else '✗ NIE'}")


def test_gmul():
    """Kilka przypadków testowych dla mnożenia w GF(2^8) zgodnie z FIPS 197."""
    print("\n" + "=" * 55)
    print("TEST: gmul (mnożenie w GF(2^8))")
    print("=" * 55)
    cases = [
        (0x57, 0x83, 0xC1),   # z FIPS 197 przykłady
        (0x57, 0x13, 0xFE),
        (0x02, 0x87, 0x15),
    ]
    for a, b, expected in cases:
        result = gmul(a, b)
        ok = result == expected
        print(f"  gmul(0x{a:02X}, 0x{b:02X}) = 0x{result:02X}  "
              f"(oczekiwano 0x{expected:02X}) {'✓' if ok else '✗'}")


if __name__ == "__main__":
    test_gmul()
    test_shift_rows()
    test_mix_columns()
    print("\n" + "=" * 55)
    print("Wszystkie testy zakończone.")
    print("=" * 55)
