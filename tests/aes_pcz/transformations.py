import src.transformations as tr

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

    tr.print_state(state, "Wejście")

    result = tr.shift_rows(state)
    tr.print_state(result, "Wyjście (ShiftRows)")
    tr.print_state(expected, "Oczekiwane")

    ok = result == expected
    print(f"\n  Wynik: {'✓ POPRAWNY' if ok else '✗ BŁĘDNY'}")

    # Sprawdzenie odwrotności
    restored = tr.inv_shift_rows(result)
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

    tr.print_state(state, "Wejście")

    result = tr.mix_columns(state)
    tr.print_state(result, "Wyjście (MixColumns)")
    tr.print_state(expected, "Oczekiwane")

    ok = result == expected
    print(f"\n  Wynik: {'✓ POPRAWNY' if ok else '✗ BŁĘDNY'}")

    # Sprawdzenie odwrotności
    restored = tr.inv_mix_columns(result)
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
        result = tr.gmul(a, b)
        ok = result == expected
        print(f"  gmul(0x{a:02X}, 0x{b:02X}) = 0x{result:02X}  "
              f"(oczekiwano 0x{expected:02X}) {'✓' if ok else '✗'}")

def main():
    test_gmul()
    test_shift_rows()
    test_mix_columns()
    print("\n" + "=" * 55)
    print("Wszystkie testy zakończone.")
    print("=" * 55)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    round_keys = tr.key_schedule(key)
    assert round_keys[1].hex() == "d6aa74fdd2af72fadaa678f1d6ab76fe"
    state = tr.bytes_to_state(bytes.fromhex("00112233445566778899aabbccddeeff"))
    tr.add_round_key(state, key)
    assert state == [
        [0x00, 0x40, 0x80, 0xC0],
        [0x10, 0x50, 0x90, 0xD0],
        [0x20, 0x60, 0xA0, 0xE0],
        [0x30, 0x70, 0xB0, 0xF0],
    ]
  
if __name__ == "__main__":
    main()
