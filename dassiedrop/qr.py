from __future__ import annotations


ALIGNMENT_CENTERS = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
}

DATA_CODEWORDS_L = {
    1: 19,
    2: 34,
    3: 55,
    4: 80,
    5: 108,
    6: 136,
    7: 156,
    8: 194,
    9: 232,
}

TOTAL_CODEWORDS = {
    1: 26,
    2: 44,
    3: 70,
    4: 100,
    5: 134,
    6: 172,
    7: 196,
    8: 242,
    9: 292,
}

BLOCKS_L = {
    1: [19],
    2: [34],
    3: [55],
    4: [80],
    5: [108],
    6: [68, 68],
    7: [78, 78],
    8: [97, 97],
    9: [116, 116],
}


def _gf_mul(left: int, right: int) -> int:
    result = 0
    while right:
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x100:
            left ^= 0x11D
        right >>= 1
    return result


def _gf_pow(value: int, power: int) -> int:
    result = 1
    for _ in range(power):
        result = _gf_mul(result, value)
    return result


def _poly_mul(left: list[int], right: list[int]) -> list[int]:
    result = [0] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            result[left_index + right_index] ^= _gf_mul(left_value, right_value)
    return result


def _rs_generator(degree: int) -> list[int]:
    generator = [1]
    for index in range(degree):
        generator = _poly_mul(generator, [1, _gf_pow(2, index)])
    return generator


def _rs_remainder(data: list[int], degree: int) -> list[int]:
    generator = _rs_generator(degree)
    remainder = data[:] + [0] * degree
    for index in range(len(data)):
        coefficient = remainder[index]
        if coefficient == 0:
            continue
        for gen_index, gen_value in enumerate(generator):
            remainder[index + gen_index] ^= _gf_mul(gen_value, coefficient)
    return remainder[-degree:]


def _append_bits(bits: list[int], value: int, count: int) -> None:
    for shift in range(count - 1, -1, -1):
        bits.append((value >> shift) & 1)


def _data_codewords(payload: bytes, version: int) -> list[int]:
    capacity = DATA_CODEWORDS_L[version]
    bits: list[int] = []
    _append_bits(bits, 0b0100, 4)
    _append_bits(bits, len(payload), 8)
    for byte in payload:
        _append_bits(bits, byte, 8)
    max_bits = capacity * 8
    _append_bits(bits, 0, min(4, max_bits - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    codewords = [
        int("".join(str(bit) for bit in bits[index : index + 8]), 2)
        for index in range(0, len(bits), 8)
    ]
    pad = 0
    while len(codewords) < capacity:
        codewords.append(0xEC if pad % 2 == 0 else 0x11)
        pad += 1
    return codewords


def _interleaved_codewords(data: list[int], version: int) -> list[int]:
    block_sizes = BLOCKS_L[version]
    ecc_degree = (TOTAL_CODEWORDS[version] - DATA_CODEWORDS_L[version]) // len(block_sizes)
    data_blocks = []
    ecc_blocks = []
    offset = 0
    for block_size in block_sizes:
        block = data[offset : offset + block_size]
        offset += block_size
        data_blocks.append(block)
        ecc_blocks.append(_rs_remainder(block, ecc_degree))
    result = []
    for index in range(max(len(block) for block in data_blocks)):
        for block in data_blocks:
            if index < len(block):
                result.append(block[index])
    for index in range(ecc_degree):
        for block in ecc_blocks:
            result.append(block[index])
    return result


def _set(matrix: list[list[bool | None]], reserved: list[list[bool]], row: int, col: int, value: bool) -> None:
    matrix[row][col] = value
    reserved[row][col] = True


def _finder(matrix: list[list[bool | None]], reserved: list[list[bool]], row: int, col: int) -> None:
    size = len(matrix)
    for rr in range(row - 1, row + 8):
        for cc in range(col - 1, col + 8):
            if 0 <= rr < size and 0 <= cc < size:
                _set(matrix, reserved, rr, cc, False)
    for rr in range(7):
        for cc in range(7):
            dark = rr in {0, 6} or cc in {0, 6} or (2 <= rr <= 4 and 2 <= cc <= 4)
            _set(matrix, reserved, row + rr, col + cc, dark)


def _alignment(matrix: list[list[bool | None]], reserved: list[list[bool]], center_row: int, center_col: int) -> None:
    for rr in range(-2, 3):
        for cc in range(-2, 3):
            dark = max(abs(rr), abs(cc)) in {0, 2}
            _set(matrix, reserved, center_row + rr, center_col + cc, dark)


def _format_bits(mask: int) -> int:
    value = (0b01 << 3) | mask
    data = value << 10
    generator = 0x537
    for shift in range(14, 9, -1):
        if (data >> shift) & 1:
            data ^= generator << (shift - 10)
    return ((value << 10) | data) ^ 0x5412


def _place_format(matrix: list[list[bool | None]], reserved: list[list[bool]], mask: int) -> None:
    size = len(matrix)
    bits = _format_bits(mask)
    first = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ]
    second = (
        [(size - 1 - index, 8) for index in range(7)]
        + [(8, size - 8 + index) for index in range(8)]
    )
    for index, (row, col) in enumerate(first):
        _set(matrix, reserved, row, col, bool((bits >> (14 - index)) & 1))
    for index, (row, col) in enumerate(second):
        _set(matrix, reserved, row, col, bool((bits >> (14 - index)) & 1))


def _base_matrix(version: int) -> tuple[list[list[bool | None]], list[list[bool]]]:
    size = 21 + 4 * (version - 1)
    matrix: list[list[bool | None]] = [[None for _ in range(size)] for _ in range(size)]
    reserved = [[False for _ in range(size)] for _ in range(size)]
    _finder(matrix, reserved, 0, 0)
    _finder(matrix, reserved, 0, size - 7)
    _finder(matrix, reserved, size - 7, 0)
    for index in range(8, size - 8):
        _set(matrix, reserved, 6, index, index % 2 == 0)
        _set(matrix, reserved, index, 6, index % 2 == 0)
    for row in ALIGNMENT_CENTERS[version]:
        for col in ALIGNMENT_CENTERS[version]:
            if reserved[row][col]:
                continue
            _alignment(matrix, reserved, row, col)
    _set(matrix, reserved, 4 * version + 9, 8, True)
    _place_format(matrix, reserved, 0)
    return matrix, reserved


def _place_data(matrix: list[list[bool | None]], reserved: list[list[bool]], codewords: list[int]) -> None:
    bits: list[int] = []
    for codeword in codewords:
        _append_bits(bits, codeword, 8)
    size = len(matrix)
    bit_index = 0
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for current_col in (col, col - 1):
                if reserved[row][current_col]:
                    continue
                bit = bits[bit_index] if bit_index < len(bits) else 0
                if (row + current_col) % 2 == 0:
                    bit ^= 1
                matrix[row][current_col] = bool(bit)
                bit_index += 1
        upward = not upward
        col -= 2


def _choose_version(text: str) -> int:
    payload_len = len(text.encode("utf-8"))
    for version, capacity in DATA_CODEWORDS_L.items():
        if payload_len + 2 <= capacity:
            return version
    raise ValueError("QR payload is too large")


def qr_svg(text: str, scale: int = 4, border: int = 4) -> str:
    version = _choose_version(text)
    data = _data_codewords(text.encode("utf-8"), version)
    codewords = _interleaved_codewords(data, version)
    matrix, reserved = _base_matrix(version)
    _place_data(matrix, reserved, codewords)
    size = len(matrix)
    view_size = size + 2 * border
    rects = []
    for row, cells in enumerate(matrix):
        for col, value in enumerate(cells):
            if value:
                rects.append(f'<rect x="{col + border}" y="{row + border}" width="1" height="1"/>')
    rect_text = "".join(rects)
    pixel_size = view_size * scale
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{pixel_size}" height="{pixel_size}" '
        f'viewBox="0 0 {view_size} {view_size}" role="img" aria-label="Authenticator QR code">'
        f'<rect width="100%" height="100%" fill="#fff"/>'
        f'<g fill="#000">{rect_text}</g>'
        f"</svg>"
    )
