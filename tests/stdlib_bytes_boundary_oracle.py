"""Independently generated short-buffer and near-overflow codec cases.

Run from a checkout: python tests/stdlib_bytes_boundary_oracle.py
HEPTA_BYTES_BACKEND selects c (default) or rust. The common fixture supplies
locked-package compilation and native execution, not expected codec values.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from test_stdlib_bytes import BACKEND, ByteCodecTests


def corpus():
    lines, case = [], 0
    for bits in (16, 32, 64):
        width = bits // 8
        for order in ("le", "be"):
            byteorder = "little" if order == "le" else "big"
            for length in range(1, width + 2):
                for offset in (0, length - 1, (1 << 64) - width, (1 << 64) - width + 1):
                    data = bytes((i * 59 + 128) % 256 for i in range(length))
                    valid = offset + width <= length
                    expected = int.from_bytes(data[offset:offset + width], byteorder) if valid else 0
                    after = bytearray(data)
                    value = 1 << (bits - 1)
                    if valid:
                        after[offset:offset + width] = value.to_bytes(width, byteorder)
                    lines += [
                        f"let mut b{case}: [u8; {length}] = {ByteCodecTests.array(data)};",
                        f"let r{case} = codec::read_u{bits}_{order}(read b{case}, {offset});",
                        f"assert(r{case}.ok == {str(valid).lower()} && r{case}.value == {expected});",
                        f"assert(codec::write_u{bits}_{order}(mut b{case}, {offset}, {value}) == {str(valid).lower()});",
                    ]
                    lines += [f"assert(b{case}[{i}] == {byte});" for i, byte in enumerate(after)]
                    case += 1
    assert case == 136, case
    return "\n".join(lines), case


def main():
    fixture = ByteCodecTests()
    fixture.setUp()
    try:
        body, count = corpus()
        fixture.execute(body)
        print(f"PASS: {count} independent boundary cases, backend={BACKEND}, both optimization levels.")
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    main()
