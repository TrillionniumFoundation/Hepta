"""Bounded exact decimal-to-IEEE rounding for source floating expressions.

No intermediate binary64 rounding precedes f32 selection. Integer quotient and
remainder implement round-to-nearest, ties-to-even, including subnormal values.
This is literal conversion only, not an implementation of runtime arithmetic.
"""
from __future__ import annotations

import re
import struct

_DECIMAL = re.compile(r"([+-]?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?\Z")
_FORMATS = {"f32": (23, 127, -126, 127, -46, 38, ">I", ">f"),
            "f64": (52, 1023, -1022, 1023, -324, 308, ">Q", ">d")}


def round_source_float(text: str, target: str) -> float:
    """Return the finite destination value, exactly representable as Python float.

    Source lexing has already checked grammar and its 4096-character limit.
    Recheck these bounds because constructed ASTs can bypass that boundary.
    Overflow refuses; underflow preserves signed zero. Decimal exponents are
    screened before powers are constructed, so huge negative exponents are cheap.
    """
    if type(text) is not str or not 0 < len(text) <= 4096 or target not in _FORMATS:
        raise ValueError("malformed or oversized floating literal")
    match = _DECIMAL.fullmatch(text)
    if match is None:
        raise ValueError("malformed decimal floating literal")
    sign_text, integer, fraction, exponent_text = match.groups()
    fraction = fraction or ""
    digits = (integer + fraction).lstrip("0")
    precision, bias, minimum, maximum, tiny_decimal, huge_decimal, bits_fmt, value_fmt = _FORMATS[target]
    sign = int(sign_text == "-") << (31 if target == "f32" else 63)

    def value(bits: int) -> float:
        return struct.unpack(value_fmt, struct.pack(bits_fmt, sign | bits))[0]

    if not digits:
        return value(0)
    scale = int(exponent_text or "0") - len(fraction)
    adjusted = len(digits) + scale - 1
    if adjusted > huge_decimal:
        raise OverflowError(f"floating literal rounds to infinity in {target}")
    if adjusted < tiny_decimal:
        return value(0)
    numerator, denominator = int(digits), 1
    if scale >= 0:
        numerator *= 10 ** scale
    else:
        denominator = 10 ** -scale

    exponent = numerator.bit_length() - denominator.bit_length()
    if (numerator < denominator << exponent if exponent >= 0
            else numerator << -exponent < denominator):
        exponent -= 1
    # Subnormals use one fixed spacing; normals use p+1 significant bits.
    spacing = max(exponent, minimum) - precision
    dividend, divisor = (numerator, denominator << spacing) if spacing >= 0 else (
        numerator << -spacing, denominator)
    mantissa, remainder = divmod(dividend, divisor)
    mantissa += int(2 * remainder > divisor or 2 * remainder == divisor and mantissa & 1)
    if exponent < minimum:
        # Rounding the largest subnormal upward already encodes the minimum normal.
        return value(mantissa)
    if mantissa == 1 << (precision + 1):
        mantissa >>= 1
        exponent += 1
    if exponent > maximum:
        raise OverflowError(f"floating literal rounds to infinity in {target}")
    return value(((exponent + bias) << precision) | (mantissa - (1 << precision)))
