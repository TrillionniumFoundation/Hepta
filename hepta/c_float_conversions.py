"""Generate integer-only IEEE numeric conversion helpers for the C backend.

No floating arithmetic or hardware conversion is used in these helpers. The
qualified IEEE object representation is copied through memcpy, without aliasing.
"""

COMMON = r'''
#if !defined(__STDC_IEC_559__) || defined(__FAST_MATH__) || !defined(__BYTE_ORDER__) || !defined(__FLOAT_WORD_ORDER__) || __BYTE_ORDER__ != __FLOAT_WORD_ORDER__
#error "Numeric float casts require IEC 60559 and matching integer/float byte order, without fast-math"
#endif
_Static_assert(FLT_RADIX == 2 && FLT_MANT_DIG == 24 && DBL_MANT_DIG == 53
    && FLT_MAX_EXP == 128 && DBL_MAX_EXP == 1024 && FLT_MIN_EXP == -125 && DBL_MIN_EXP == -1021
    && FLT_HAS_SUBNORM == 1 && DBL_HAS_SUBNORM == 1 && sizeof(float) == 4 && sizeof(double) == 8,
    "Numeric float casts require binary32/binary64 with subnormals");
static inline uint64_t __hepta_cb_round_shift(uint64_t value, unsigned shift) {
    if (!shift) return value;
    if (shift > 64) return 0;
    if (shift == 64) return value > (UINT64_C(1) << 63);
    uint64_t quotient = value >> shift;
    uint64_t remainder = value & ((UINT64_C(1) << shift) - 1);
    uint64_t half = UINT64_C(1) << (shift - 1);
    return quotient + (remainder > half || (remainder == half && (quotient & 1)));
}
/* Encode the exact dyadic value (-1)^negative * significand * 2^power. */
static inline uint64_t __hepta_cb_encode_float(bool negative, uint64_t significand,
                                               int power, unsigned width) {
    unsigned fraction = width == 32 ? 23 : 52;
    int bias = width == 32 ? 127 : 1023;
    uint64_t sign = (uint64_t)negative << (width - 1);
    uint64_t infinity = sign | ((uint64_t)(2 * bias + 1) << fraction);
    if (!significand) return sign;
    unsigned leading = 0;
    for (uint64_t rest = significand; rest >>= 1;) ++leading;
    int exponent = (int)leading + power;
    if (exponent > bias) return infinity;
    if (exponent < 1 - bias) exponent = 1 - bias;
    int shift = exponent - (int)fraction - power;
    uint64_t rounded = shift > 0 ? __hepta_cb_round_shift(significand, (unsigned)shift)
                                : significand << (unsigned)(-shift);
    if (rounded >= (UINT64_C(1) << (fraction + 1))) { rounded >>= 1; ++exponent; }
    if (exponent > bias) return infinity;
    if (rounded < (UINT64_C(1) << fraction)) return sign | rounded;
    return sign | ((uint64_t)(exponent + bias) << fraction)
                | (rounded & ((UINT64_C(1) << fraction) - 1));
}
'''


def helpers(pairs, scalars):
    if not pairs:
        return ''
    lines = [COMMON]
    for source, target in sorted(pairs):
        width = int(target[1:])
        lines.append(f'static inline {scalars[target]} __hepta_cb_{source}_to_{target}({scalars[source]} x) {{')
        if source in ('f32', 'f64'):
            sw = int(source[1:])
            fraction, bias = (23, 127) if sw == 32 else (52, 1023)
            tf, tb = (23, 127) if width == 32 else (52, 1023)
            lines += [f'uint{sw}_t raw; memcpy(&raw, &x, sizeof raw);',
                      f'bool negative = (raw >> {sw - 1}) != 0;',
                      f'unsigned exponent = (unsigned)((raw >> {fraction}) & {2 * bias + 1});',
                      f'uint64_t significand = raw & ((UINT64_C(1) << {fraction}) - 1);',
                      'uint64_t encoded;',
                      f'if (exponent == {2 * bias + 1}) {{',
                      f'encoded = ((uint64_t)negative << {width - 1}) | (UINT64_C({2 * tb + 1}) << {tf});',
                      # NaN payloads are unspecified by the language. Emit a
                      # signed quiet NaN without evaluating a signaling input.
                      f'if (significand) encoded |= UINT64_C(1) << {tf - 1};',
                      '} else {',
                      f'if (exponent) significand |= UINT64_C(1) << {fraction};',
                      f'encoded = __hepta_cb_encode_float(negative, significand, (int)(exponent ? exponent : 1) - {bias + fraction}, {width});',
                      '}']
        else:
            negative = 'x < 0' if source.startswith('i') else 'false'
            lines += [f'bool negative = {negative};',
                      'uint64_t magnitude = negative ? UINT64_C(0) - (uint64_t)x : (uint64_t)x;',
                      f'uint64_t encoded = __hepta_cb_encode_float(negative, magnitude, 0, {width});']
        lines += [f'uint{width}_t bits = (uint{width}_t)encoded; {scalars[target]} result;',
                  'memcpy(&result, &bits, sizeof result); return result; }']
    return '\n'.join(lines)
