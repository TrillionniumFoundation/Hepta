"""Independent decoder for the reviewed VEX/EVEX integer-kernel forms.

No encoder, producer bytes or disassembler output is consulted. Prefix bits,
operand roles, vector lengths, reserved fields and actual memory displacements
are decoded separately. EVEX disp8 is a signed *tuple-scaled* displacement.
Only unmasked full-vector accesses through RDI/RDX and low vector registers
are admitted. Instruction requirements are returned from the decoded form.

Semantics and encodings: Intel SDM Vol. 2B MOVDQU, PADDQ, POR, PSADBW,
PXOR, PSRLDQ; Vol. 2C VEXTRACTI128/VEXTRACTI64X4 and VZEROUPPER.
"""
from __future__ import annotations


class WideMachineRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise WideMachineRejected("unreviewed wide instruction: " + message)


def decode_wide_instruction(data, start):
    """Return (operation, operands, byte_length, required_cpu_features)."""
    p = start

    def take(n):
        nonlocal p
        _require(0 <= p <= len(data) and n <= len(data) - p, "truncated prefix or operand")
        result = data[p:p+n]
        p += n
        return result

    first = take(1)[0]
    _require(first in (0xc4, 0xc5, 0x62), "VEX/EVEX prefix required")
    evex = first == 0x62
    if first == 0xc5:
        prefix = take(1)[0]
        _require(prefix & 0x80, "extended vector register")
        opcode_map, w, high_b = 1, 0, 0
        encoded_v, length, pp = (prefix >> 3) & 15, (prefix >> 2) & 1, prefix & 3
        bits = 256 if length else 128
    elif first == 0xc4:
        p0, p1 = take(2)
        _require(p0 & 0xc0 == 0xc0, "extended vector/index register")
        opcode_map, w, high_b = p0 & 31, p1 >> 7, 0 if p0 & 0x20 else 8
        encoded_v, length, pp = (p1 >> 3) & 15, (p1 >> 2) & 1, p1 & 3
        bits = 256 if length else 128
    else:
        p0, p1, p2 = take(3)
        _require(p0 in (0xf1, 0xf3) and p1 & 4 and p2 == 0x48,
                 "EVEX register extension, reserved bit, length, mask, zeroing or broadcast")
        opcode_map, w, high_b = p0 & 3, p1 >> 7, 0
        encoded_v, bits, pp = (p1 >> 3) & 15, 512, p1 & 3
    source1 = (~encoded_v) & 15
    _require(source1 < 8, "extended VEX.vvvv source")
    opcode = take(1)[0]

    def result(op, args, features):
        return op, args, p-start, tuple(sorted(features))

    if opcode == 0x77:
        _require(first == 0xc5 and opcode_map == 1 and bits == 128 and pp == 0 and encoded_v == 15,
                 "only VZEROUPPER is admitted")
        return result('vzeroupper', (), ('avx',))

    modrm = take(1)[0]
    mode, register, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7

    def memory():
        _require(mode in (0, 1, 2) and high_b == 0 and rm in (2, 7),
                 "memory must use RDX/RDI without index or address override")
        displacement = (0 if mode == 0 else
                        int.from_bytes(take(1 if mode == 1 else 4), 'little', signed=True))
        if evex and mode == 1:
            # All admitted EVEX memory forms use Full Mem tuples, with no
            # broadcast. Their disp8 scale is the complete 64-byte vector.
            displacement *= 64
        return rm, displacement

    if opcode_map == 1 and opcode in (0x6f, 0x7f):
        _require(pp == 2 and encoded_v == 15 and
                 ((evex and w == 1) or (first == 0xc5 and bits == 256)),
                 "VMOVDQU/VMOVDQU64 prefix or reserved vvvv")
        base, displacement = memory()
        features = ('avx512f',) if evex else ('avx',)
        if opcode == 0x6f:
            return result('vload', (bits, register, base, displacement), features)
        return result('vstore', (bits, base, displacement, register), features)

    packed = {0xef: 'vpxor', 0xeb: 'vpor', 0xdb: 'vpand',
              0xf6: 'vpsadbw', 0xd4: 'vpaddq', 0xfb: 'vpsubq'}
    if opcode_map == 1 and opcode in packed:
        _require(pp == 1 and high_b == 0 and
                 ((evex and w == (0 if opcode == 0xf6 else 1)) or first == 0xc5),
                 "packed integer map, width selector or W field")
        features = (('avx512f', 'avx512bw') if opcode == 0xf6 else ('avx512f',)) if evex else (
            ('avx2',) if bits == 256 else ('avx',))
        if mode == 3:
            return result(packed[opcode], (bits, register, source1, rm), features)
        base, displacement = memory()
        return result(packed[opcode] + '_mem', (bits, register, source1, base, displacement), features)

    if opcode_map == 3 and opcode in (0x39, 0x3b):
        _require(mode == 3 and pp == 1 and encoded_v == 15 and high_b == 0,
                 "extract register operands or reserved vvvv")
        _require((first == 0xc4 and opcode == 0x39 and bits == 256 and w == 0) or
                 (evex and opcode == 0x3b and w == 1), "extract form or source width")
        index = take(1)[0]
        _require(index in (0, 1), "unreviewed extract immediate")
        return result('vextract', (bits, bits//2, rm, register, index),
                      ('avx512f',) if evex else ('avx2',))

    if opcode_map == 1 and opcode == 0x7e:
        _require(first == 0xc4 and bits == 128 and w == 1 and pp == 1 and
                 encoded_v == 15 and mode == 3, "VMOVQ must transfer XMM to a 64-bit GPR")
        return result('vmovq', (rm + high_b, register), ('avx',))

    if opcode_map == 1 and opcode == 0x73:
        _require(first == 0xc5 and bits == 128 and pp == 1 and mode == 3 and register == 3,
                 "VPSRLDQ must be a 128-bit immediate register shift")
        # This NDD form places the destination in VEX.vvvv, the source in
        # ModRM.r/m, and the opcode extension (/3) in ModRM.reg.
        return result('vpsrldq', (128, source1, rm, take(1)[0]), ('avx',))

    raise WideMachineRejected("unreviewed VEX/EVEX opcode or map")
