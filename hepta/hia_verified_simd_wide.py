"""Direct AVX2/AVX512 byte emission for the explicit verified SIMD targets.

This producer does not detect the running CPU or authorize execution.  Its
caller selects an ISA explicitly; the separate final-ELF consumer must decode
and validate the resulting image before the build/load compatibility gate can
admit it.  There is no assembler dependency or runtime dispatch in a kernel.
"""
from __future__ import annotations


_ACCUMULATORS = (0, 3, 4, 5)


def _prefix(width, opcode, source, *, move=False):
    """Low-register VEX/EVEX, with no masking, broadcast or rounding mode."""
    if width not in (16, 32, 64) or not 0 <= source < 8:
        raise ValueError("unsupported wide SIMD prefix")
    pp = 2 if move else 1  # F3 for MOVDQU[64]; 66 for packed arithmetic.
    inverted_source = ((~source) & 15) << 3
    if width == 64:
        # PSADBW is W0; PADDQ/PORQ/PXORQ/MOVDQU64 are W1.  All admitted
        # operands are low registers; L'L=10, V'=1, aaa=0, z=b=0.
        w = 0 if opcode == 0xf6 else 0x80
        return bytes((0x62, 0xf1, w | inverted_source | 4 | pp, 0x48))
    return bytes((0xc5, 0x80 | inverted_source | (4 if width == 32 else 0) | pp))


def _register(c, width, opcode, destination, source, operand):
    if opcode not in (0xd4, 0xeb, 0xef) or any(not 0 <= r < 8 for r in (destination, source, operand)):
        raise ValueError("unsupported wide SIMD register operation")
    c.emit(_prefix(width, opcode, source) + bytes((opcode, 0xc0 | (destination << 3) | operand)))


def _memory(c, width, opcode, vector, source, base, displacement=0):
    """Exactly one unaligned full-width access, at a declared chunk offset."""
    if (width not in (16, 32, 64) or opcode not in (0x6f, 0x7f, 0xeb, 0xf6)
            or base not in ("rdi", "rdx") or displacement not in (0, width, 2 * width, 3 * width)
            or not 0 <= vector < 8):
        raise ValueError("unsupported wide SIMD memory operation")
    move = opcode in (0x6f, 0x7f)
    if width == 16 and (not move or displacement != 0):
        raise ValueError("128-bit memory operations are restricted to endpoint copies")
    if move and source != 0:
        raise ValueError("MOVDQU reserved vvvv must be all ones")
    address = (vector << 3) | (7 if base == "rdi" else 2)
    if displacement == 0:
        modrm = bytes((address,))
    else:
        # EVEX Full Mem tuple disp8 is scaled by the 64-byte operand width;
        # VEX disp8 remains a signed byte displacement.  Every emitted
        # positive offset fits exactly, including the last 192-byte chunk.
        encoded_displacement = displacement // 64 if width == 64 else displacement
        modrm = bytes((address | 0x40, encoded_displacement))
    c.emit(_prefix(width, opcode, source, move=move) + bytes((opcode,)) + modrm)


def _combine(c, width, kind, accumulator, operand):
    _register(c, width, 0xd4 if kind == "sum_u8" else 0xeb,
              accumulator, accumulator, operand)


def _chunk(c, width, kind, displacement=0, accumulator=0):
    if kind == "sum_u8":
        # The memory operand and persistent zero vector form groups of eight
        # unsigned-byte sums; each becomes one zero-extended qword lane.
        _memory(c, width, 0xf6, 1, 2, "rdi", displacement)
        _combine(c, width, kind, accumulator, 1)
    else:
        # A folded memory operand avoids a separate load instruction and
        # retains the same one-read-per-chunk memory model.
        _memory(c, width, 0xeb, accumulator, accumulator, "rdi", displacement)


def _horizontal(c, width, kind):
    if width == 64:
        c.emit(bytes.fromhex("62f3fd483bc101"))  # vextracti64x4 ymm1,zmm0,1
        _combine(c, 32, kind, 0, 1)
    c.emit(bytes.fromhex("c4e37d39c101"))  # vextracti128 xmm1,ymm0,1
    _combine(c, 16, kind, 0, 1)
    c.emit(bytes.fromhex("c4e1f97ec0c5f973d808c4c1f97ec1"))
    # vmovq rax,xmm0; vpsrldq xmm0,xmm0,8; vmovq r9,xmm0
    (c.add if kind == "sum_u8" else c.or_)("rax", "r9")


def _reduce(c, width, kind):
    c.mov_imm("rax", 0)
    c.cmp("rdx", "rsi")
    c.jcc("a", "abort")
    c.test("rdx", "rdx")
    c.jcc("e", "done")
    c.test("rdi", "rdi")
    c.jcc("e", "abort")
    c.mov_rr("r9", "rdi")
    c.add("r9", "rdx")
    c.jcc("b", "abort")
    c.mov_rr("r10", "rdx")
    for register in (0, 2, 3, 4, 5):
        _register(c, width, 0xef, register, register, register)
    c.label("bulk")
    c.alu_imm("cmp", "r10", 4 * width)
    c.jcc("b", "bulk_merge")
    for chunk, accumulator in enumerate(_ACCUMULATORS):
        _chunk(c, width, kind, chunk * width, accumulator)
    c.alu_imm("add", "rdi", 4 * width)
    c.alu_imm("sub", "r10", 4 * width)
    c.jmp("bulk")
    c.label("bulk_merge")
    for accumulator in _ACCUMULATORS[1:]:
        _combine(c, width, kind, 0, accumulator)
    c.label("vector")
    c.alu_imm("cmp", "r10", width)
    c.jcc("b", "horizontal")
    _chunk(c, width, kind)
    c.alu_imm("add", "rdi", width)
    c.alu_imm("sub", "r10", width)
    c.jmp("vector")
    c.label("horizontal")
    _horizontal(c, width, kind)
    c.emit(bytes.fromhex("c5f877"))  # vzeroupper before the scalar byte tail
    c.label("tail")
    c.test("r10", "r10")
    c.jcc("e", "done")
    c.load_u8("r9", "rdi")
    (c.add if kind == "sum_u8" else c.or_)("rax", "r9")
    c.alu_imm("add", "rdi", 1)
    c.alu_imm("sub", "r10", 1)
    c.jmp("tail")
    c.label("done")
    if kind == "all_zero_u8":
        c.test("rax", "rax")
        c.setcc("e", "rax")
    c.ret()


def _copy_byte_tail(c, width):
    """Historical exact-byte control, including interleaved bulk transfers."""
    c.mov_rr("rax", "r8")
    c.cmp("r8", "rsi")
    c.jcc("a", "abort")
    c.cmp("r8", "rcx")
    c.jcc("a", "abort")
    c.test("r8", "r8")
    c.jcc("e", "done")
    for pointer, end in (("rdi", "r9"), ("rdx", "r10")):
        c.test(pointer, pointer)
        c.jcc("e", "abort")
        c.mov_rr(end, pointer)
        c.add(end, "r8")
        c.jcc("b", "abort")
    c.cmp("r9", "rdx")
    c.jcc("be", "admitted")
    c.cmp("r10", "rdi")
    c.jcc("a", "abort")
    c.label("admitted")
    c.mov_rr("r10", "r8")
    c.label("bulk")
    c.alu_imm("cmp", "r10", 4 * width)
    c.jcc("b", "vector")
    for chunk in range(4):
        _memory(c, width, 0x6f, 1, 0, "rdx", chunk * width)
        _memory(c, width, 0x7f, 1, 0, "rdi", chunk * width)
    c.alu_imm("add", "rdi", 4 * width)
    c.alu_imm("add", "rdx", 4 * width)
    c.alu_imm("sub", "r10", 4 * width)
    c.jmp("bulk")
    c.label("vector")
    c.alu_imm("cmp", "r10", width)
    c.jcc("b", "vector_done")
    _memory(c, width, 0x6f, 1, 0, "rdx")
    _memory(c, width, 0x7f, 1, 0, "rdi")
    c.alu_imm("add", "rdi", width)
    c.alu_imm("add", "rdx", width)
    c.alu_imm("sub", "r10", width)
    c.jmp("vector")
    c.label("vector_done")
    c.emit(bytes.fromhex("c5f877"))
    c.label("tail")
    c.test("r10", "r10")
    c.jcc("e", "done")
    c.load_u8("r9", "rdx")
    c.store_u8("rdi", 0, "r9")
    c.alu_imm("add", "rdi", 1)
    c.alu_imm("add", "rdx", 1)
    c.alu_imm("sub", "r10", 1)
    c.jmp("tail")
    c.label("done")
    c.ret()


def _copy_word(c, width, register, *, store=False):
    """One exact 1/2/4/8-byte unaligned transfer using r9 or r11, mod=0."""
    if width not in (1, 2, 4, 8) or register not in (9, 11):
        raise ValueError("unsupported endpoint integer transfer")
    modrm = ((register & 7) << 3) | (7 if store else 2)
    if store:
        prefix = bytes.fromhex("6644") if width == 2 else bytes((0x4c if width == 8 else 0x44,))
        opcode = bytes((0x88 if width == 1 else 0x89,))
    else:
        prefix = bytes((0x44 if width == 4 else 0x4c,))
        opcode = bytes((0x8b,)) if width in (4, 8) else bytes((0x0f, 0xb6 if width == 1 else 0xb7))
    c.emit(prefix + opcode + bytes((modrm,)))


def _copy_endpoints(c, width):
    """Guarded wide loops followed by two bounded endpoint transfers.

    For a suffix with w <= remaining < 2w, the first and last w-byte blocks
    cover exactly that suffix. Their stores may overlap; each repeated byte
    receives the same source byte, and the admitted source/destination ranges
    are disjoint. Both source blocks are read before either destination write.
    """
    c.mov_rr("rax", "r8")
    c.cmp("r8", "rsi")
    c.jcc("a", "abort")
    c.cmp("r8", "rcx")
    c.jcc("a", "abort")
    c.test("r8", "r8")
    c.jcc("e", "done")
    for pointer, end in (("rdi", "r9"), ("rdx", "r10")):
        c.test(pointer, pointer)
        c.jcc("e", "abort")
        c.mov_rr(end, pointer)
        c.add(end, "r8")
        c.jcc("b", "abort")
    c.cmp("r9", "rdx")
    c.jcc("be", "admitted")
    c.cmp("r10", "rdi")
    c.jcc("a", "abort")
    c.label("admitted")
    c.mov_rr("r10", "r8")
    c.label("bulk")
    c.alu_imm("cmp", "r10", 4 * width)
    c.jcc("b", "vector")
    for chunk in range(4):
        _memory(c, width, 0x6f, 1 + chunk, 0, "rdx", chunk * width)
    for chunk in range(4):
        _memory(c, width, 0x7f, 1 + chunk, 0, "rdi", chunk * width)
    c.alu_imm("add", "rdi", 4 * width)
    c.alu_imm("add", "rdx", 4 * width)
    c.alu_imm("sub", "r10", 4 * width)
    c.jmp("bulk")
    c.label("vector")
    c.alu_imm("cmp", "r10", width)
    c.jcc("b", "tail_dispatch")
    _memory(c, width, 0x6f, 1, 0, "rdx")
    _memory(c, width, 0x7f, 1, 0, "rdi")
    c.alu_imm("add", "rdi", width)
    c.alu_imm("add", "rdx", width)
    c.alu_imm("sub", "r10", width)
    c.jmp("vector")
    c.label("tail_dispatch")
    c.test("r10", "r10")
    c.jcc("e", "vector_done")
    for block in (32, 16, 8, 4, 2):
        if block >= width:
            continue
        c.label("tail_" + str(block))
        c.alu_imm("cmp", "r10", block)
        c.jcc("b", "tail_" + str(block // 2))
        if block >= 16:
            _memory(c, block, 0x6f, 1, 0, "rdx")
        else:
            _copy_word(c, block, 9)
        c.alu_imm("sub", "r10", block)
        c.add("rdx", "r10")
        if block >= 16:
            _memory(c, block, 0x6f, 2, 0, "rdx")
            _memory(c, block, 0x7f, 1, 0, "rdi")
        else:
            _copy_word(c, block, 11)
            _copy_word(c, block, 9, store=True)
        c.add("rdi", "r10")
        if block >= 16:
            _memory(c, block, 0x7f, 2, 0, "rdi")
        else:
            _copy_word(c, block, 11, store=True)
        c.jmp("vector_done")
    c.label("tail_1")
    _copy_word(c, 1, 9)
    _copy_word(c, 1, 9, store=True)
    c.label("vector_done")
    c.emit(bytes.fromhex("c5f877"))
    c.label("done")
    c.ret()


def emit_wide_simd(c, kind, isa, *, copy_tail="endpoints"):
    """Append the complete closed four-chunk CFG, including its abort suffix."""
    if isa not in ("avx2", "avx512") or kind not in ("sum_u8", "all_zero_u8", "copy_u8"):
        raise ValueError("unsupported explicit wide SIMD target")
    width = 32 if isa == "avx2" else 64
    if kind == "copy_u8":
        if copy_tail not in ("byte", "endpoints"):
            raise ValueError("unsupported wide copy tail strategy")
        (_copy_byte_tail if copy_tail == "byte" else _copy_endpoints)(c, width)
    else:
        _reduce(c, width, kind)
    c.label("abort")
    c.alu_imm("sub", "rsp", 8)
    c.call("abort")
    c.ud2()
