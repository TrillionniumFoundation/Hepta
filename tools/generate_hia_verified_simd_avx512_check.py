"""Author the native verifier for the canonical AVX-512 byte kernels.

The HIA consumer checks the final exported text from the ELF binder. Its
closed instruction vocabulary identifies exact operations, widths, registers,
addressing modes and displacements. Branch operands are derived from the
semantic labels below. Only the external abort relocation is image-specific.
"""
import struct
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import SOURCE as ELF
from tools.generate_hia_shared_linker import document

MODULE = 'verified_simd_avx512_check'

# The finite vocabulary is independent of the object producer. These are
# complete single instructions, including canonical EVEX/VEX operand bits.
VOCABULARY = {
    ('add', 0, 9): '4c01c8',
    ('add', 10, 8): '4d01c2',
    ('add', 2, 10): '4c01d2',
    ('add', 7, 10): '4c01d7',
    ('add', 9, 2): '4901d1',
    ('add', 9, 8): '4d01c1',
    ('alu_imm', 'add', 2, 256): '4881c200010000',
    ('alu_imm', 'add', 2, 64): '4883c240',
    ('alu_imm', 'add', 7, 16): '4883c710',
    ('alu_imm', 'add', 7, 2): '4883c702',
    ('alu_imm', 'add', 7, 256): '4881c700010000',
    ('alu_imm', 'add', 7, 4): '4883c704',
    ('alu_imm', 'add', 7, 64): '4883c740',
    ('alu_imm', 'add', 7, 8): '4883c708',
    ('alu_imm', 'cmp', 10, 1): '4983fa01',
    ('alu_imm', 'cmp', 10, 16): '4983fa10',
    ('alu_imm', 'cmp', 10, 2): '4983fa02',
    ('alu_imm', 'cmp', 10, 256): '4981fa00010000',
    ('alu_imm', 'cmp', 10, 32): '4983fa20',
    ('alu_imm', 'cmp', 10, 4): '4983fa04',
    ('alu_imm', 'cmp', 10, 64): '4983fa40',
    ('alu_imm', 'cmp', 10, 8): '4983fa08',
    ('alu_imm', 'sub', 10, 16): '4983ea10',
    ('alu_imm', 'sub', 10, 2): '4983ea02',
    ('alu_imm', 'sub', 10, 256): '4981ea00010000',
    ('alu_imm', 'sub', 10, 32): '4983ea20',
    ('alu_imm', 'sub', 10, 4): '4983ea04',
    ('alu_imm', 'sub', 10, 64): '4983ea40',
    ('alu_imm', 'sub', 10, 8): '4983ea08',
    ('alu_imm', 'sub', 4, 8): '4883ec08',
    ('cmp', 10, 7): '4939fa',
    ('cmp', 2, 6): '4839f2',
    ('cmp', 8, 1): '4939c8',
    ('cmp', 8, 6): '4939f0',
    ('cmp', 9, 2): '4939d1',
    ('copy_load', 16, 11, 2, 0): '4c0fb71a',
    ('copy_load', 16, 9, 2, 0): '4c0fb70a',
    ('copy_load', 16, 9, 7, 0): '4c0fb70f',
    ('copy_load', 32, 11, 2, 0): '448b1a',
    ('copy_load', 32, 9, 2, 0): '448b0a',
    ('copy_load', 32, 9, 7, 0): '448b0f',
    ('copy_load', 64, 11, 2, 0): '4c8b1a',
    ('copy_load', 64, 9, 2, 0): '4c8b0a',
    ('copy_load', 64, 9, 7, 0): '4c8b0f',
    ('copy_load', 8, 9, 2, 0): '4c0fb60a',
    ('copy_load', 8, 9, 7, 0): '4c0fb60f',
    ('copy_store', 16, 7, 0, 11): '6644891f',
    ('copy_store', 16, 7, 0, 9): '6644890f',
    ('copy_store', 32, 7, 0, 11): '44891f',
    ('copy_store', 32, 7, 0, 9): '44890f',
    ('copy_store', 64, 7, 0, 11): '4c891f',
    ('copy_store', 64, 7, 0, 9): '4c890f',
    ('copy_store', 8, 7, 0, 9): '44880f',
    ('imm', 0, 0): 'b800000000',
    ('mov', 0, 8): '4c89c0',
    ('mov', 10, 2): '4989d2',
    ('mov', 10, 8): '4d89c2',
    ('mov', 9, 7): '4989f9',
    ('or', 0, 9): '4c09c8',
    ('ret',): 'c3',
    ('sete', 0): '400f94c0',
    ('test', 0, 0): '4885c0',
    ('test', 10, 10): '4d85d2',
    ('test', 2, 2): '4885d2',
    ('test', 7, 7): '4885ff',
    ('test', 8, 8): '4d85c0',
    ('ud2',): '0f0b',
    ('vextract', 256, 128, 1, 0, 1): 'c4e37d39c101',
    ('vextract', 512, 256, 1, 0, 1): '62f3fd483bc101',
    ('vgpr_to_xmm', 1, 9): 'c4c1f96ec9',
    ('vload', 128, 1, 2, 0): 'c5fa6f0a',
    ('vload', 128, 2, 2, 0): 'c5fa6f12',
    ('vload', 256, 1, 2, 0): 'c5fe6f0a',
    ('vload', 256, 2, 2, 0): 'c5fe6f12',
    ('vload', 512, 1, 2, 0): '62f1fe486f0a',
    ('vload', 512, 2, 2, 64): '62f1fe486f5201',
    ('vload', 512, 3, 2, 128): '62f1fe486f5a02',
    ('vload', 512, 4, 2, 192): '62f1fe486f6203',
    ('vmovq', 0, 0): 'c4e1f97ec0',
    ('vmovq', 9, 0): 'c4c1f97ec1',
    ('vmovq', 9, 1): 'c4c1f97ec9',
    ('vpaddq', 128, 0, 0, 1): 'c5f9d4c1',
    ('vpaddq', 256, 0, 0, 1): 'c5fdd4c1',
    ('vpaddq', 512, 0, 0, 1): '62f1fd48d4c1',
    ('vpaddq', 512, 0, 0, 3): '62f1fd48d4c3',
    ('vpaddq', 512, 0, 0, 4): '62f1fd48d4c4',
    ('vpaddq', 512, 0, 0, 5): '62f1fd48d4c5',
    ('vpaddq', 512, 3, 3, 1): '62f1e548d4d9',
    ('vpaddq', 512, 4, 4, 1): '62f1dd48d4e1',
    ('vpaddq', 512, 5, 5, 1): '62f1d548d4e9',
    ('vpor', 128, 0, 0, 1): 'c5f9ebc1',
    ('vpor', 256, 0, 0, 1): 'c5fdebc1',
    ('vpor', 512, 0, 0, 3): '62f1fd48ebc3',
    ('vpor', 512, 0, 0, 4): '62f1fd48ebc4',
    ('vpor', 512, 0, 0, 5): '62f1fd48ebc5',
    ('vpor_mem', 128, 0, 0, 7, 0): 'c5f9eb07',
    ('vpor_mem', 512, 0, 0, 7, 0): '62f1fd48eb07',
    ('vpor_mem', 512, 3, 3, 7, 64): '62f1e548eb5f01',
    ('vpor_mem', 512, 4, 4, 7, 128): '62f1dd48eb6702',
    ('vpor_mem', 512, 5, 5, 7, 192): '62f1d548eb6f03',
    ('vpsadbw', 128, 1, 2, 1): 'c5e9f6c9',
    ('vpsadbw_mem', 128, 1, 2, 7, 0): 'c5e9f60f',
    ('vpsadbw_mem', 512, 1, 2, 7, 0): '62f16d48f60f',
    ('vpsadbw_mem', 512, 1, 2, 7, 128): '62f16d48f64f02',
    ('vpsadbw_mem', 512, 1, 2, 7, 192): '62f16d48f64f03',
    ('vpsadbw_mem', 512, 1, 2, 7, 64): '62f16d48f64f01',
    ('vpsrldq', 128, 0, 0, 8): 'c5f973d808',
    ('vpxor', 128, 0, 0, 0): 'c5f9efc0',
    ('vpxor', 128, 2, 2, 2): 'c5e9efd2',
    ('vpxor', 512, 0, 0, 0): '62f1fd48efc0',
    ('vpxor', 512, 2, 2, 2): '62f1ed48efd2',
    ('vpxor', 512, 3, 3, 3): '62f1e548efdb',
    ('vpxor', 512, 4, 4, 4): '62f1dd48efe4',
    ('vpxor', 512, 5, 5, 5): '62f1d548efed',
    ('vstore', 128, 7, 0, 1): 'c5fa7f0f',
    ('vstore', 128, 7, 0, 2): 'c5fa7f17',
    ('vstore', 256, 7, 0, 1): 'c5fe7f0f',
    ('vstore', 256, 7, 0, 2): 'c5fe7f17',
    ('vstore', 512, 7, 0, 1): '62f1fe487f0f',
    ('vstore', 512, 7, 128, 3): '62f1fe487f5f02',
    ('vstore', 512, 7, 192, 4): '62f1fe487f6703',
    ('vstore', 512, 7, 64, 2): '62f1fe487f5701',
    ('vzeroupper',): 'c5f877',
}


def grammar(kind):
    rows = []
    def take(op, *args):
        rows.append((op, *args))
    def label(name):
        take('label', name)
    def below(count, target):
        take('alu_imm', 'cmp', 10, count)
        take('jcc', 2, target)
    def advance(count):
        take('alu_imm', 'add', 7, count)
        if copy:
            take('alu_imm', 'add', 2, count)
        take('alu_imm', 'sub', 10, count)
    def reduce(width, distance, acc):
        if summing:
            take('vpsadbw_mem', width, 1, 2, 7, distance)
            take('vpaddq', width, acc, acc, 1)
        else:
            take('vpor_mem', width, acc, acc, 7, distance)
    def copy_memory(load, width, reg):
        if width >= 128:
            if load:
                take('vload', width, reg, 2, 0)
            else:
                take('vstore', width, 7, 0, reg)
        elif load:
            take('copy_load', width, reg, 2, 0)
        else:
            take('copy_store', width, 7, 0, reg)

    copy = kind == 3
    summing = kind == 1
    combine = 'vpaddq' if summing else 'vpor'
    merge = 'add' if summing else 'or'
    if copy:
        take('mov', 0, 8)
        for bound in (6, 1):
            take('cmp', 8, bound)
            take('jcc', 7, 'abort')
        take('test', 8, 8)
        take('jcc', 4, 'return')
        for pointer, end in ((7, 9), (2, 10)):
            take('test', pointer, pointer)
            take('jcc', 4, 'abort')
            take('mov', end, pointer)
            take('add', end, 8)
            take('jcc', 2, 'abort')
        take('cmp', 9, 2)
        take('jcc', 6, 'admitted')
        take('cmp', 10, 7)
        take('jcc', 7, 'abort')
        label('admitted')
        take('mov', 10, 8)
    else:
        take('imm', 0, 0)
        take('cmp', 2, 6)
        take('jcc', 7, 'abort')
        take('test', 2, 2)
        take('jcc', 4, 'return')
        take('test', 7, 7)
        take('jcc', 4, 'abort')
        take('mov', 9, 7)
        take('add', 9, 2)
        take('jcc', 2, 'abort')
        take('mov', 10, 2)
        below(64, 'short_init')
        for acc in (0, 2, 3, 4, 5):
            take('vpxor', 512, acc, acc, acc)

    label('bulk')
    below(256, 'vector' if copy else 'merge')
    if copy:
        for n in range(4):
            take('vload', 512, n+1, 2, n*64)
        for n in range(4):
            take('vstore', 512, 7, n*64, n+1)
    else:
        for n, acc in enumerate((0, 3, 4, 5)):
            reduce(512, n*64, acc)
    advance(256)
    take('jmp', 'bulk')
    if not copy:
        label('merge')
        for acc in (3, 4, 5):
            take(combine, 512, 0, 0, acc)

    label('vector')
    below(64, 'tail' if copy else 'horizontal')
    if copy:
        copy_memory(True, 512, 1)
        copy_memory(False, 512, 1)
    else:
        reduce(512, 0, 0)
    advance(64)
    take('jmp', 'vector')
    if copy:
        # With width <= n < 2*width the first and last loads cover [0,n).
        # Read both endpoints before writing either destination.
        label('tail')
        take('test', 10, 10)
        take('jcc', 4, 'cleanup')
        take('alu_imm', 'cmp', 10, 1)
        take('jcc', 4, 'byte')
        for size in (32, 16, 8, 4, 2):
            label(size)
            below(size, size//2 if size>2 else 'byte')
            first, last = (1, 2) if size>=16 else (9, 11)
            copy_memory(True, size*8, first)
            take('alu_imm', 'sub', 10, size)
            take('add', 2, 10)
            copy_memory(True, size*8, last)
            copy_memory(False, size*8, first)
            take('add', 7, 10)
            copy_memory(False, size*8, last)
            take('jmp', 'cleanup')
        label('byte')
        copy_memory(True, 8, 9)
        copy_memory(False, 8, 9)
    else:
        label('horizontal')
        for wide, narrow in ((512, 256), (256, 128)):
            take('vextract', wide, narrow, 1, 0, 1)
            take(combine, narrow, 0, 0, 1)
        take('jmp', 'narrow')
        label('short_init')
        for acc in (0, 2):
            take('vpxor', 128, acc, acc, acc)
        label('narrow')
        below(16, 'fold')
        reduce(128, 0, 0)
        advance(16)
        take('jmp', 'narrow')
        label('fold')
        take('vmovq', 0, 0)
        take('vpsrldq', 128, 0, 0, 8)
        take('vmovq', 9, 0)
        take(merge, 0, 9)
        for size in (8, 4, 2):
            label(size)
            below(size, size//2 if size>2 else 'byte')
            take('copy_load', size*8, 9, 7, 0)
            if summing:
                take('vgpr_to_xmm', 1, 9)
                take('vpsadbw', 128, 1, 2, 1)
                take('vmovq', 9, 1)
            take(merge, 0, 9)
            advance(size)
        label('byte')
        take('test', 10, 10)
        take('jcc', 4, 'cleanup')
        take('copy_load', 8, 9, 7, 0)
        take(merge, 0, 9)
    label('cleanup')
    take('vzeroupper')
    label('return')
    if kind == 2:
        take('test', 0, 0)
        take('imm', 0, 0)
        take('sete', 0)
    take('ret')
    label('abort')
    take('alu_imm', 'sub', 4, 8)
    take('call')
    take('ud2')
    return rows

def instructions(kind):
    """Resolve branch labels independently of the code offsets in the image."""
    rows = grammar(kind)
    offsets = {}
    size = 0
    for row in rows:
        op = row[0]
        if op == 'label':
            offsets[row[1]] = size
        elif op == 'jcc':
            size += 6
        elif op in ('jmp', 'call'):
            size += 5
        else:
            size += len(bytes.fromhex(VOCABULARY[row]))
    pc = 0
    words = []
    for row in rows:
        op = row[0]
        if op == 'label':
            continue
        if op == 'jcc' or op == 'jmp':
            prefix = bytes((15, 128 + row[1])) if op == 'jcc' else b'\xe9'
            length = len(prefix) + 4
            raw = prefix + struct.pack('<i', offsets[row[-1]] - pc - length)
        elif op == 'call':
            words.append(255 << 56)
            pc += 5
            continue
        else:
            raw = bytes.fromhex(VOCABULARY[row])
        assert 0 < len(raw) <= 7
        words.append((len(raw) << 56) | int.from_bytes(raw, 'little'))
        pc += len(raw)
    assert pc == size
    return words


POLICY = '''
def validate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 168 or length(o) < 32 or length(w) < 1024:
        return 0
    shape = uint(s, 0, 8)
    if shape < 1 or shape > 3 or uint(s, 8, 8) != BIND_REPLY:
        return 0
    span = uint(s, 32, 8)
    if span == 0 or span > 2048 or length(s) != 88 + span + 56:
        return 0
    if uint(s, 40, 8) != 0 or uint(s, 48, 8) != 0 or uint(s, 64, 8) != 1 or uint(s, 72, 8) != 56 or uint(s, 80, 8) != 0:
        return 0
    end = 88 + span
    if uint(s, end, 8) != 0 or uint(s, end + 8, 8) != 1 or uint(s, end + 16, 8) != 0:
        return 0
    if uint(s, end + 32, 8) != 1 or uint(s, end + 40, 8) != uint(s, 56, 8):
        return 0
    count = specification(w, shape)
    i = 0
    pc = 88
    while i < count:
        word = get(w, i * 8)
        width = word >> 56
        if width == 255:
            if pc + 5 > end or byte(s, pc) != 232 or uint(s, end + 24, 8) != pc - 88 + 1:
                return 0
            displacement = uint(s, pc + 1, 4)
            if displacement >= 2147483648:
                displacement = displacement | 18446744069414584320
            if uint(s, end + 48, 8) != displacement or uint(s, 24, 8) + pc - 88 + 5 + displacement != uint(s, 56, 8):
                return 0
            pc = pc + 5
        else:
            if pc + width > end or uint(s, pc, width) != (word & 72057594037927935):
                return 0
            pc = pc + width
        i = i + 1
    if pc != end:
        return 0
    put(o, 0, SUCCESS)
    put(o, 8, shape)
    put(o, 16, 3)
    put(o, 24, span)
    return 32

def specification(w:mutbuf, shape:u64) -> u64:
    if shape == 1:
        return grammar1(w)
    if shape == 2:
        return grammar2(w)
    return grammar3(w)
'''


def source_program():
    source = POLICY.replace('BIND_REPLY', str(int.from_bytes(b'HIAEBNR1','little'))).replace(
        'SUCCESS', str(int.from_bytes(b'HIASIMV1','little')))
    for kind in (1, 2, 3):
        words = instructions(kind)
        source += f'\ndef grammar{kind}(w:mutbuf) -> u64:\n'
        for n, word in enumerate(words):
            source += f'    put(w, {n*8}, {word})\n'
        source += f'    return {len(words)}\n'
    return source


if __name__ == '__main__':
    helpers = ELF[ELF.index('def uint('):ELF.index('def copy_bytes(')]
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap' / (MODULE + '.hepta')
    target.write_text(render_assembly(document(source_program() + helpers, MODULE)))
