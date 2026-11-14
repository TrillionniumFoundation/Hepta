"""Independent compact semantic resident; the ordinary compiler stays fixed.

This author projects the exact frozen v3 semantic program into explicitly
bounded, disjoint compact tables.  It is not the public compiler, a machine
entry adapter, a cold qualification, or a replacement diagnostic formatter.
"""
from __future__ import annotations
import argparse
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import FunctionType

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import generate_hia_file_render_checker as parent
from tools import generate_hia_selfhost as compiler
from hepta.hia_agent_assembly import render_assembly

SOURCE = 'examples/hia_bootstrap/file_render_checker_word64_ascii.hepta'
PARENT_EXPANDED = 'fff28420e62b771a51518ed5e78d99275f8adb8a8deee90076c5854b085dba87'
COUNTS = {'functions': 256, 'blocks': 4096, 'operations': 16384,
          'list_items': 256, 'SSA_per_function': 32768, 'block_parameters_total': 32768}
SIZES = [('state', 4096), ('functions', 256 * 64), ('formal_types', 256 * 256),
         ('return_types_origins', 256 * 256 * 2), ('exports', 256 * 32),
         ('blocks', 4096 * 28), ('block_parameters', 32768 * 7),
         ('calls', 8192), ('call_state', 256), ('values', 32768 * 8),
         ('names', 32768 * 6), ('arguments', 256 * 2), ('outputs', 256 * 3),
         ('returns', 256 * 2), ('temporary_capabilities', 256 * 2), ('queue', 4096 * 2)]
REGIONS = {}
_at = 0
for _name, _size in SIZES:
    REGIONS[_name] = (_at, _at + _size)
    _at += _size
assert _at == 1047040 and _at <= 1048576
CONSTANTS = {'FBASE': REGIONS['functions'][0], 'FSTRIDE': 64,
             'BBASE': REGIONS['blocks'][0], 'BSTRIDE': 28,
             'VBASE': REGIONS['values'][0], 'ARGS': REGIONS['arguments'][0],
             'CBASE': REGIONS['calls'][0], 'CSTATE': REGIONS['call_state'][0],
             'QBASE': REGIONS['queue'][0], 'CAPTMP': REGIONS['temporary_capabilities'][0],
             'FPARAM': REGIONS['formal_types'][0], 'FRESULT': REGIONS['return_types_origins'][0],
             'BPAR': REGIONS['block_parameters'][0], 'NAMES': REGIONS['names'][0],
             'EXPORTS': REGIONS['exports'][0], 'OUTPUTS': REGIONS['outputs'][0],
             'RETURNS': REGIONS['returns'][0],
             'MAX_INSTRUCTIONS': 16384, 'MAX_CORE_NODES': compiler.MAX_CORE_NODES,
             'MAX_RELOCATIONS': compiler.MAX_RELOCATIONS}
F_OFFSETS = {0: 0, 8: 4, 16: 8, 24: 12, 32: 16, 40: 20, 176: 24,
             184: 28, 240: 32, 248: 36, 256: 40, 264: 44}

def expr(text):
    return ast.parse(text, mode='eval').body

def text(node):
    return ast.unparse(node)

def replace_once(value, old, new):
    if value.count(old) != 1:
        raise ValueError('compact projection preimage differs: ' + old)
    return value.replace(old, new, 1)

def pieces(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return pieces(node.left) + pieces(node.right)
    return [node]

def scaled(node, scale):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        if isinstance(node.right, ast.Constant) and node.right.value == scale:
            return node.left
        if isinstance(node.left, ast.Constant) and node.left.value == scale:
            return node.right
    return None

def summed(nodes):
    if not nodes:
        return ast.Constant(0)
    result = nodes[0]
    for node in nodes[1:]:
        result = ast.BinOp(result, ast.Add(), node)
    return result

def indexed(nodes, scale, constant=0):
    if not nodes:
        if constant % scale:
            raise ValueError('unaligned compact index')
        return ast.Constant(constant // scale)
    if len(nodes) != 1 or constant % scale:
        raise ValueError('unexpected compact index terms: ' + repr([text(x) for x in nodes]))
    result = scaled(nodes[0], scale)
    if result is None:
        raise ValueError('unexpected compact index stride: ' + text(nodes[0]))
    return result if not constant else ast.BinOp(result, ast.Add(), ast.Constant(constant // scale))

class Memory(ast.NodeTransformer):
    def __init__(self, node, log):
        self.name = node.name
        self.log = log
        self.fptr = set()
        self.bptr = set()
        for item in ast.walk(node):
            if isinstance(item, ast.Assign) and len(item.targets) == 1 and isinstance(item.targets[0], ast.Name):
                names = {n.id for n in ast.walk(item.value) if isinstance(n, ast.Name)}
                if 'FBASE' in names:
                    self.fptr.add(item.targets[0].id)
                if 'BBASE' in names:
                    self.bptr.add(item.targets[0].id)
        if self.name in ('call_loan',):
            self.fptr.add('base')
        if self.name == 'loan_incoming':
            self.bptr.add('bb')

    def table(self, terms, name, stride, aliases=()):
        for node in terms:
            if isinstance(node, ast.Name) and node.id in aliases:
                return node, [x for x in terms if x is not node]
        starts = [x for x in terms if isinstance(x, ast.Name) and x.id == name]
        if not starts:
            return None
        if len(starts) != 1:
            raise ValueError('multiple compact table roots')
        rest = [x for x in terms if x is not starts[0]]
        scales = [x for x in rest if isinstance(x, ast.BinOp) and isinstance(x.op, ast.Mult)
                  and isinstance(x.right, ast.Name) and x.right.id == stride]
        if len(scales) != 1:
            raise ValueError('table record is not exactly indexed: ' + name + repr([text(x) for x in rest]))
        return ast.BinOp(starts[0], ast.Add(), scales[0]), [x for x in rest if x is not scales[0]]

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if not isinstance(node.func, ast.Name):
            return node
        call = node.func.id
        if call == 'same_identifier' and self.name == 'read_function_name':
            node.args[2] = expr('base + 32')
            node.args.append(ast.Constant(4))
            return node
        if call == 'lookup_identifier':
            base = text(node.args[2])
            if base == 'FBASE + 240':
                node.args[2] = expr('FBASE + 32')
                return node
            if base == '1010448':
                node.args[2] = ast.Name('EXPORTS', ast.Load())
                node.args[3] = ast.Constant(32)
                return node
        if call not in ('get', 'put', 'byte', 'store') or len(node.args) < 2 or text(node.args[0]) != 'w':
            return node
        write = call in ('put', 'store')
        at = node.args[1]
        terms = pieces(at)
        constant = sum(x.value for x in terms if isinstance(x, ast.Constant) and type(x.value) is int)
        rest = [x for x in terms if not isinstance(x, ast.Constant)]
        val = text(node.args[2]) if write else None
        before = text(node)
        result = None
        def access(read, store, where):
            return expr(f'{store}(w, {where}, {val})' if write else f'{read}(w, {where})')
        def field(read, store, base, index, kind):
            return expr(f'{store}(w, {base}, {index}, {kind}, {val})' if write
                        else f'{read}(w, {base}, {index}, {kind})')
        matched = self.table(rest, 'FBASE', 'FSTRIDE', self.fptr)
        if matched:
            base, remaining = matched
            if constant in (48, 192, 216):
                idx = indexed(remaining, 8)
                result = field('sxget', 'sxput', text(base), text(idx), {48: 0, 192: 1, 216: 2}[constant])
            elif not remaining and constant in F_OFFSETS:
                result = access('state_get32', 'state_put32', f'{text(base)} + {F_OFFSETS[constant]}')
            else:
                raise ValueError('unmapped function field: ' + before)
        if result is None:
            matched = self.table(rest, 'BBASE', 'BSTRIDE', self.bptr)
            if matched:
                base, remaining = matched
                if constant in (32, 40):
                    result = field('bxget', 'bxput', text(base), text(indexed(remaining, 16)), 0 if constant == 32 else 1)
                elif constant == 304:
                    result = field('bxget', 'bxput', text(base), text(summed(remaining)), 2)
                elif constant == 288:
                    idx = indexed(remaining, 8)
                    result = access('cx16', 'cp16', f'{text(base)} + 8 + ({text(idx)}) * 2')
                elif not remaining and constant == 296:
                    result = access('cx16', 'cp16', f'{text(base)} + 10')
                elif not remaining and constant in (0, 8, 16, 24):
                    kind = {0: ('state_get32', 'state_put32', 0), 8: ('cx16', 'cp16', 4),
                            16: ('byte', 'store', 6), 24: ('byte', 'store', 7)}[constant]
                    result = access(kind[0], kind[1], f'{text(base)} + {kind[2]}')
                else:
                    raise ValueError('unmapped block field: ' + before)
        for root, stride, kinds in [('VBASE', 16, {0: 0, 8: 1}), ('CAPBASE', 24, {0: 2, 8: 3, 16: 4})]:
            starts = [x for x in rest if isinstance(x, ast.Name) and x.id == root]
            if result is None and starts:
                idx = indexed([x for x in rest if x is not starts[0]], stride)
                if constant not in kinds:
                    raise ValueError('unmapped value field: ' + before)
                result = expr(f'vxput(w, {text(idx)}, {kinds[constant]}, {val})' if write
                              else f'vxget(w, {text(idx)}, {kinds[constant]})')
        for root in ('ORIGINBASE', 'KBASE', 'CAPTMP', 'ARGS', 'QBASE', 'CSTATE', 'BLOCKORIGIN'):
            starts = [x for x in rest if isinstance(x, ast.Name) and x.id == root]
            if result is not None or not starts:
                continue
            remain = [x for x in rest if x is not starts[0]]
            if root == 'ORIGINBASE':
                idx = text(summed(remain))
                result = expr(f'vxput(w, {idx}, 5, {val})' if write else f'vxget(w, {idx}, 5)')
            elif root == 'KBASE':
                result = access('byte', 'store', f'BBASE + ({text(summed(remain))}) * BSTRIDE + 14')
            elif root == 'CAPTMP':
                result = access('cx16', 'cp16', f'CAPTMP + ({text(summed(remain))}) * 2')
            elif root in ('ARGS', 'QBASE', 'CSTATE'):
                idx = text(indexed(remain, 8, constant))
                if root == 'CSTATE':
                    result = access('byte', 'store', f'CSTATE + ({idx})')
                else:
                    result = access('cx16', 'cp16', f'{root} + ({idx}) * 2')
            else:
                mids = [(x, scaled(x, 16)) for x in remain if scaled(x, 16) is not None]
                if len(mids) != 1 or constant:
                    raise ValueError('unmapped block origin: ' + before)
                idx = summed([x for x in remain if x is not mids[0][0]])
                result = field('bxget', 'bxput', f'BBASE + ({text(mids[0][1])}) * BSTRIDE', text(idx), 3)
        if result is None and self.name not in ('put', 'get', 'state_get32', 'state_put32'):
            if constant in (296, 304, 312, 320, 328, 336):
                kind = (constant - 296) % 16
                if kind not in (0, 8):
                    raise ValueError('bad output field')
                idx = indexed(rest, 16, constant - (296 if kind == 0 else 304))
                result = access('cx16' if kind == 0 else 'byte', 'cp16' if kind == 0 else 'store',
                                f'OUTPUTS + ({text(idx)}) * 3' + (' + 2' if kind else ''))
            elif constant in (400, 408, 416):
                idx = indexed(rest, 8, constant - 400)
                result = access('cx16', 'cp16', f'RETURNS + ({text(idx)}) * 2')
        if result is not None:
            self.log.append({'function': self.name, 'before': before, 'after': text(result)})
            return ast.copy_location(result, node)
        return node

HELPERS = r'''
def assembly_limits(s:readbuf, w:mutbuf) -> u64:
    i = 0
    lines = 1
    width = 0
    while i < length(s):
        if byte(s, i) == 10:
            lines = lines + 1
            width = 0
        else:
            width = width + 1
        if lines > 16384 or width > 16384:
            fail(w, 70)
            return 0
        i = i + 1
    return 1

def cx16(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8)

def cp16(w:mutbuf, at:u64, value:u64) -> u64:
    if value > 65535:
        return fail(w, 69)
    store(w, at, value & 255)
    store(w, at + 1, value >> 8)
    return 0

def sxget(w:mutbuf, base:u64, slot:u64, kind:u64) -> u64:
    at = ((base - FBASE) >> 6) * 256 + slot
    if kind == 0:
        return byte(w, FPARAM + at)
    value = cx16(w, FRESULT + at * 2)
    if kind == 1:
        return value & 31
    return value >> 5

def sxput(w:mutbuf, base:u64, slot:u64, kind:u64, value:u64) -> u64:
    if slot >= 256 or base < FBASE or base >= FBASE + 16384 or ((base - FBASE) & 63) != 0:
        return fail(w, 69)
    at = ((base - FBASE) >> 6) * 256 + slot
    if kind == 0:
        if value > 16:
            return fail(w, 69)
        store(w, FPARAM + at, value)
    else:
        prior = cx16(w, FRESULT + at * 2)
        if kind == 1:
            if value > 16:
                return fail(w, 69)
            prior = (prior & 65504) | value
        else:
            if kind != 2 or value > 256:
                return fail(w, 69)
            prior = (prior & 31) | (value << 5)
        cp16(w, FRESULT + at * 2, prior)
    return 0

def vxget(w:mutbuf, slot:u64, kind:u64) -> u64:
    at = VBASE + slot * 8
    if kind == 2:
        return cx16(w, at + 4)
    if kind == 3:
        return cx16(w, at + 6)
    if kind == 0:
        return byte(w, at) & 31
    if kind == 1:
        return (byte(w, at) >> 6) | (byte(w, at + 1) << 2) | ((byte(w, at + 2) & 7) << 10)
    if kind == 4:
        return (byte(w, at) >> 5) & 1
    return (byte(w, at + 2) >> 3) | ((byte(w, at + 3) & 15) << 5)

def vxput(w:mutbuf, slot:u64, kind:u64, value:u64) -> u64:
    if slot >= 32768:
        return fail(w, 69)
    at = VBASE + slot * 8
    if kind == 2 or kind == 3:
        if value > 32768:
            return fail(w, 69)
        return cp16(w, at + kind * 2, value)
    if kind == 0:
        if value > 16:
            return fail(w, 69)
        store(w, at, (byte(w, at) & 224) | value)
        return 0
    if kind == 1:
        if value > 4096:
            return fail(w, 69)
        store(w, at, (byte(w, at) & 63) | ((value & 3) << 6))
        store(w, at + 1, (value >> 2) & 255)
        store(w, at + 2, (byte(w, at + 2) & 248) | (value >> 10))
        return 0
    if kind == 4:
        if value > 1:
            return fail(w, 69)
        store(w, at, (byte(w, at) & 223) | (value << 5))
        return 0
    if kind != 5 or value > 256:
        return fail(w, 69)
    store(w, at + 2, (byte(w, at + 2) & 7) | ((value & 31) << 3))
    store(w, at + 3, (byte(w, at + 3) & 240) | (value >> 5))
    return 0

def bxget(w:mutbuf, base:u64, slot:u64, kind:u64) -> u64:
    at = BPAR + (cx16(w, base + 12) + slot) * 7
    if kind == 1:
        return byte(w, at + 2)
    if kind == 2:
        return cx16(w, at + 3)
    if kind == 3:
        return cx16(w, at + 5)
    return cx16(w, at)

def bxput(w:mutbuf, base:u64, slot:u64, kind:u64, value:u64) -> u64:
    index = cx16(w, base + 12) + slot
    if slot >= 256 or index >= 32768:
        return fail(w, 69)
    at = BPAR + index * 7
    if kind == 1:
        if value > 16:
            return fail(w, 69)
        store(w, at + 2, value)
        return 0
    if kind == 2:
        return cp16(w, at + 3, value)
    if kind == 3:
        if value > 256:
            return fail(w, 69)
        return cp16(w, at + 5, value)
    if kind != 0 or value >= 32768:
        return fail(w, 69)
    return cp16(w, at, value)

def cg_get(w:mutbuf, source:u64, target:u64) -> u64:
    return (byte(w, CBASE + source * 32 + (target >> 3)) >> (target & 7)) & 1

def cg_put(w:mutbuf, source:u64, target:u64) -> u64:
    at = CBASE + source * 32 + (target >> 3)
    store(w, at, byte(w, at) | (1 << (target & 7)))
    return 0

def clear_argument_marks(w:mutbuf, n:u64) -> u64:
    i = 0
    while i < n:
        v = cx16(w, ARGS + i * 2)
        at = VBASE + v * 8
        value = byte(w, at + 3)
        store(w, at + 3, value & 239)
        i = i + 1
    return 0

def header_put8(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value)
    fill_range(w, at + 1, 7, 0)
    return 0

def header_put16(w:mutbuf, at:u64, value:u64) -> u64:
    cp16(w, at, value)
    fill_range(w, at + 2, 6, 0)
    return 0

def header_put32(w:mutbuf, at:u64, value:u64) -> u64:
    state_put32(w, at, value)
    fill_range(w, at + 4, 4, 0)
    return 0
'''

ARGUMENTS = r'''
def args(s:readbuf, w:mutbuf, is_edge:u64) -> u64:
    expect(s, w, 40)
    n = 0
    v = 0
    t = 0
    state = 0
    while get(w, 8) != 41 and get(w, 40) == 0:
        v = expect(s, w, 256)
        t = variable(w, v)
        if n >= 256:
            clear_argument_marks(w, n)
            return fail(w, 15)
        if (t >= 8 and t <= 9) or (t == 7 and is_edge != 2) or (is_edge == 1 and t == 6):
            state = byte(w, VBASE + v * 8 + 3)
            if (state & 16) != 0:
                fail(w, 16)
            else:
                store(w, VBASE + v * 8 + 3, state | 16)
        cp16(w, ARGS + n * 2, v)
        n = n + 1
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                fail(w, 17)
    clear_argument_marks(w, n)
    expect(s, w, 41)
    put(w, 136, n)
    return n
'''

# These words are written only by the pinned scalar lexer/inventory/control
# producers. Numeric literal payload word16 and decrementing loan/owner
# counts280/352 remain full-width. Every selected read is dominated by a
# whole-word initial write or the original first256-byte phase reset.
NARROW_READ_WORDS = frozenset((0, 8, 24, 32, 40, 48, 64, 72, 80, 88, 96, 104,
    112, 120, 136, 232, 240, 248, 256, 264, 272, 288, 344, 360, 368, 384,
    392, 432, 456, 464, 472, 480, 488, 640, 648, 1024, 1032))
# These upper words are already zero from the original phase reset. The
# early compile/fail writers stay full-width, including preflight refusals.
NARROW_WRITE_WORDS = frozenset((0, 8, 24, 32, 64, 72, 80, 88, 96, 104,
    112, 120, 136, 232, 240, 248))
NARROW_WORD_WIDTHS = {offset: 4 for offset in NARROW_READ_WORDS}
NARROW_WORD_WIDTHS.update({offset: 1 for offset in (32, 40, 48, 72, 232, 264,
    360, 368, 432, 464, 640)})
NARROW_WORD_WIDTHS.update({offset: 2 for offset in (8, 64, 80, 88, 96, 112,
    136, 272, 288, 344, 384, 392, 480, 488, 648, 1024)})

class HeaderWords(ast.NodeTransformer):
    def __init__(self, function, log):
        self.function, self.log = function, log
    def visit_Call(self, node):
        node = self.generic_visit(node)
        if (not isinstance(node.func, ast.Name) or node.func.id not in ('get', 'put')
            or len(node.args) < 2 or text(node.args[0]) != 'w'
            or not isinstance(node.args[1], ast.Constant)
            or type(node.args[1].value) is not int):
            return node
        offset = node.args[1].value
        old = text(node)
        if node.func.id == 'get' and offset in NARROW_READ_WORDS:
            node.func = ast.Name({1: 'byte', 2: 'cx16', 4: 'state_get32'}[NARROW_WORD_WIDTHS[offset]], ast.Load())
        elif (node.func.id == 'put' and 0 <= offset <= 1032 and offset % 8 == 0
              and isinstance(node.args[2], ast.Constant) and node.args[2].value == 0):
            # Exact whole-word zero, including dirty preimages and the original
            # early preflight refusal. The entry extent dominates every field.
            node.func = ast.Name('fill_range', ast.Load())
            node.args = [node.args[0], node.args[1], ast.Constant(8), ast.Constant(0)]
        elif (node.func.id == 'put' and offset in NARROW_READ_WORDS
              and self.function not in ('compile', 'fail')):
            width = NARROW_WORD_WIDTHS[offset]
            method = ({1: 'store', 2: 'cp16', 4: 'state_put32'}[width]
                      if offset in NARROW_WRITE_WORDS else
                      {1: 'header_put8', 2: 'header_put16', 4: 'header_put32'}[width])
            node.func = ast.Name(method, ast.Load())
        else:
            return node
        self.log.append({'function': self.function, 'before': old, 'after': text(node)})
        return node

NAMES = r'''
def same_identifier(s:readbuf, w:mutbuf, base:u64, width:u64) -> u64:
    size = byte(w, 464)
    if size != byte(w, base + width):
        return 0
    begin = get(w, 456)
    other = state_get32(w, base)
    if width == 3:
        other = other & 16777215
    i = 0
    while i < size:
        if byte(s, begin + i) != byte(s, other + i):
            return 0
        i = i + 1
    return 1

def lookup_identifier(s:readbuf, w:mutbuf, base:u64, stride:u64, count:u64) -> u64:
    i = 0
    record = 0
    width = 4
    if stride == 32:
        width = 8
    target_hash = get(w, 472)
    while i < count:
        record = base + i * stride
        if state_get32(w, record + width * 2) == target_hash:
            if same_identifier(s, w, record, width) == 1:
                return i
        i = i + 1
    return count

def read_value_name(s:readbuf, w:mutbuf, kind:u64) -> u64:
    quoted = 0
    if kind == 260:
        quoted = 1
    if get(w, 32) != quoted:
        return fail(w, 48)
    identifier(s, w)
    if get(w, 40) != 0:
        return 0
    slot = ((get(w, 472) * 2654435761) & 4294967295) >> 17
    probes = 0
    base = 0
    index = 0
    begin = 0
    while probes < 32768:
        base = NAMES + slot * 6
        if byte(w, base + 3) == 0:
            index = get(w, 480)
            if index >= 32768:
                return fail(w, 37)
            begin = get(w, 456)
            store(w, base, begin & 255)
            store(w, base + 1, (begin >> 8) & 255)
            store(w, base + 2, (begin >> 16) & 255)
            store(w, base + 3, byte(w, 464))
            cp16(w, base + 4, index)
            put(w, 480, index + 1)
            next_token(s, w)
            return index
        if same_identifier(s, w, base, 3) == 1:
            index = cx16(w, base + 4)
            next_token(s, w)
            return index
        slot = (slot + 1) & 32767
        probes = probes + 1
    return fail(w, 37)

def read_block_name(s:readbuf, w:mutbuf, definition:u64) -> u64:
    if get(w, 32) != 0:
        return fail(w, 48)
    identifier(s, w)
    if get(w, 40) != 0:
        return 0
    count = get(w, 488)
    start = state_get32(w, FBASE + get(w, 72) * FSTRIDE + 4)
    base = BBASE + start * BSTRIDE + 16
    index = lookup_identifier(s, w, base, BSTRIDE, count)
    if definition == 1:
        if index != count or count >= 4096 or start + count >= 4096:
            return fail(w, 11)
        state_put32(w, base + count * BSTRIDE, get(w, 456))
        state_put32(w, base + count * BSTRIDE + 4, get(w, 464))
        state_put32(w, base + count * BSTRIDE + 8, get(w, 472))
        put(w, 488, count + 1)
    else:
        if index == count:
            return fail(w, 19)
    next_token(s, w)
    return index
'''

PURE_ENCODING = frozenset(('emit', 'emit4', 'emit8', 'emit_bytes', 'write4', 'mem',
    'load_var', 'store_var', 'copy_argument', 'normalize', 'function_start',
    'relocation', 'owned_branch', 'owned_patch', 'owned_immediate', 'owned_move_buffer', 'cast_integer'))

class EraseEncoding(ast.NodeTransformer):
    def __init__(self, log):
        self.log = log
    def visit_Call(self, node):
        original = text(node)
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name) and node.func.id in PURE_ENCODING:
            calls = {n.func.id for arg in node.args for n in ast.walk(arg)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            if not calls <= {'get', 'byte', 'state_get32', 'frame', 'integer_width', 'signed_type'}:
                raise ValueError('encoding argument may contain a semantic transition: ' + original)
            self.log.append(original)
            return ast.Constant(0)
        return node
    def visit_Expr(self, node):
        node = self.generic_visit(node)
        return None if isinstance(node.value, ast.Constant) else node

class Constants(ast.NodeTransformer):
    def visit_Name(self, node):
        return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node) if node.id in CONSTANTS else node

def _rewrite_function(node):
    raw = ast.unparse(node)
    name = node.name
    substitutions = {
        'compile': [('fill_range(w, CBASE, 67584, 0)', 'put(w, 40, 0)\n    put(w, 48, 0)\n    if assembly_limits(s, w) == 0:\n        return 4294967295\n    fill_range(w, CBASE, 8448, 0)'),
                    ('fill_range(w, KBASE, 1536, 0)', 'fill_range(w, BBASE, 114688, 0)\n    put(w, 1032, 0)'),
                    ('        if phase == 1:\n            if get(w, 56) > length(o):\n                return 4294967294', '')],
        'parse_function': [('fill_range(w, 955152, 49152, 0)', 'fill_range(w, NAMES, 196608, 0)'),
                           ('fill_range(w, VBASE, 32768, 0)', 'fill_range(w, VBASE, 262144, 0)')],
        'parse_params': [('if count >= 16:', 'if count >= 256:')],
        'parse_block': [('b >= 256 or get(w, 80) >= 1536', 'b >= 4096 or get(w, 80) >= 4096'),
                        ('18446744073709551615', '65535'),
                        ('    if get(w, 48) > 0:\n        put(w, bb, get(w, 56))', ''),
                        ('    count = parse_params(s, w, 0)',
                         '    if get(w, 48) == 0 and get(w, 432) == 1:\n        cp16(w, bb + 12, get(w, 1032))\n    count = parse_params(s, w, 0)\n    if get(w, 48) == 0 and get(w, 432) == 1:\n        put(w, 1032, get(w, 1032) + count)')],
        'args': [('if n >= 16:', 'if n >= 256:')],
        'edge': [('b >= 256 or bid >= 1536', 'b >= 4096 or bid >= 4096')],
        'define': [('v >= 2048', 'v >= 32768')],
        'variable': [('v >= 2048', 'v >= 32768')],
        'loan_ancestor': [('depth < 2048', 'depth < 32768')],
        'read_result_types': [('if count >= 3:', 'if count >= 256:')],
        'owned_read_outputs': [('put(w, 296, 2048)', 'put(w, 296, 32768)'), ('if count >= 3:', 'if count >= 256:')],
        'loan_incoming': [('while i < 16:', 'while i < count:'), ('i << 4', 'i << 8'),
                          ('packed & 15', 'packed & 255'), ('packed >> 4', 'packed >> 8')],
        'loan_argument': [('return 16', 'return 256')],
        'loan_transfer': [('    interned_count = get(w, 480)',
                           '    if n != get(w, BBASE + bid * BSTRIDE + 8):\n        return fail(w, 19)\n    interned_count = get(w, 480)'),
                          ('while i < 16:', 'while i < n:'), ('parent << 4', 'parent << 8'),
                          ('get(w, 384) >= 256', 'get(w, 384) >= 4096')],
        'read_exports': [('1010448 + n * 48', 'EXPORTS + n * 32')],
        'validate_exports': [('1010448 + i * 48', 'EXPORTS + i * 32')],
    }
    repeated = {('parse_block', '18446744073709551615'): 2, ('loan_transfer', 'while i < 16:'): 2}
    for old, new in substitutions.get(name, ()):
        expected = repeated.get((name, old), 1)
        if raw.count(old) != expected:
            raise ValueError(f'compact exact {name} preimage {old!r}: {raw.count(old)} != {expected}')
        raw = raw.replace(old, new)
    if name == 'instruction':
        raw = replace_once(raw, 'store(w, CBASE + get(w, 72) * 256 + x, 1)', 'cg_put(w, get(w, 72), x)')
    if name == 'check_calls':
        raw = replace_once(raw, 'byte(w, CBASE + f * 256 + target)', 'cg_get(w, f, target)')
    if name == 'loan_transfer':
        raw = replace_once(raw, 'root = loan_argument(w, n, get(w, CAPBASE + v * 24))',
            'root = get(w, CAPBASE + v * 24)\n'
            '                if root == v:\n'
            '                    root = i\n'
            '                else:\n'
            '                    root = loan_argument(w, n, root)')
    return ast.parse(raw).body[0]

LEXICAL_WORDS_SHA256 = '113512f56e2bda1a8055c8caf450f1dd1990b0fad0bf5adebf93249c68b97659'

def lexical_vocabulary(node, log):
    """Preserve every token; skip impossible words and unroll ordered reads.

    next_token has already scanned the complete nonempty ASCII word inside s.
    Only there may a first byte absent from every frozen keyword establish an
    identifier without calling keyword. The keyword helper itself retains its
    complete original read order, including zero and oversized lengths.
    """
    words = compiler.WORDS
    if sha256(json.dumps(words, separators=(',', ':')).encode()).hexdigest() != LEXICAL_WORDS_SHA256:
        raise ValueError('exact keyword vocabulary changed')
    first = sorted({ord(word[0]) for word in words})
    if len(words) != 98 or len(set(words)) != 98 or any(not word.isascii() or not 0 < len(word) <= 32 for word in words):
        raise ValueError('keyword vocabulary is not the reviewed fixed domain')
    low, high = first[0], first[-1]
    mask = sum(1 << (value - low) for value in first)
    if (low, high, mask) != (97, 119, 8289215):
        raise ValueError('keyword first-byte domain changed')
    raw = ast.unparse(node)
    before = raw
    if node.name == 'next_token':
        old = 'if kind == 0:\n        kind = keyword(s, begin, pos - begin)'
        new = (f'if kind == 0:\n'
               f'        c = byte(s, begin)\n'
               f'        if c < {low} or c > {high}:\n'
               f'            kind = 261\n'
               f'        elif ({mask} >> (c - {low}) & 1) == 0:\n'
               f'            kind = 261\n'
               f'    {old}')
        raw = replace_once(raw, old, new)
    elif node.name == 'keyword':
        old = 'while i < size:\n        value = byte(s, begin + i)'
        prefix = ''
        for index in range(8):
            prefix += (f'if size > {index}:\n'
                       f'        value = byte(s, begin + {index})\n'
                       f'        a = a | value << {index * 8}\n'
                       f'    ')
        prefix += 'i = 8\n    if size < 8:\n        i = size\n    '
        raw = replace_once(raw, old, prefix + old)
    if raw != before:
        log.append({'function': node.name, 'before_sha256': sha256(before.encode()).hexdigest(),
                    'after_sha256': sha256(raw.encode()).hexdigest(),
                    'vocabulary_sha256': LEXICAL_WORDS_SHA256, 'first_byte_mask': mask,
                    'proof': 'all 98 keywords retain their exact original matching branches; only scanned words with an impossible first byte skip the call; first eight keyword byte reads are sequential and individually length guarded'})
        return ast.parse(raw).body[0]
    return node

R5_EXPANDED_SHA256 = '18f6af40015e3a5034972eccce125c430fb4eaf0e091b9f7e588bc6d1d128ffc'

DENSE_LEXER = '\ndef next_token(s:readbuf, w:mutbuf) -> u64:\n    count = cx16(w, 1036)\n    if count - 1 >= 5957 or byte(w, 40) != 0:\n        return next_token_original(s, w)\n    index = cx16(w, 1038)\n    if index + 1 < count:\n        if state_get32(w, 643328 + index * 33) == state_get32(w, 0):\n            move_dense_bytes(w, 120, 0, 4)\n            move_dense_bytes(w, 0, 643328 + (index + 1) * 33, 33)\n            cp16(w, 1038, index + 1)\n            return 0\n    next_token_original(s, w)\n    if count <= 5956 and byte(w, 40) == 0 and cx16(w, 8) != 0:\n        at = 643328 + (count - 1) * 33\n        if count == 1:\n            move_dense_bytes(w, at, 120, 4)\n        if state_get32(w, at) == state_get32(w, 120):\n            move_dense_bytes(w, at + 33, 0, 33)\n            cp16(w, 1036, count + 1)\n            cp16(w, 1038, count)\n    return 0\n'

VALUE_CLEAR_BEFORE = 'fill_range(w, 577792, 262144, 0)'

VALUE_CLEAR_AFTER = 'fill_range(w, 577792, choose(cx16(w, 1036) - 1 < 5957, 65536, 262144), 0)\n    if cx16(w, 1036) == 0:\n        cp16(w, 1036, 1)'

NEW_NAME_BEFORE = '            header_put16(w, 480, index + 1)\n            next_token(s, w)\n            return index'

NEW_NAME_AFTER = '            header_put16(w, 480, index + 1)\n            next_token(s, w)\n            if index == 8192 and cx16(w, 1036) - 1 < 5957:\n                fill_range(w, 643328, 196608, 0)\n                cp16(w, 1036, 65535)\n            return index'

COUNTER_BEFORE = 'header_put32(w, 1032, state_get32(w, 1032) + count)'

COUNTER_AFTER = 'state_put32(w, 1032, state_get32(w, 1032) + count)'

def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('R8 exact projection mismatch: ' + before)
    return text.replace(before, after, 1)

def canonical(module):
    return '\n\n'.join((ast.unparse(node) for node in module.body)) + '\n'

def function(text):
    nodes = ast.parse(text).body
    if len(nodes) != 1 or not isinstance(nodes[0], ast.FunctionDef):
        raise ValueError('R8 replacement is not one function')
    return nodes[0]

def dense_projection(module):
    module = copy.deepcopy(module)
    before = canonical(module)
    if sha256(before.encode()).hexdigest() != R5_EXPANDED_SHA256:
        raise ValueError('R8 requires the exact frozen R5 expanded source')
    if len(module.body) != 105 or any((not isinstance(n, ast.FunctionDef) for n in module.body)):
        raise ValueError('R8 original function inventory changed')
    original = {n.name: copy.deepcopy(n) for n in module.body}
    if len(original) != 105:
        raise ValueError('R8 duplicate original function')
    if any((n.name in ('compile_phases', 'next_token_original') for n in module.body)):
        raise ValueError('R8 private function collision')
    users = {node.name for node in module.body if any((isinstance(item, ast.Constant) and type(item.value) is int and (item.value == 577792) for item in ast.walk(node)))}
    if users != {'parse_function', 'args', 'vxget', 'vxput', 'clear_argument_marks'}:
        raise ValueError('R8 unreviewed direct value-table access')
    original_lexer = original['next_token']
    for node in ast.walk(original_lexer):
        if isinstance(node, ast.Return):
            if isinstance(node.value, ast.Constant) and node.value.value == 0:
                continue
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and (node.value.func.id == 'fail'):
                continue
            raise ValueError('R8 original lexer gained a nonzero normal return')
    fail_returns = [ast.unparse(n.value) for n in ast.walk(original['fail']) if isinstance(n, ast.Return)]
    if fail_returns != ['0']:
        raise ValueError('R8 original fail return changed')
    compile_node = original['compile']
    if ast.unparse(compile_node.body[0]) != 'phase = 0':
        raise ValueError('R8 phase initializer changed')
    split = [i for i, node in enumerate(compile_node.body) if ast.unparse(node) == 'put(w, 432, 1)']
    if len(split) != 1 or ast.unparse(compile_node.body[split[0] - 1]) != 'fill_range(w, 1032, 8, 0)':
        raise ValueError('R8 metadata is not initialized at the original boundary')
    boundary = split[0]
    prefix = copy.deepcopy(compile_node.body[1:boundary])
    phases = copy.deepcopy(compile_node)
    phases.name = 'compile_phases'
    phases.body = [copy.deepcopy(compile_node.body[0]), *copy.deepcopy(compile_node.body[boundary:])]
    phase_text = once(ast.unparse(phases), '        fill_range(w, 0, 256, 0)', '        fill_range(w, 0, 256, 0)\n        cp16(w, 1038, 0)')
    phases = function(phase_text)
    before_returns = [ast.unparse(n.value) for n in ast.walk(compile_node) if isinstance(n, ast.Return)]
    prefix_returns = [ast.unparse(n.value) for n in ast.walk(ast.Module(body=prefix, type_ignores=[])) if isinstance(n, ast.Return)]
    phase_returns = [ast.unparse(n.value) for n in ast.walk(phases) if isinstance(n, ast.Return)]
    if len(before_returns) != 9 or len(prefix_returns) != 4 or len(phase_returns) != 5:
        raise ValueError('R8 original return boundaries changed')
    cleanup = ast.parse('\nresult = compile_phases(s, o, w)\ncount = cx16(w, 1036)\nif count - 1 < 5957:\n    fill_range(w, 643328, 196608, 0)\nfill_range(w, 1036, 4, 0)\nreturn result\n').body
    result = []
    for node in module.body:
        text = ast.unparse(node)
        if node.name == 'compile':
            node.body = prefix + cleanup
        elif node.name == 'next_token':
            node.name = 'next_token_original'
        elif node.name == 'parse_function':
            node = function(once(text, VALUE_CLEAR_BEFORE, VALUE_CLEAR_AFTER))
        elif node.name == 'parse_block':
            node = function(once(text, COUNTER_BEFORE, COUNTER_AFTER))
        elif node.name == 'read_value_name':
            node = function(once(text, NEW_NAME_BEFORE, NEW_NAME_AFTER))
        result.append(node)
    result.extend([phases, function(DENSE_LEXER)])
    after = ast.fix_missing_locations(ast.Module(body=result, type_ignores=[]))
    restored = inverse_projection(after)
    if ast.dump(restored, include_attributes=False) != ast.dump(module_original(before), include_attributes=False):
        raise ValueError('R8 inverse AST does not reconstruct all105 original functions')
    names = {n.name for n in after.body}
    externals = {n.func.id for n in ast.walk(after) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)} - names
    if externals != {'byte', 'choose', 'fill_range', 'length', 'move_dense_bytes', 'store'}:
        raise ValueError('R8 unexpected primitive or dangling call: ' + repr(externals))
    changes = []
    for node in after.body:
        lookup = 'next_token' if node.name == 'next_token_original' else node.name
        old = original.get(lookup)
        if old is None or ast.dump(old, include_attributes=False) != ast.dump(node, include_attributes=False):
            changes.append({'function': node.name, 'before_sha256': sha256(ast.unparse(old).encode()).hexdigest() if old else None, 'after_sha256': sha256(ast.unparse(node).encode()).hexdigest()})
    return (after, {'schema': 'hia.R8.dense-token-AST-projection.v1', 'status': 'AUTHORED_AST_ONLY_NOT_GENERATED_COMPILED_OR_EXECUTED', 'before_sha256': sha256(before.encode()).hexdigest(), 'after_sha256': sha256(canonical(after).encode()).hexdigest(), 'functions': len(after.body), 'inverse_all_original105_functions_exact': True, 'pre_init_original_returns_unchanged': prefix_returns, 'post_init_original_returns_all_pass_cleanup': phase_returns, 'value_region': [577792, 839936], 'borrowed_tail': [643328, 839936], 'metadata': {'count_plus_one_u16': 1036, 'next_index_u16': 1038, 'pending': 0, 'active_counts': [1, 5957], 'retired': 65535}, 'row_bytes': 33, 'virtual_first_row': True, 'capacity_records': 5956, 'lookup': 'sequential only; cursor resets at each original semantic-pass header clear', 'miss': 'unchanged original next_token, no speculative or future lexing', 'first_enable': 'only after original first full values clear', 'retirement': 'after original next_token and before returning newly interned index8192; permanent through this f0', 'normal_return_cleanup': 'active tail to original zero; all post-init high4metadata to original zero; retired real highSSA tail preserved', 'interruption_limit': 'fuel/trap may expose private metadata/cache and changed private call stack; no all-exit equivalence claim', 'changes': changes, 'new_source_domain_or_budget': False, 'machine_growth_bytes': None, 'ELF_fit': None, 'ten_million_fuel_closure': None})

def module_original(text):
    return ast.parse(text)

def inverse_projection(after):
    table = {n.name: copy.deepcopy(n) for n in after.body}
    current = table['compile']
    phase = table['compile_phases']
    index = next((i for i, n in enumerate(current.body) if isinstance(n, ast.Assign) and ast.unparse(n.value) == 'compile_phases(s, o, w)'))
    expected_cleanup = ast.parse('\nresult = compile_phases(s, o, w)\ncount = cx16(w, 1036)\nif count - 1 < 5957:\n    fill_range(w, 643328, 196608, 0)\nfill_range(w, 1036, 4, 0)\nreturn result\n').body
    if [ast.dump(n) for n in current.body[index:]] != [ast.dump(n) for n in expected_cleanup]:
        raise ValueError('R8 inverse cleanup changed')
    phase = function(once(ast.unparse(phase), '        fill_range(w, 0, 256, 0)\n        cp16(w, 1038, 0)', '        fill_range(w, 0, 256, 0)'))
    current.body = [copy.deepcopy(phase.body[0]), *current.body[:index], *phase.body[1:]]
    restored = []
    for old in after.body:
        if old.name in ('compile_phases', 'next_token'):
            continue
        node = table[old.name]
        text = ast.unparse(node)
        if node.name == 'next_token_original':
            node.name = 'next_token'
        elif node.name == 'parse_function':
            node = function(once(text, VALUE_CLEAR_AFTER, VALUE_CLEAR_BEFORE))
        elif node.name == 'parse_block':
            node = function(once(text, COUNTER_AFTER, COUNTER_BEFORE))
        elif node.name == 'read_value_name':
            node = function(once(text, NEW_NAME_AFTER, NEW_NAME_BEFORE))
        restored.append(node)
    return ast.fix_missing_locations(ast.Module(body=restored, type_ignores=[]))

class DenseReplayBuilder(compiler.Builder):
    def expr(self, node):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == 'move_dense_bytes'):
            allowed = {
                'move_dense_bytes(w, 120, 0, 4)',
                'move_dense_bytes(w, 0, 643328 + (index + 1) * 33, 33)',
                'move_dense_bytes(w, at, 120, 4)',
                'move_dense_bytes(w, at + 33, 0, 33)',
            }
            if (self.node.name != 'next_token' or ast.unparse(node) not in allowed
                    or node.keywords or len(node.args) != 4):
                raise ValueError('unreviewed R8 private copy site')
            workspace = self.expr(node.args[0])
            if workspace[1] != 'mutbuf':
                raise ValueError('R8 requires the actual mutable workspace loan')
            values = [workspace]
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and type(arg.value) is int:
                    if not 0 <= arg.value < 1048576:
                        raise ValueError('R8 private copy constant outside original workspace')
                    values.append(self.c(arg.value, 'usize'))
                else:
                    values.append(self.cast(self.expr(arg), 'usize'))
            return self.op('buffer.move_within', values)
        return super().expr(node)

def expanded():
    if sha256(parent.source_program().encode()).hexdigest() != PARENT_EXPANDED:
        raise ValueError('the exact frozen v3 semantic preimage changed')
    nodes = parent._symbolic(parent.projected_source())
    access_log, erased, header_log, lexical_log = [], [], [], []
    result = []
    replacements = {n.name: n for n in ast.parse(NAMES).body}
    pure_sources = {name: ast.unparse(nodes[name]) for name in sorted(PURE_ENCODING)}
    for name, node in nodes.items():
        if name in replacements:
            result.append(replacements[name])
            continue
        if name in PURE_ENCODING:
            continue
        node = _rewrite_function(node)
        if name == 'args':
            # Preserve the exact original duplicate predicate and failure
            # position; only its already-seen membership representation changes.
            expected = ('v == get(w, ARGS + j * 8) and (t >= 8 and t <= 9 or '
                        '(t == 7 and is_edge != 2) or (is_edge == 1 and t == 6))')
            if expected not in ast.unparse(node):
                raise ValueError('argument duplicate-policy preimage changed')
            # This complete authored replacement already uses the compact
            # table layout, like NAMES above. Do not reinterpret its byte
            # offsets as the frozen parent's 16-byte value-record layout.
            result.append(ast.parse(ARGUMENTS).body[0])
            continue
        node = EraseEncoding(erased).visit(node)
        # Erasing an encoding-only body can leave an if/loop empty. Its test
        # still evaluates; a harmless return-free expression fills the body.
        for item in ast.walk(node):
            if isinstance(item, (ast.If, ast.While)) and not item.body:
                item.body = [ast.Expr(ast.Constant(0))]
        node = Memory(node, access_log).visit(node)
        result.append(node)
    result.extend(ast.parse(HELPERS).body)
    result = [HeaderWords(node.name, header_log).visit(node) for node in result]
    result = [lexical_vocabulary(node, lexical_log) for node in result]
    module = Constants().visit(ast.Module(body=result, type_ignores=[]))
    ast.fix_missing_locations(module)
    table = {n.name: n for n in module.body}
    live, pending = set(), ['compile']
    while pending:
        name = pending.pop()
        if name in live:
            continue
        live.add(name)
        for item in ast.walk(table[name]):
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id in table:
                pending.append(item.func.id)
    module = ast.Module(body=[n for n in module.body if n.name in live], type_ignores=[])
    module, dense_log = dense_projection(module)
    program = canonical(module)
    forbidden = {'FBASE', 'BBASE', 'VBASE', 'CAPBASE', 'KBASE', 'ORIGINBASE', 'BLOCKORIGIN', 'FIXBASE'}
    dangling = sorted({n.id for n in ast.walk(ast.parse(program)) if isinstance(n, ast.Name)} & forbidden)
    if dangling:
        raise ValueError('unmapped old workspace symbols: ' + repr(dangling))
    return program, {'dense_replay': dense_log, 'exact_parent': PARENT_EXPANDED, 'access_projection': access_log,
                     'erased_encoding_calls': erased, 'erased_encoding_original_bodies': pure_sources,
                     'workspace': [{'name': n, 'begin': b, 'end': e} for n, (b, e) in REGIONS.items()],
                     'workspace_last_end': _at, 'remaining_workspace': 1048576 - _at,
                     'input_counts': COUNTS, 'author_counts': {'functions': 128, 'blocks': 1536, 'ops': 8192},
                     'semantic_passes': ['phase0-signatures', 'phase0-all-functions-and-resource-CFG',
                                         'phase1-edge-call-effect-result-checks'],
                     'new_error_phase': 'CFG arity is checked before compact incoming-loan writes',
                     'new_arena_refusal': '69 for compact index/extent exhaustion; no overlap or truncation',
                     'narrow_header_words': header_log,
                     'narrow_header_widths': NARROW_WORD_WIDTHS,
                     'lexical_projection': lexical_log,
                     'argument_membership': {'bit': 28, 'region': 'values', 'additional_workspace': 0,
                         'cleanup': 'clear every parsed argument before normal return and the original n>=256 refusal',
                         'unchanged_predicate': 'owner or mutable unless readonly formal-call, or any view on CFG edge'},
                     'value_field_bytes': {'type': [0], 'live': [0], 'block_plus_one': [0, 1, 2],
                         'formal_origin': [2, 3], 'argument_member': [3],
                         'unchanged_root_parent': [4, 5, 6, 7],
                         'scope': 'only admitted f0, validated SSA slots and the complete private 1MiB workspace; no external callbacks within a field transition'},
                     'loan_self_root_shortcut': 'CFG arguments contain each resource exactly once; root==actual argument implies index i',
                     'machine_code_size_is_not_a_Core_semantic_requirement': True,
                     'new_product_qualification': False}

def source_program():
    return expanded()[0]

# R9-private representation successor. No public compiler/runtime change.
# Core's fixed profile gives u64 and usize the identical unsigned 64-bit
# value set. This exact resident contains no type-named checked arithmetic
# or checked cast. Every memory operation remains at its original CFG point.
WORD64_BASE_SOURCE_BYTES = 395910
WORD64_BASE_SOURCE_SHA256 = '83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de'
WORD64_BASE_COUNTS = {'functions': 107, 'blocks': 1456, 'ops': 6664}
WORD64_REMOVED_CASTS = 317


def _word64_core_document(original):
    """Retag this one private resident and remove only identity wrap casts.

    No read, write, call, check, branch, return or loop is eliminated. Scalar
    uses are redirected to the already-dominating source of an identity cast.
    The complete ordered JSON edit log reconstructs the original document.
    """
    from hepta.hia_opcodes import WIDTHS
    from hepta.hia_program import verify_program
    if WIDTHS['u64'] != 64 or WIDTHS['usize'] != 64:
        raise ValueError('word64 fixed primitive widths differ')
    before = copy.deepcopy(original)
    counts = {'functions': len(before['functions']),
              'blocks': sum(len(f['blocks']) for f in before['functions']),
              'ops': sum(len(b['ops']) for f in before['functions'] for b in f['blocks'])}
    if (set(before) != {'schema', 'module', 'functions'}
            or before['schema'] != 'hepta.hia.program.v8'
            or before['module'] != 'file_render_checker_v4'
            or counts != WORD64_BASE_COUNTS
            or [f['name'] for f in before['functions']] != ['f'+str(i) for i in range(107)]):
        raise ValueError('word64 exact private Core preimage differs')
    if ([p['type'] for p in before['functions'][0]['params']] != ['readbuf','mutbuf','mutbuf']
            or before['functions'][0]['returns'] != ['u32']):
        raise ValueError('word64 external f0 ABI differs')
    after = copy.deepcopy(before)
    edits = []
    removed = []
    def parent_at(value, path):
        for part in path[:-1]:
            value = value[part]
        return value, path[-1]
    def change(path, value):
        parent, key = parent_at(after, path)
        old = copy.deepcopy(parent[key])
        if old != value:
            edits.append({'op':'set','path':list(path),'before':old,'after':copy.deepcopy(value)})
            parent[key] = copy.deepcopy(value)
    def remove(path):
        parent, key = parent_at(after, path)
        edits.append({'op':'remove','path':list(path),'before':copy.deepcopy(parent[key])})
        del parent[key]
    def alias_type(typ):
        return 'usize' if typ == 'u64' else typ
    for fi, function_before in enumerate(before['functions']):
        fp = ['functions', fi]
        original_types = {}
        def declare(value):
            if set(value) != {'name','type'}:
                raise ValueError('word64 declaration schema differs')
            old = original_types.setdefault(value['name'], value['type'])
            if old != value['type']:
                raise ValueError('word64 SSA type identity differs')
        for p in function_before['params']:
            declare(p)
        for block in function_before['blocks']:
            for p in block['params']:
                declare(p)
            for operation in block['ops']:
                if set(operation) != {'op','args','out','attrs'}:
                    raise ValueError('word64 operation schema differs')
                if (operation['op'] in {'int.add.checked','int.sub.checked','int.mul.checked',
                                      'int.neg.checked','int.div.checked','int.rem.checked'}
                        or operation['op']=='int.cast' and operation['attrs'] != {'mode':'wrap'}):
                    raise ValueError('word64 refuses an unreviewed type-named trap site')
                for p in operation['out']:
                    declare(p)
        aliases = {}
        removals = set()
        for bi, block in enumerate(function_before['blocks']):
            for oi, operation in enumerate(block['ops']):
                if operation['op'] != 'int.cast':
                    continue
                if len(operation['args']) != 1 or len(operation['out']) != 1:
                    raise ValueError('word64 cast shape differs')
                source = operation['args'][0]
                output = operation['out'][0]
                old_type, new_type = original_types[source], output['type']
                if {old_type,new_type} == {'u64','usize'}:
                    if operation['attrs'] != {'mode':'wrap'} or output['name'] in aliases:
                        raise ValueError('word64 alias is not one identity wrap cast')
                    aliases[output['name']] = source
                    removals.add((bi,oi))
                    removed.append({'function':function_before['name'],'block':block['id'],
                                    'original_op_index':oi,'operation':copy.deepcopy(operation)})
        def resolve(name):
            seen = set()
            while name in aliases:
                if name in seen:
                    raise ValueError('word64 SSA alias cycle')
                seen.add(name)
                name = aliases[name]
            return name
        for name in aliases:
            resolve(name)
        # Retag declared word values before deleting casts. This operation
        # never rewrites numeric token values, user type codes or attrs.
        for pi, p in enumerate(function_before['params']):
            change(fp+['params',pi,'type'],alias_type(p['type']))
        change(fp+['returns'],[alias_type(t) for t in function_before['returns']])
        for bi, block in enumerate(function_before['blocks']):
            bp = fp+['blocks',bi]
            for pi,p in enumerate(block['params']):
                change(bp+['params',pi,'type'],alias_type(p['type']))
            for oi, operation in enumerate(block['ops']):
                for pi,p in enumerate(operation['out']):
                    change(bp+['ops',oi,'out',pi,'type'],alias_type(p['type']))
        for bi, block in enumerate(function_before['blocks']):
            bp = fp+['blocks',bi]
            deleted = 0
            for oi, operation in enumerate(block['ops']):
                current_index = oi-deleted
                if (bi,oi) in removals:
                    remove(bp+['ops',current_index])
                    deleted += 1
                else:
                    change(bp+['ops',current_index,'args'],[resolve(a) for a in operation['args']])
            term = block['term']
            if term['op'] == 'ret':
                change(bp+['term','values'],[resolve(a) for a in term['values']])
            elif term['op'] == 'jump':
                change(bp+['term','args'],[resolve(a) for a in term['args']])
            elif term['op'] == 'branch':
                change(bp+['term','cond'],resolve(term['cond']))
                for side in ('then','else'):
                    change(bp+['term',side,'args'],[resolve(a) for a in term[side]['args']])
            elif term['op'] != 'trap':
                raise ValueError('word64 terminator differs')
    if len(removed) != WORD64_REMOVED_CASTS:
        raise ValueError('word64 identity cast inventory differs')
    # Mechanical inverse, checked from the transformed document, not from a
    # stored replacement document. Reverse indices restore each original op.
    restored = copy.deepcopy(after)
    for edit in reversed(edits):
        parent,key = parent_at(restored,edit['path'])
        if edit['op']=='set':
            if parent[key] != edit['after']:
                raise ValueError('word64 inverse set preimage differs')
            parent[key] = copy.deepcopy(edit['before'])
        elif edit['op']=='remove':
            if not isinstance(parent,list) or not 0 <= key <= len(parent):
                raise ValueError('word64 inverse insert index differs')
            parent.insert(key,copy.deepcopy(edit['before']))
        else:
            raise ValueError('word64 inverse operation differs')
    if restored != before:
        raise ValueError('word64 whole Core inverse differs')
    actual_counts = {'functions': len(after['functions']),
                     'blocks': sum(len(f['blocks']) for f in after['functions']),
                     'ops': sum(len(b['ops']) for f in after['functions'] for b in f['blocks'])}
    if actual_counts != {'functions':107,'blocks':1456,'ops':6347}:
        raise ValueError('word64 transformed Core inventory differs')
    if (after['functions'][0]['params'] != before['functions'][0]['params']
            or after['functions'][0]['returns'] != before['functions'][0]['returns']):
        raise ValueError('word64 changed the external buffer/u32 ABI')
    # Run the unchanged complete Core verifier on the new document. The
    # inverse log establishes provenance; it does not replace verification.
    verify_program(after)
    encode = lambda d: json.dumps(d,sort_keys=True,separators=(',',':')).encode()
    proof = {'schema':'hia.R9.private-word64-Core-projection.v1',
             'original_core_sha256':sha256(encode(before)).hexdigest(),
             'after_core_sha256':sha256(encode(after)).hexdigest(),
             'original_counts':counts,'after_counts':actual_counts,
             'fixed_word_bits':64,'external_f0_unchanged':True,
             'complete_original_Core_verifier_returned':True,
             'all_other_operations_kept_in_order':True,
             'whole_inverse_equal':True,'removed_identity_casts':removed,'edits':edits,
             'public_compiler_or_VM_changed':False,
             'machine_size_or_fuel_PASS_claim':False}
    return after,proof


# R10 private scalar-byte successor: all physical accesses remain in order.
BYTE_IO_R9_SOURCE_BYTES = 398741
BYTE_IO_R9_SOURCE_SHA256 = '2f271037fa0adfbc1875fc7759bdf058842db57e1dee591db8e84122f8cad4e7'
BYTE_IO_R9_COUNTS = {'functions': 107, 'blocks': 1456, 'ops': 6347}
BYTE_IO_AFTER_COUNTS = {'functions': 107, 'blocks': 1456, 'ops': 6299}


def _scalar_byte_trace(block, writing):
    """Normalize just the reviewed straight-line byte/word algebra.

    Each byte access is retained as an ordered event. Offset normalization is
    modulo 2**64; no bound on an input offset or word value is assumed.
    """
    expected_types = ['mutbuf', 'usize'] + (['usize'] if writing else [])
    if [p['type'] for p in block['params']] != expected_types:
        raise ValueError('scalar-byte block parameter types differ')
    env = {block['params'][0]['name']: ('buffer',),
           block['params'][1]['name']: ('offset', 0)}
    if writing:
        env[block['params'][2]['name']] = ('word-shift', 0)
    trace = []
    def constant(value):
        if value[0] != 'const' or type(value[1]) is not int:
            raise ValueError('scalar-byte expected one integer constant')
        return value[1]
    def packed(value):
        if value[0] != 'packed':
            raise ValueError('scalar-byte expected packed read bytes')
        return dict(value[1])
    for instruction in block['ops']:
        if set(instruction) != {'op', 'args', 'out', 'attrs'}:
            raise ValueError('scalar-byte operation shape differs')
        op, attrs, outputs = instruction['op'], instruction['attrs'], instruction['out']
        args = [env[name] for name in instruction['args']]
        value = None
        if op == 'const':
            if set(attrs) != {'value'} or type(attrs['value']) is not int:
                raise ValueError('scalar-byte constant differs')
            value = ('const', attrs['value'])
        elif op == 'int.add.wrap':
            if attrs or args[0][0] != 'offset':
                raise ValueError('scalar-byte offset operation differs')
            value = ('offset', (args[0][1] + constant(args[1])) % (1 << 64))
        elif op == 'buffer.load':
            if attrs or args[0] != ('buffer',) or args[1][0] != 'offset':
                raise ValueError('scalar-byte load differs')
            ordinal = sum(event[0] == 'load' for event in trace)
            trace.append(('load', args[1][1]))
            value = ('loaded-byte', ordinal)
        elif op == 'int.cast':
            if attrs != {'mode': 'wrap'} or len(outputs) != 1:
                raise ValueError('scalar-byte cast differs')
            target = outputs[0]['type']
            if target == 'usize' and args[0][0] == 'loaded-byte':
                value = ('packed', ((args[0][1], 0),))
            elif target == 'u8' and args[0][0] in ('word-shift', 'masked-byte'):
                value = ('write-byte', args[0][1])
            else:
                raise ValueError('scalar-byte unexpected cast domain')
        elif op == 'int.shl.checked':
            shift = constant(args[1])
            if attrs or not 0 <= shift < 64:
                raise ValueError('scalar-byte invalid left-shift count')
            terms = {index: position + shift for index, position in packed(args[0]).items()}
            if any(not 0 <= position <= 56 for position in terms.values()):
                raise ValueError('scalar-byte packed term exceeds its full word')
            value = ('packed', tuple(sorted(terms.items())))
        elif op == 'bit.or':
            if attrs:
                raise ValueError('scalar-byte or attrs differ')
            left, right = packed(args[0]), packed(args[1])
            positions = list(left.values()) + list(right.values())
            if set(left) & set(right) or any(abs(a-b) < 8 for i,a in enumerate(positions) for b in positions[i+1:]):
                raise ValueError('scalar-byte packed lanes overlap')
            value = ('packed', tuple(sorted(tuple(left.items()) + tuple(right.items()))))
        elif op == 'int.shr.checked':
            shift = constant(args[1])
            if attrs or args[0][0] != 'word-shift' or not 0 <= shift < 64:
                raise ValueError('scalar-byte right shift differs')
            total = args[0][1] + shift
            if total > 56:
                raise ValueError('scalar-byte right shift exceeds selected byte')
            value = ('word-shift', total)
        elif op == 'bit.and':
            if attrs or args[0][0] != 'word-shift' or constant(args[1]) != 255:
                raise ValueError('scalar-byte mask is not the exact low-byte mask')
            value = ('masked-byte', args[0][1])
        elif op == 'buffer.store':
            if (attrs or outputs or args[0] != ('buffer',)
                    or args[1][0] != 'offset' or args[2][0] != 'write-byte'):
                raise ValueError('scalar-byte store differs')
            trace.append(('store', args[1][1], args[2][1]))
        else:
            raise ValueError('scalar-byte unexpected operation: '+op)
        if value is not None:
            if len(outputs) != 1 or outputs[0]['name'] in env:
                raise ValueError('scalar-byte output is not fresh SSA')
            env[outputs[0]['name']] = value
    if block['term']['op'] != 'ret' or len(block['term']['values']) != 1:
        raise ValueError('scalar-byte terminator differs')
    return {'accesses': trace, 'returned_value': env[block['term']['values'][0]]}


def _scalar_byte_operations(params, width, writing):
    """Emit full-width operations; never omit or widen a physical byte access."""
    operations = []
    next_value = max(int(p['name'][1:]) for p in params) + 1
    constants = {}
    def operation(name, args, typ=None, attrs=None):
        nonlocal next_value
        outputs = []
        if typ is not None:
            result = 'v'+str(next_value)
            next_value += 1
            outputs = [{'name': result, 'type': typ}]
        operations.append({'op': name, 'args': list(args), 'out': outputs, 'attrs': dict(attrs or {})})
        return outputs[0]['name'] if outputs else None
    def constant(value):
        if value not in constants:
            constants[value] = operation('const', [], 'usize', {'value': value})
        return constants[value]
    storage, offset = (p['name'] for p in params[:2])
    if writing:
        value = params[2]['name']
        for index in range(width):
            byte_value = operation('int.cast', [value], 'u8', {'mode': 'wrap'})
            operation('buffer.store', [storage, offset, byte_value])
            if index+1 < width:
                offset = operation('int.add.wrap', [offset, constant(1)], 'usize')
                value = operation('int.shr.checked', [value, constant(8)], 'usize')
        result = constant(0)
    else:
        values = []
        for index in range(width):
            if index:
                offset = operation('int.add.wrap', [offset, constant(1)], 'usize')
            byte_value = operation('buffer.load', [storage, offset], 'u8')
            values.append(operation('int.cast', [byte_value], 'usize', {'mode': 'wrap'}))
        result = values[-1]
        for value in reversed(values[:-1]):
            result = operation('int.shl.checked', [result, constant(8)], 'usize')
            result = operation('bit.or', [result, value], 'usize')
    return operations, {'op': 'ret', 'values': [result]}


def _scalar_byte_core_document(original):
    """Change five exact scalar helpers, retaining every ordered byte effect."""
    from hepta.hia_opcodes import WIDTHS
    from hepta.hia_program import verify_program
    if WIDTHS['usize'] != 64 or WIDTHS['u8'] != 8:
        raise ValueError('scalar-byte primitive widths differ')
    before = copy.deepcopy(original)
    def counts(value):
        return {'functions': len(value['functions']),
                'blocks': sum(len(f['blocks']) for f in value['functions']),
                'ops': sum(len(b['ops']) for f in value['functions'] for b in f['blocks'])}
    raw = render_assembly(before).encode()
    if (len(raw) != BYTE_IO_R9_SOURCE_BYTES or sha256(raw).hexdigest() != BYTE_IO_R9_SOURCE_SHA256
            or counts(before) != BYTE_IO_R9_COUNTS
            or [f['name'] for f in before['functions']] != ['f'+str(i) for i in range(107)]):
        raise ValueError('scalar-byte exact actual R9 preimage differs')
    after = copy.deepcopy(before)
    edits, proofs = [], []
    def replace(path, value):
        parent = after
        for key in path[:-1]:
            parent = parent[key]
        key = path[-1]
        old = copy.deepcopy(parent[key])
        edits.append({'path': path, 'before': old, 'after': copy.deepcopy(value)})
        parent[key] = copy.deepcopy(value)
    targets = ((22, 8, True), (23, 8, False), (24, 4, True), (25, 4, False))
    for fi, width, writing in targets:
        function = before['functions'][fi]
        if (len(function['blocks']) != 1 or function['entry'] != function['blocks'][0]['id']
                or function['params'] != function['blocks'][0]['params']
                or function['returns'] != ['usize']):
            raise ValueError('scalar-byte exact leaf function shape differs')
        block = function['blocks'][0]
        operations, term = _scalar_byte_operations(block['params'], width, writing)
        replace(['functions', fi, 'blocks', 0, 'ops'], operations)
        replace(['functions', fi, 'blocks', 0, 'term'], term)
        old_trace = _scalar_byte_trace(block, writing)
        new_trace = _scalar_byte_trace(after['functions'][fi]['blocks'][0], writing)
        expected = ([('store', i, 8*i) for i in range(width)] if writing
                    else [('load', i) for i in range(width)])
        if old_trace != new_trace or old_trace['accesses'] != expected:
            raise ValueError('scalar-byte ordered effects or return differ')
        proofs.append({'function': function['name'], 'width_bytes': width, 'writing': writing,
                       'before_ops': len(block['ops']), 'after_ops': len(operations),
                       'normalized_trace': old_trace, 'equal': True})
    # cp16's refusal/first-error path is left completely untouched. Only the
    # already-existing low-byte mask in its successful store block is removed.
    fi = 92
    function = before['functions'][fi]
    if (len(function['blocks']) != 3 or function['entry'] != 'b0'
            or [b['id'] for b in function['blocks']] != ['b0', 'b1', 'b2']):
        raise ValueError('scalar-byte cp16 CFG differs')
    block = function['blocks'][2]
    params = block['params']
    if [p['type'] for p in params] != ['mutbuf', 'usize', 'usize']:
        raise ValueError('scalar-byte cp16 success parameters differ')
    operations = copy.deepcopy(block['ops'])
    mask_constants = [op for op in operations if op['op'] == 'const' and op['attrs'] == {'value': 255}]
    if len(mask_constants) != 1:
        raise ValueError('scalar-byte cp16 mask constant differs')
    mask_constant = mask_constants[0]
    mask_name = mask_constant['out'][0]['name']
    masks = [op for op in operations if op['op'] == 'bit.and'
             and op['args'] == [params[2]['name'], mask_name] and op['attrs'] == {}]
    if len(masks) != 1:
        raise ValueError('scalar-byte cp16 mask site differs')
    mask = masks[0]
    masked_name = mask['out'][0]['name']
    uses = [op for op in operations if masked_name in op['args']]
    if (len(uses) != 1 or uses[0]['op'] != 'int.cast' or uses[0]['args'] != [masked_name]
            or uses[0]['out'][0]['type'] != 'u8' or uses[0]['attrs'] != {'mode': 'wrap'}
            or sum(mask_name in op['args'] for op in operations) != 1):
        raise ValueError('scalar-byte cp16 low-byte use differs')
    operations = [op for op in operations if op not in (mask_constant, mask)]
    for op in operations:
        op['args'] = [params[2]['name'] if name == masked_name else name for name in op['args']]
    replace(['functions', fi, 'blocks', 2, 'ops'], operations)
    old_trace = _scalar_byte_trace(block, True)
    new_trace = _scalar_byte_trace(after['functions'][fi]['blocks'][2], True)
    if (old_trace != new_trace or old_trace['accesses'] != [('store', 0, 0), ('store', 1, 8)]
            or before['functions'][fi]['blocks'][:2] != after['functions'][fi]['blocks'][:2]):
        raise ValueError('scalar-byte cp16 effects or error path differ')
    proofs.append({'function': 'f92', 'width_bytes': 2, 'writing': True,
                   'before_ops': len(block['ops']), 'after_ops': len(operations),
                   'normalized_trace': old_trace, 'equal': True,
                   'complete_refusal_and_first_error_blocks_unchanged': True})
    restored = copy.deepcopy(after)
    for edit in reversed(edits):
        parent = restored
        for key in edit['path'][:-1]:
            parent = parent[key]
        key = edit['path'][-1]
        if parent[key] != edit['after']:
            raise ValueError('scalar-byte inverse preimage differs')
        parent[key] = copy.deepcopy(edit['before'])
    if restored != before or counts(after) != BYTE_IO_AFTER_COUNTS:
        raise ValueError('scalar-byte whole inverse or counts differ')
    selected = {22, 23, 24, 25, 92}
    if any(after['functions'][i] != before['functions'][i] for i in range(107) if i not in selected):
        raise ValueError('scalar-byte changed an unselected function')
    for fi in selected:
        if {k:v for k,v in after['functions'][fi].items() if k != 'blocks'} != {
                k:v for k,v in before['functions'][fi].items() if k != 'blocks'}:
            raise ValueError('scalar-byte changed a function ABI or annotation')
    verify_program(after)
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return after, {'schema': 'hia.R10.private-scalar-byte-Core-projection.v1',
                   'original_counts': counts(before), 'after_counts': counts(after),
                   'original_core_sha256': sha256(encode(before)).hexdigest(),
                   'after_core_sha256': sha256(encode(after)).hexdigest(),
                   'full_word_bits': 64, 'ordered_full_byte_effects_equal': True,
                   'new_field_range_or_initialization_assumption': False,
                   'refusal_branch_unchanged': True, 'all_102_other_functions_unchanged': True,
                   'external_f0_and_all_function_ABIs_unchanged': True,
                   'whole_inverse_equal': True, 'edits': edits, 'helpers': proofs,
                   'complete_original_Core_verifier_returned': True,
                   'public_compiler_or_VM_changed': False, 'machine_size_or_fuel_PASS_claim': False}

ASCII_GUARD_EXPECTED_BLOCKS = [{'function_index': 16, 'block_id': 'b7', 'kind': 'delimiter', 'kept_prefix_ops': 2, 'character': 'v99', 'index': None, 'result_name': 'v134', 'block': {'id': 'b7', 'params': [{'name': 'v83', 'type': 'readbuf'}, {'name': 'v84', 'type': 'mutbuf'}, {'name': 'v85', 'type': 'usize'}, {'name': 'v86', 'type': 'usize'}, {'name': 'v89', 'type': 'usize'}, {'name': 'v90', 'type': 'usize'}], 'ops': [{'op': 'buffer.load', 'args': ['v83', 'v85'], 'out': [{'name': 'v98', 'type': 'u8'}], 'attrs': {}}, {'op': 'int.cast', 'args': ['v98'], 'out': [{'name': 'v99', 'type': 'usize'}], 'attrs': {'mode': 'wrap'}}, {'op': 'const', 'args': [], 'out': [{'name': 'v100', 'type': 'usize'}], 'attrs': {'value': 10}}, {'op': 'compare.eq', 'args': ['v99', 'v100'], 'out': [{'name': 'v101', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v102', 'type': 'usize'}], 'attrs': {'value': 40}}, {'op': 'compare.eq', 'args': ['v99', 'v102'], 'out': [{'name': 'v103', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v101', 'v103'], 'out': [{'name': 'v104', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v105', 'type': 'usize'}], 'attrs': {'value': 41}}, {'op': 'compare.eq', 'args': ['v99', 'v105'], 'out': [{'name': 'v106', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v104', 'v106'], 'out': [{'name': 'v107', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v108', 'type': 'usize'}], 'attrs': {'value': 44}}, {'op': 'compare.eq', 'args': ['v99', 'v108'], 'out': [{'name': 'v109', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v107', 'v109'], 'out': [{'name': 'v110', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v111', 'type': 'usize'}], 'attrs': {'value': 58}}, {'op': 'compare.eq', 'args': ['v99', 'v111'], 'out': [{'name': 'v112', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v110', 'v112'], 'out': [{'name': 'v113', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v114', 'type': 'usize'}], 'attrs': {'value': 61}}, {'op': 'compare.eq', 'args': ['v99', 'v114'], 'out': [{'name': 'v115', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v113', 'v115'], 'out': [{'name': 'v116', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v117', 'type': 'usize'}], 'attrs': {'value': 123}}, {'op': 'compare.eq', 'args': ['v99', 'v117'], 'out': [{'name': 'v118', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v116', 'v118'], 'out': [{'name': 'v119', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v120', 'type': 'usize'}], 'attrs': {'value': 125}}, {'op': 'compare.eq', 'args': ['v99', 'v120'], 'out': [{'name': 'v121', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v119', 'v121'], 'out': [{'name': 'v122', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v123', 'type': 'usize'}], 'attrs': {'value': 45}}, {'op': 'compare.eq', 'args': ['v99', 'v123'], 'out': [{'name': 'v124', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v122', 'v124'], 'out': [{'name': 'v125', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v126', 'type': 'usize'}], 'attrs': {'value': 62}}, {'op': 'compare.eq', 'args': ['v99', 'v126'], 'out': [{'name': 'v127', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v125', 'v127'], 'out': [{'name': 'v128', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v129', 'type': 'usize'}], 'attrs': {'value': 91}}, {'op': 'compare.eq', 'args': ['v99', 'v129'], 'out': [{'name': 'v130', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v128', 'v130'], 'out': [{'name': 'v131', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v132', 'type': 'usize'}], 'attrs': {'value': 93}}, {'op': 'compare.eq', 'args': ['v99', 'v132'], 'out': [{'name': 'v133', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v131', 'v133'], 'out': [{'name': 'v134', 'type': 'bool'}], 'attrs': {}}], 'term': {'op': 'branch', 'cond': 'v134', 'then': {'target': 'b8', 'args': ['v83', 'v84', 'v85', 'v99']}, 'else': {'target': 'b9', 'args': ['v83', 'v84', 'v85', 'v86', 'v99', 'v89', 'v90']}}}}, {'function_index': 79, 'block_id': 'b4', 'kind': 'identifier', 'kept_prefix_ops': 3, 'character': 'v62', 'index': 'v46', 'result_name': 'v88', 'block': {'id': 'b4', 'params': [{'name': 'v41', 'type': 'readbuf'}, {'name': 'v42', 'type': 'mutbuf'}, {'name': 'v44', 'type': 'usize'}, {'name': 'v45', 'type': 'usize'}, {'name': 'v46', 'type': 'usize'}, {'name': 'v47', 'type': 'usize'}], 'ops': [{'op': 'int.add.wrap', 'args': ['v44', 'v46'], 'out': [{'name': 'v59', 'type': 'usize'}], 'attrs': {}}, {'op': 'buffer.load', 'args': ['v41', 'v59'], 'out': [{'name': 'v61', 'type': 'u8'}], 'attrs': {}}, {'op': 'int.cast', 'args': ['v61'], 'out': [{'name': 'v62', 'type': 'usize'}], 'attrs': {'mode': 'wrap'}}, {'op': 'const', 'args': [], 'out': [{'name': 'v63', 'type': 'usize'}], 'attrs': {'value': 0}}, {'op': 'const', 'args': [], 'out': [{'name': 'v64', 'type': 'usize'}], 'attrs': {'value': 65}}, {'op': 'compare.ge', 'args': ['v62', 'v64'], 'out': [{'name': 'v65', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v66', 'type': 'usize'}], 'attrs': {'value': 90}}, {'op': 'compare.le', 'args': ['v62', 'v66'], 'out': [{'name': 'v67', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.and', 'args': ['v65', 'v67'], 'out': [{'name': 'v68', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v69', 'type': 'usize'}], 'attrs': {'value': 97}}, {'op': 'compare.ge', 'args': ['v62', 'v69'], 'out': [{'name': 'v70', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v71', 'type': 'usize'}], 'attrs': {'value': 122}}, {'op': 'compare.le', 'args': ['v62', 'v71'], 'out': [{'name': 'v72', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.and', 'args': ['v70', 'v72'], 'out': [{'name': 'v73', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v68', 'v73'], 'out': [{'name': 'v74', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v75', 'type': 'usize'}], 'attrs': {'value': 95}}, {'op': 'compare.eq', 'args': ['v62', 'v75'], 'out': [{'name': 'v76', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.or', 'args': ['v74', 'v76'], 'out': [{'name': 'v77', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v78', 'type': 'usize'}], 'attrs': {'value': 1}}, {'op': 'select', 'args': ['v77', 'v78', 'v63'], 'out': [{'name': 'v79', 'type': 'usize'}], 'attrs': {}}, {'op': 'compare.ne', 'args': ['v46', 'v63'], 'out': [{'name': 'v80', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v81', 'type': 'usize'}], 'attrs': {'value': 48}}, {'op': 'compare.ge', 'args': ['v62', 'v81'], 'out': [{'name': 'v82', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.and', 'args': ['v80', 'v82'], 'out': [{'name': 'v83', 'type': 'bool'}], 'attrs': {}}, {'op': 'const', 'args': [], 'out': [{'name': 'v84', 'type': 'usize'}], 'attrs': {'value': 57}}, {'op': 'compare.le', 'args': ['v62', 'v84'], 'out': [{'name': 'v85', 'type': 'bool'}], 'attrs': {}}, {'op': 'bool.and', 'args': ['v83', 'v85'], 'out': [{'name': 'v86', 'type': 'bool'}], 'attrs': {}}, {'op': 'select', 'args': ['v86', 'v78', 'v79'], 'out': [{'name': 'v87', 'type': 'usize'}], 'attrs': {}}, {'op': 'compare.eq', 'args': ['v87', 'v63'], 'out': [{'name': 'v88', 'type': 'bool'}], 'attrs': {}}], 'term': {'op': 'branch', 'cond': 'v88', 'then': {'target': 'b6', 'args': ['v41', 'v42']}, 'else': {'target': 'b7', 'args': ['v41', 'v42', 'v44', 'v45', 'v46', 'v47', 'v62']}}}}]

# R11: two exact, effect-free ASCII predicates after the unchanged byte loads.
ASCII_GUARD_R10_SOURCE_BYTES = 397114
ASCII_GUARD_R10_SOURCE_SHA256 = 'be5c71d43ecdd7178b9c3f1016cd1dc8aa98d1b1003b256a6870d0d32150894b'
ASCII_GUARD_R10_COUNTS = {'functions': 107, 'blocks': 1456, 'ops': 6299}
ASCII_GUARD_AFTER_COUNTS = {'functions': 107, 'blocks': 1456, 'ops': 6270}
ASCII_GUARD_DELIMITERS = (10, 40, 41, 44, 58, 61, 123, 125, 45, 62, 91, 93)


def _ascii_guard_operations(kind, character, index, names, result_name):
    """Emit only total scalar operations; no field, cursor or buffer assumptions."""
    operations = []
    pool = iter(names)
    used = set()
    def operation(op, args, typ, attrs=None, final=False):
        name = result_name if final else next(pool)
        if name in used or (not final and name == result_name):
            raise ValueError('ASCII predicate output identity differs')
        used.add(name)
        operations.append({'op': op, 'args': list(args), 'out': [{'name': name, 'type': typ}],
                           'attrs': dict(attrs or {})})
        return name
    def constant(value):
        return operation('const', [], 'usize', {'value': value})
    if kind == 'delimiter':
        low_mask = sum(1 << c for c in ASCII_GUARD_DELIMITERS if c < 64)
        high_mask = sum(1 << (c - 64) for c in ASCII_GUARD_DELIMITERS if c >= 64)
        lower_half = operation('compare.lt', [character, constant(64)], 'bool')
        mask = operation('select', [lower_half, constant(low_mask), constant(high_mask)], 'usize')
        count = operation('bit.and', [character, constant(63)], 'usize')
        shifted = operation('int.shr.checked', [mask, count], 'usize')
        one = constant(1)
        selected = operation('bit.and', [shifted, one], 'usize')
        member = operation('compare.eq', [selected, one], 'bool')
        ascii_range = operation('compare.lt', [character, constant(128)], 'bool')
        operation('bool.and', [ascii_range, member], 'bool', final=True)
    elif kind == 'identifier':
        folded = operation('bit.or', [character, constant(32)], 'usize')
        letter_delta = operation('int.sub.wrap', [folded, constant(97)], 'usize')
        letter = operation('compare.lt', [letter_delta, constant(26)], 'bool')
        underscore = operation('compare.eq', [character, constant(95)], 'bool')
        head = operation('bool.or', [letter, underscore], 'bool')
        digit_delta = operation('int.sub.wrap', [character, constant(48)], 'usize')
        digit = operation('compare.lt', [digit_delta, constant(10)], 'bool')
        not_first = operation('compare.ne', [index, constant(0)], 'bool')
        tail_digit = operation('bool.and', [not_first, digit], 'bool')
        allowed = operation('bool.or', [head, tail_digit], 'bool')
        operation('bool.not', [allowed], 'bool', final=True)
    else:
        raise ValueError('unknown private ASCII predicate')
    return operations


def _ascii_guard_value(operations, initial):
    """A closed scalar evaluator for the finite certificate, never a buffer VM."""
    values = dict(initial)
    mask = (1 << 64) - 1
    for instruction in operations:
        if set(instruction) != {'op', 'args', 'out', 'attrs'} or len(instruction['out']) != 1:
            raise ValueError('ASCII predicate operation shape differs')
        op, attrs = instruction['op'], instruction['attrs']
        args = [values[name] for name in instruction['args']]
        if op == 'const':
            if args or set(attrs) != {'value'} or type(attrs['value']) is not int or not 0 <= attrs['value'] <= mask:
                raise ValueError('ASCII predicate constant differs')
            value = attrs['value']
        else:
            if attrs:
                raise ValueError('ASCII predicate scalar attrs differ')
            if op == 'bit.and': value = args[0] & args[1]
            elif op == 'bit.or': value = args[0] | args[1]
            elif op == 'int.sub.wrap': value = (args[0] - args[1]) & mask
            elif op == 'int.shr.checked':
                if not 0 <= args[1] < 64:
                    raise ValueError('ASCII predicate introduced an invalid shift')
                value = args[0] >> args[1]
            elif op == 'compare.lt': value = args[0] < args[1]
            elif op == 'compare.le': value = args[0] <= args[1]
            elif op == 'compare.gt': value = args[0] > args[1]
            elif op == 'compare.ge': value = args[0] >= args[1]
            elif op == 'compare.eq': value = args[0] == args[1]
            elif op == 'compare.ne': value = args[0] != args[1]
            elif op == 'bool.and': value = args[0] and args[1]
            elif op == 'bool.or': value = args[0] or args[1]
            elif op == 'bool.not': value = not args[0]
            elif op == 'select': value = args[1] if args[0] else args[2]
            else: raise ValueError('ASCII predicate contains a non-total scalar operation: ' + op)
        output = instruction['out'][0]
        if (set(output) != {'name', 'type'} or output['name'] in values
                or output['type'] not in ('usize', 'bool')
                or (output['type'] == 'bool' and type(value) is not bool)
                or (output['type'] == 'usize' and (type(value) is not int or not 0 <= value <= mask))):
            raise ValueError('ASCII predicate result type or freshness differs')
        values[output['name']] = value
    return values


def _ascii_guard_certificate(kind, old, new, character, index, result_name):
    """Finite bytes plus an explicit whole-u64-domain algebraic certificate.

    Both actual characters are unchanged u8->usize casts. The stronger proof
    also covers every u64 character: delimiter has a final c<128 guard and
    its sole shift count is c&63; identifier's folded interval is exactly
    97..122, and its wrapped digit interval is exactly 48..57. Index is used
    only through index!=0. No cursor or initialization bound is introduced.
    """
    byte_cases = 0
    boundary_cases = 0
    upper = (1 << 64) - 1
    boundaries = (0, 1, 9, 10, 31, 32, 39, 40, 41, 44, 45, 46, 47, 48, 57, 58,
                  61, 62, 63, 64, 65, 90, 91, 93, 94, 95, 96, 97, 122, 123,
                  125, 126, 127, 128, 255, 256, 65535, 65536,
                  (1 << 32) - 1, 1 << 32, (1 << 63) - 1, 1 << 63, upper - 1, upper)
    indices = (0,) if index is None else (0, 1, upper)
    for c in tuple(range(256)) + boundaries:
        for i in indices:
            initial = {character: c}
            if index is not None:
                initial[index] = i
            left = _ascii_guard_value(old, initial)[result_name]
            right = _ascii_guard_value(new, initial)[result_name]
            if kind == 'delimiter':
                expected = c in ASCII_GUARD_DELIMITERS
            else:
                expected = not (65 <= c <= 90 or 97 <= c <= 122 or c == 95
                                or (i != 0 and 48 <= c <= 57))
            if left is not expected or right is not expected:
                raise ValueError('ASCII predicate finite equivalence differs')
            if c < 256:
                byte_cases += 1
            else:
                boundary_cases += 1
    return {'kind': kind, 'all_256_byte_values_checked': True,
            'index_classes': ['zero'] if index is None else ['zero', 'nonzero'],
            'finite_evaluations_per_side': byte_cases + boundary_cases,
            'all_u64_character_boundary_controls_equal': True,
            'full_u64_algebra':
              ('c>=128 forces false; c<128 exhaustively checked; shift=c&63 always 0..63'
               if kind == 'delimiter' else
               '(c|32)-97 modulo 2**64 <26 iff 65<=c<=90 or 97<=c<=122; '
               '(c-48) modulo 2**64 <10 iff 48<=c<=57; index is tested only for zero'),
            'new_buffer_accesses': 0, 'new_calls': 0, 'new_effects_or_traps': False,
            'before_pure_ops': len(old), 'after_pure_ops': len(new)}


def _ascii_guard_core_document(original):
    """Project exactly two scalar slices; keep all reads/writes and CFG edges."""
    from hepta.hia_opcodes import WIDTHS
    from hepta.hia_program import verify_program
    if WIDTHS['usize'] != 64 or WIDTHS['u8'] != 8:
        raise ValueError('ASCII predicate requires the actual fixed 64-bit word domain')
    def counts(value):
        return {'functions': len(value['functions']),
                'blocks': sum(len(f['blocks']) for f in value['functions']),
                'ops': sum(len(b['ops']) for f in value['functions'] for b in f['blocks'])}
    before = copy.deepcopy(original)
    raw = render_assembly(before).encode()
    if (len(raw) != ASCII_GUARD_R10_SOURCE_BYTES
            or sha256(raw).hexdigest() != ASCII_GUARD_R10_SOURCE_SHA256
            or counts(before) != ASCII_GUARD_R10_COUNTS
            or [f['name'] for f in before['functions']] != ['f'+str(i) for i in range(107)]):
        raise ValueError('ASCII predicate exact actual R10 Core preimage differs')
    after = copy.deepcopy(before)
    edits, proofs = [], []
    for spec in ASCII_GUARD_EXPECTED_BLOCKS:
        fi, block_id, prefix = spec['function_index'], spec['block_id'], spec['kept_prefix_ops']
        blocks = before['functions'][fi]['blocks']
        matches = [i for i, block in enumerate(blocks) if block['id'] == block_id]
        if len(matches) != 1:
            raise ValueError('ASCII predicate exact block identity differs')
        bi = matches[0]
        block = blocks[bi]
        if block != spec['block']:
            raise ValueError('ASCII predicate complete block preimage differs')
        old = block['ops'][prefix:]
        result_name = spec['result_name']
        names = [op['out'][0]['name'] for op in old if op['out'][0]['name'] != result_name]
        new = _ascii_guard_operations(spec['kind'], spec['character'], spec['index'], names, result_name)
        certificate = _ascii_guard_certificate(spec['kind'], old, new, spec['character'],
                                               spec['index'], result_name)
        new_operations = copy.deepcopy(block['ops'][:prefix]) + new
        path = ['functions', fi, 'blocks', bi, 'ops']
        edits.append({'path': path, 'before': copy.deepcopy(block['ops']),
                      'after': copy.deepcopy(new_operations)})
        after['functions'][fi]['blocks'][bi]['ops'] = new_operations
        proofs.append(dict(certificate, function=before['functions'][fi]['name'], block=block_id,
                           unchanged_prefix_ops=prefix, terminator_unchanged=True))
    restored = copy.deepcopy(after)
    for edit in reversed(edits):
        parent = restored
        for key in edit['path'][:-1]:
            parent = parent[key]
        key = edit['path'][-1]
        if parent[key] != edit['after']:
            raise ValueError('ASCII predicate inverse preimage differs')
        parent[key] = copy.deepcopy(edit['before'])
    if restored != before or counts(after) != ASCII_GUARD_AFTER_COUNTS:
        raise ValueError('ASCII predicate whole inverse or Core counts differ')
    if any(after['functions'][i] != before['functions'][i] for i in range(107) if i not in (16, 79)):
        raise ValueError('ASCII predicate changed an unselected function')
    verify_program(after)
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return after, {'schema': 'hia.R11.private-ASCII-predicate-Core-projection.v1',
                   'original_counts': counts(before), 'after_counts': counts(after),
                   'original_core_sha256': sha256(encode(before)).hexdigest(),
                   'after_core_sha256': sha256(encode(after)).hexdigest(),
                   'full_word_bits': 64, 'all_byte_loads_and_casts_unchanged': True,
                   'all_calls_stores_hashes_and_error_branches_unchanged': True,
                   'all_105_other_functions_unchanged': True,
                   'all_function_and_block_ABIs_and_terminators_unchanged': True,
                   'new_range_or_initialization_assumption': False,
                   'whole_inverse_equal': True, 'edits': edits, 'predicates': proofs,
                   'complete_original_Core_verifier_returned': True,
                   'public_compiler_or_VM_changed': False, 'machine_size_or_fuel_PASS_claim': False}


def document():
    namespace = dict(compiler.document.__globals__, source_program=source_program, Builder=DenseReplayBuilder)
    method = FunctionType(compiler.document.__code__, namespace, compiler.document.__name__)
    method.__kwdefaults__ = compiler.document.__kwdefaults__
    doc, _ = method()
    doc['module'] = 'file_render_checker_v4'
    baseline = render_assembly(doc).encode()
    if (len(baseline) != WORD64_BASE_SOURCE_BYTES
            or sha256(baseline).hexdigest() != WORD64_BASE_SOURCE_SHA256):
        raise ValueError('word64 original rendered R8 bytes differ')
    doc, word64_proof = _word64_core_document(doc)
    doc, scalar_byte_proof = _scalar_byte_core_document(doc)
    doc, ascii_guard_proof = _ascii_guard_core_document(doc)
    counts = {'functions': len(doc['functions']), 'blocks': sum(len(f['blocks']) for f in doc['functions']),
              'ops': sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])}
    if counts['functions'] > 128 or counts['blocks'] > 1536 or counts['ops'] > 8192:
        raise ValueError('compact resident exceeds unchanged compiler author limits: ' + repr(counts))
    return doc, dict(counts, word64_projection=word64_proof, scalar_byte_projection=scalar_byte_proof, ascii_predicate_projection=ascii_guard_proof)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    program, report = expanded()
    doc, counts = document()
    raw = render_assembly(doc).encode()
    if args.check:
        if (ROOT / SOURCE).read_bytes() != raw:
            raise ValueError('compact semantic resident differs')
    else:
        (ROOT / SOURCE).write_bytes(raw)
    report.update(generated=counts, source_bytes=len(raw), source_sha256=sha256(raw).hexdigest(),
                  author_source_sha256=sha256(program.encode()).hexdigest())
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('generated', 'source_bytes', 'source_sha256', 'workspace_last_end')}))

if __name__ == '__main__':
    main()
