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

SOURCE = 'examples/hia_bootstrap/file_render_checker_v4.hepta'
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
    program = '\n\n'.join(ast.unparse(n) for n in module.body if n.name in live) + '\n'
    forbidden = {'FBASE', 'BBASE', 'VBASE', 'CAPBASE', 'KBASE', 'ORIGINBASE', 'BLOCKORIGIN', 'FIXBASE'}
    dangling = sorted({n.id for n in ast.walk(ast.parse(program)) if isinstance(n, ast.Name)} & forbidden)
    if dangling:
        raise ValueError('unmapped old workspace symbols: ' + repr(dangling))
    return program, {'exact_parent': PARENT_EXPANDED, 'access_projection': access_log,
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

def document():
    namespace = dict(compiler.document.__globals__, source_program=source_program)
    method = FunctionType(compiler.document.__code__, namespace, compiler.document.__name__)
    method.__kwdefaults__ = compiler.document.__kwdefaults__
    doc, _ = method()
    doc['module'] = 'file_render_checker_v4'
    counts = {'functions': len(doc['functions']), 'blocks': sum(len(f['blocks']) for f in doc['functions']),
              'ops': sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])}
    if counts['functions'] > 128 or counts['blocks'] > 1536 or counts['ops'] > 8192:
        raise ValueError('compact resident exceeds unchanged compiler author limits: ' + repr(counts))
    return doc, counts

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
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
    if args.report is not None:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('generated', 'source_bytes', 'source_sha256', 'workspace_last_end')}))

if __name__ == '__main__':
    main()
