"""Pinned x86 decoding and register-only symbolic formulas from HIA."""
from __future__ import annotations

import ctypes
from functools import lru_cache
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_safe_core_x64 import Instruction, SafeCoreMachineRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/safe_core_x64_decode.hepta')
SCHEMA = 'hepta.hia.safe-core-x64-decode-native.v1'
SELECTOR = 'HEPTA_HIA_SAFE_CORE_X64_DECODE_MANIFEST'
MAX_TEXT = 65536
MAX_INSTRUCTIONS = 8192
WORKSPACE = 128 + MAX_TEXT
HEADER = struct.Struct('<3Q')
ROW = struct.Struct('<6Q')
CALL_COUNT = struct.Struct('<Q')
CALL_BINDING = struct.Struct('<3Q')
MEMORY_REQUEST = struct.Struct('<5Q')
SCHEDULER_REQUEST = struct.Struct('<4Q')
SCHEDULER_REPLY = struct.Struct('<3Q')
# One bit per decoded instruction per pending ancestry. Each fork keeps a
# separate native snapshot, instead of sharing a mutable visited set.
SCHEDULER_HEADER = 64
SCHEDULER_FRAMES = MAX_INSTRUCTIONS + 1
SCHEDULER_BITMAP = MAX_INSTRUCTIONS // 8
SCHEDULER_VISITS = SCHEDULER_HEADER + SCHEDULER_FRAMES * 8
SCHEDULER_WORKSPACE = SCHEDULER_VISITS + SCHEDULER_FRAMES * SCHEDULER_BITMAP
SCHEDULER_LIVE = 1
SCHEDULER_EXECUTE = 2
SCHEDULER_REFUSALS = {
    3: 'machine path budget exceeded',
    4: 'machine execution budget exceeded',
    5: 'unknown instruction entry, machine cycle or recursion',
}
OPERATIONS = (
    ('push', ('u',)), ('pop', ('u',)), ('imm', ('u', 'u')), ('ret', ()),
    ('leave', ()), ('nop', ()), ('call', ('i',)), ('jmp', ('i',)),
    ('jcc', ('u', 'i')), ('setcc', ('u', 'u')), ('cmovne', ('u', 'u')),
    ('imul', ('u', 'u')), ('load8', ('u', 'u', 'i')), ('ud2', ()),
    ('store8', ('u', 'i', 'u')), ('mov', ('u', 'u')), ('store', ('u', 'i', 'u')),
    ('load', ('u', 'u', 'i')), ('lea', ('u', 'u', 'i')),
    ('add', ('u', 'u')), ('sub', ('u', 'u')), ('and', ('u', 'u')), ('or', ('u', 'u')),
    ('xor', ('u', 'u')), ('cmp', ('u', 'u')), ('test', ('u', 'u')),
    ('immediate_alu', ('a', 'u', 'i')), ('shl', ('u', 'u')), ('shr', ('u', 'u')),
    ('not', ('u',)),
)
OPERATION_IDS = {name: code for code, (name, _) in enumerate(OPERATIONS, 1)}
RECIPE_REQUEST = struct.Struct('<2Q')
RECIPE_HEADER = struct.Struct('<5Q')
RECIPE_NODE = struct.Struct('<4Q')
MAX_RECIPE_NODES = 12
RECIPE_INPUTS = 5
# Only generic bit-vector/Boolean primitives cross this ABI. HIA supplies
# their composition and selects which architectural observations change.
RECIPE_PRIMITIVES = {
    'add': ('rr', lambda z, ctx, a, b: a + b),
    'sub': ('rr', lambda z, ctx, a, b: a - b),
    'and': ('rr', lambda z, ctx, a, b: a & b),
    'or': ('rr', lambda z, ctx, a, b: a | b),
    'xor': ('rr', lambda z, ctx, a, b: a ^ b),
    'not': ('r', lambda z, ctx, a: ~a),
    'imul': ('rr', lambda z, ctx, a, b: a * b),
    'ne': ('rr', lambda z, ctx, a, b: a != b),
    'ult': ('rr', lambda z, ctx, a, b: z.ULT(a, b)),
    'zero': ('r', lambda z, ctx, a: a == 0),
    'one': ('r', lambda z, ctx, a: a == 1),
    'false': ('', lambda z, ctx: z.BoolVal(False, ctx=ctx)),
    'bool_not': ('r', lambda z, ctx, a: z.Not(a)),
    'bool_or': ('rr', lambda z, ctx, a, b: z.Or(a, b)),
    'bool_and': ('rr', lambda z, ctx, a, b: z.And(a, b)),
    'choose': ('rrr', lambda z, ctx, a, b, c: z.If(a, b, c)),
    'signext': ('ri', lambda z, ctx, a, bits: z.SignExt(bits, a)),
    'extract': ('rii', lambda z, ctx, a, high, low: z.Extract(high, low, a)),
    'shl': ('ri', lambda z, ctx, a, bits: a << bits),
    'lshr': ('ri', lambda z, ctx, a, bits: z.LShR(a, bits)),
    'literal64': ('i', lambda z, ctx, number: z.BitVecVal(number, 64, ctx=ctx)),
    'simplify': ('r', lambda z, ctx, a: z.simplify(a)),
}
RECIPE_LAYOUT = tuple(RECIPE_PRIMITIVES.values())
RECIPE_IDS = {name: code for code, name in enumerate(RECIPE_PRIMITIVES, 1)}
ALU_GROUPS = {0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp'}
REFUSALS = (
    ('text_budget', 'machine text budget exceeded'),
    ('truncated', 'truncated machine instruction'),
    ('indexed', 'indexed memory addressing is outside the profile'),
    ('mode', 'only register or explicit base/disp32 addressing is admitted'),
    ('sib', 'unknown SIB addressing'),
    ('stack_prefix', 'unreviewed stack instruction prefix'),
    ('imm_prefix', 'unreviewed immediate prefix'),
    ('single_prefix', 'unreviewed single-byte prefix'),
    ('branch_prefix', 'unreviewed direct branch prefix'),
    ('conditional_prefix', 'unreviewed conditional branch prefix'),
    ('setcc', 'unreviewed SETcc byte register'),
    ('cmovne', 'only 64-bit register-register CMOVNE is admitted'),
    ('imul', 'only 64-bit register-register IMUL is admitted'),
    ('load8', 'unreviewed zero-extending byte load'),
    ('ud2_prefix', 'unreviewed UD2 prefix'),
    ('opcode_0f', 'unsupported 0F opcode'),
    ('store8', 'unreviewed byte store'),
    ('move_width', 'non-64-bit ordinary move is outside the profile'),
    ('move_mode', 'unreviewed move/LEA register form'),
    ('alu_width', 'unreviewed ALU memory or narrow operand'),
    ('immediate_alu', 'unreviewed immediate ALU instruction'),
    ('shift', 'unreviewed shift instruction'),
    ('unary', 'unreviewed unary instruction'),
    ('opcode', 'unsupported machine opcode at byte {}'),
    ('instruction_budget', 'decoded instruction budget exceeded'),
    ('target', 'branch is not an exact instruction boundary'),
    ('condition', 'only reviewed unsigned/equality conditions are admitted'),
    ('call_inventory', 'call instruction inventory differs from checked relocations'),
    ('call_target', 'call target is not an admitted function boundary'),
)
REFUSAL_IDS = {name: code for code, (name, _) in enumerate(REFUSALS, 1)}


def _operand(kind, word):
    if kind == 'a':
        if word not in ALU_GROUPS:
            raise RuntimeError('invalid native Safe Core ALU group')
        return ALU_GROUPS[word]
    if kind == 'i' and word >= 1 << 63:
        return word - (1 << 64)
    return word


class NativeMachineScheduler:
    """HIA owns pending paths, exact visitation and budget counters."""

    def __init__(self, entry):
        self._entry = entry
        self._workspace = ctypes.create_string_buffer(SCHEDULER_WORKSPACE)
        self._output = ctypes.create_string_buffer(SCHEDULER_REPLY.size)

    def _exchange(self, operation, first, second=0):
        from .hia_safe_core_x64 import require

        request = SCHEDULER_REQUEST.pack(operation, first, second, 0)
        source = ctypes.create_string_buffer(request, len(request))
        result = self._entry(source, len(source), self._output, len(self._output),
                             self._workspace, len(self._workspace))
        if result != SCHEDULER_REPLY.size:
            raise RuntimeError('invalid native Safe Core scheduler exchange')
        action, handle, steps = SCHEDULER_REPLY.unpack(self._output)
        if action in SCHEDULER_REFUSALS:
            require(False, SCHEDULER_REFUSALS[action])
        if action not in (0, SCHEDULER_LIVE, SCHEDULER_EXECUTE) or bool(handle) != bool(action):
            raise RuntimeError('invalid native Safe Core scheduler action')
        return action, handle, steps

    def start(self, handle):
        return self._exchange(0, handle)

    def observed(self, live, ordinal=MAX_INSTRUCTIONS):
        return self._exchange(1, int(live), ordinal)

    def advance(self, finished, fork=0):
        return self._exchange(2, int(finished), fork)


class NativeSafeCoreX64Decode(NativeHiaJsonImage):
    def decode(self, data, calls=None):
        from .hia_safe_core_x64 import require

        require(type(data) is bytes and 0 < len(data) <= MAX_TEXT, REFUSALS[0][1])
        source = ctypes.create_string_buffer(data, len(data))
        capacity = HEADER.size + min(len(data), MAX_INSTRUCTIONS) * ROW.size
        output = ctypes.create_string_buffer(capacity)
        if calls is None:
            scratch = ctypes.create_string_buffer(WORKSPACE)
        else:
            require(len(calls) <= MAX_INSTRUCTIONS, REFUSALS[REFUSAL_IDS['call_inventory'] - 1][1])
            scratch = ctypes.create_string_buffer(WORKSPACE + CALL_COUNT.size + len(calls) * CALL_BINDING.size)
            CALL_COUNT.pack_into(scratch, WORKSPACE, len(calls))
            for index, (pc, target) in enumerate(sorted(calls.items())):
                external = target == 'abort'
                encoded_pc = pc if 0 <= pc < 1 << 64 else (1 << 64) - 1
                encoded_target = 0 if external else target if 0 <= target < 1 << 64 else (1 << 64) - 1
                CALL_BINDING.pack_into(scratch, WORKSPACE + CALL_COUNT.size + index * CALL_BINDING.size,
                                       encoded_pc, int(external), encoded_target)
        size = self._entry(source, len(data), output, capacity, scratch, len(scratch))
        if not HEADER.size <= size <= capacity:
            raise RuntimeError('invalid native Safe Core decoder response size')
        status, detail, count = HEADER.unpack_from(output)
        if status:
            if status > len(REFUSALS) or size != HEADER.size or count or detail >= len(data):
                raise RuntimeError('invalid native Safe Core decoder refusal')
            name, message = REFUSALS[status - 1]
            if name in ('opcode', 'opcode_0f'):
                raise SafeCoreMachineRejected(message.format(detail))
            require(False, message)
        if (detail or not 0 < count <= min(len(data), MAX_INSTRUCTIONS)
                or size != HEADER.size + count * ROW.size):
            raise RuntimeError('invalid native Safe Core instruction inventory')
        result, pc = {}, 0
        for offset in range(HEADER.size, size, ROW.size):
            at, code, width, *words = ROW.unpack_from(output, offset)
            if at != pc or not 1 <= code <= len(OPERATIONS) or not 1 <= width <= len(data) - pc:
                raise RuntimeError('invalid native Safe Core instruction row')
            name, roles = OPERATIONS[code - 1]
            args = tuple(_operand(role, word) for role, word in zip(roles, words))
            result[pc] = Instruction(name, args, width)
            pc += width
        if pc != len(data):
            raise RuntimeError('native Safe Core decoder left unconsumed machine bytes')
        return result

    def scheduler(self):
        return NativeMachineScheduler(self._entry)

    def memory_admitted(self, offset, low, size, writing, loan=None):
        if offset is None:
            kind = 1
            access = 0 if loan is None else 2 if loan == 'mutbuf' else 1
            first, second = access, 0
        else:
            kind = 0
            first, second = offset % (1 << 64), low % (1 << 64)
        packet = MEMORY_REQUEST.pack(kind, first, second, size, int(writing))
        request = ctypes.create_string_buffer(packet, len(packet))
        result = self._entry(None, 0, None, 0, request, len(packet))
        if result not in (0, 1):
            raise RuntimeError('invalid native Safe Core memory admission')
        return result == 1

    @lru_cache(maxsize=512)
    def recipe(self, operation, parameter=0):
        packet = RECIPE_REQUEST.pack(OPERATION_IDS[operation], parameter)
        request = ctypes.create_string_buffer(packet, len(packet))
        capacity = RECIPE_HEADER.size + MAX_RECIPE_NODES * RECIPE_NODE.size
        output = ctypes.create_string_buffer(capacity)
        size = self._entry(None, 0, output, capacity, request, len(packet))
        if not RECIPE_HEADER.size <= size <= capacity:
            raise RuntimeError('invalid native Safe Core formula extent')
        count, *roots = RECIPE_HEADER.unpack_from(output)
        if (count > MAX_RECIPE_NODES or size != RECIPE_HEADER.size + count * RECIPE_NODE.size
                or any(ref > RECIPE_INPUTS + count for ref in roots)):
            raise RuntimeError('invalid native Safe Core formula roots')
        nodes = []
        for at in range(RECIPE_HEADER.size, size, RECIPE_NODE.size):
            code, *args = RECIPE_NODE.unpack_from(output, at)
            if not 1 <= code <= len(RECIPE_LAYOUT):
                raise RuntimeError('invalid native Safe Core formula primitive')
            roles, lower = RECIPE_LAYOUT[code - 1]
            limit = RECIPE_INPUTS + len(nodes)
            if any(arg != 0 for arg in args[len(roles):]) or any(
                    not 1 <= arg <= limit for role, arg in zip(roles, args) if role == 'r'):
                raise RuntimeError('invalid native Safe Core formula operand')
            nodes.append((lower, tuple((role == 'r', arg) for role, arg in zip(roles, args))))
        return tuple(roots), tuple(nodes)

    def symbolic(self, z, ctx, operation, parameter=0, *, left=None, right=None,
                 zf=None, cf=None, arbitrary=None):
        roots, nodes = self.recipe(operation, parameter)
        values = [None, left, right, zf, cf, arbitrary]
        for lower, sources in nodes:
            args = [values[index] if is_ref else index for is_ref, index in sources]
            if any(value is None for value in args):
                raise RuntimeError('missing native Safe Core formula input')
            values.append(lower(z, ctx, *args))
        result = tuple(values[ref] for ref in roots)
        for index, (ref, value) in enumerate(zip(roots, result, strict=True)):
            if ref and not ((z.is_bv(value) and value.size() == 64) if index == 0 else z.is_bool(value)):
                raise RuntimeError('invalid native Safe Core formula result sort')
        return result


def installed_safe_core_x64_decode(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeSafeCoreX64Decode)


def selected_safe_core_x64_decode():
    selected = os.environ.get(SELECTOR)
    return None if selected is None else installed_safe_core_x64_decode(selected)
