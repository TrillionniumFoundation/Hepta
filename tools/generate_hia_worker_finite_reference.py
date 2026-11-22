"""Author the pure finite-counterexample input for HIA's independent reference VM."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import EXECUTION_CHAIN_FIELDS, EXECUTION_RESOURCE_FIELDS, WIDTHS
from hepta.hia_schema import PRIMITIVE_PROFILES, supports_feature
from hepta.hia_optimization import PURE
from hepta.hia_scalar_reference_native import OPCODES
from hepta.hia_scalar_reference_wire import (
    BRANCH, CONSTANT, JUMP, PROGRAM_MAGIC, PROGRAM_RESULT, RETURN, TRAP, TRAPS, TYPES,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_json_decode import source_program as json_decoder
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_emit_verification import literal_match
from tools.generate_hia_worker_inspection_effect import function
from tools.hia_retained_proof_method import FINITE_COMPLETION, FINITE_OBSERVATION

SOURCE = Path('examples/hia_bootstrap/worker_finite_reference.hepta')
OBSERVATION_SOURCE = SOURCE.with_name('worker_finite_observation.hepta')
KEYS = ('functions', 'exports', 'function', 'arguments', 'name', 'blocks', 'params',
        'returns', 'effects', 'entry', 'id', 'ops', 'term', 'op', 'args', 'out',
        'attrs', 'type', 'value', 'mode', 'values', 'target', 'cond', 'then', 'else', 'code')
OBSERVATION_KEYS = ('functions', 'exports', 'function', 'arguments', 'name', 'params',
                    'returns', 'effects', 'type', 'values', 'schema', 'method', 'checked',
                    'required', 'complete', 'counterexample', 'before', 'after', 'status',
                    'first_trap', 'resources', 'proof_binding', 'all_inputs_in_declared_widths',
                    'transcript_sha256', *sorted(EXECUTION_RESOURCE_FIELDS),
                    *sorted(EXECUTION_CHAIN_FIELDS))
NONE = (1 << 64) - 1
INVALID = 0xfffffffd
MAX_INPUT = 8 << 20
MAX_BLOCKS = 128
MAX_OPERATIONS = 4096
MAX_VALUES = 8192
PROJECTION = int.from_bytes(b'HIAFRP01', 'little')
JOIN = int.from_bytes(b'HIAFRJ01', 'little')
COMPLETE_PROJECTION = int.from_bytes(b'HIAFIP01', 'little')
COMPLETE_JOIN = int.from_bytes(b'HIAVFC02', 'little')

POLICY = r'''
# [verified immutable Core, retained {function, arguments}].
# This role emits the interpreter wire; it never runs Core or asserts a verdict.
def finite_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < 1048576 or length(w) < 33554432:
        return BAD
    put(o, 48, 262144)
    put(o, 56, 128)
    used = widen(decode_json(s, w, o))
    if used >= 4294967292 or get(w, 64) != 5 or get(w, 96) != 2:
        return BAD
    core = child(w, 64)
    case = next(w, core)
    if object(w, core) == False or object(w, case) == False or get(w, case + 32) != 2:
        return BAD
    name = lookup(w, case, K_function)
    args = lookup(w, case, K_arguments)
    if kind(w, name) != 4 or kind(w, args) != 5:
        return BAD
    fn = public_function(w, core, name)
    if fn == NONE:
        return BAD
    arena = (used + 7) & 18446744073709551608
    if length(w) - arena < MAP_BYTES:
        return BAD
    return project_fn(s, o, w, arena, fn, args)

def public_function(w:mutbuf, core:u64, name:u64) -> u64:
    if object(w, core) == False or kind(w, name) != 4:
        return NONE
    if published(w, lookup(w, core, K_exports), name) == False:
        return NONE
    return named(w, lookup(w, core, K_functions), name, K_name)

def published(w:mutbuf, exports:u64, name:u64) -> bool:
    if exports == NONE:
        return True
    if kind(w, exports) != 5:
        return False
    item = child(w, exports)
    while item != NONE:
        if eq_text(w, item, name):
            return True
        item = next(w, item)
    return False

# Arena words:
# 0 append offset; 8 max scalar slots; 16 max edge/return arguments;
# 24 original block count; 32 current scalar slots; 40 exact entry PC.
# Block rows begin at 64: original block, instruction location, DAG marker.
# The current block's SSA name/type rows begin after the bounded block table.
def project_fn(s:readbuf, o:mutbuf, w:mutbuf, a:u64, fn:u64, args:u64) -> u64:
    blocks = lookup(w, fn, K_blocks)
    effects = lookup(w, fn, K_effects)
    params = lookup(w, fn, K_params)
    returns = lookup(w, fn, K_returns)
    if kind(w, blocks) != 5 or kind(w, effects) != 5 or kind(w, params) != 5 or kind(w, returns) != 5:
        return BAD
    if get(w, effects + 32) > 1 or (get(w, effects + 32) == 1 and trap_name(w, child(w, effects)) == False):
        return BAD
    if get(w, returns + 32) > 1 or get(w, params + 32) != get(w, args + 32):
        return BAD
    if get(w, returns + 32) == 1 and type_code(w, child(w, returns)) == NONE:
        return BAD
    n = get(w, blocks + 32)
    if n == 0 or n > BLOCK_MAX:
        return BAD
    put(w, a + 24, n)
    put(w, a + 8, 1)
    put(w, a + 16, 1)
    if index_blocks(w, a, blocks, lookup(w, fn, K_entry)) == False:
        return BAD
    if graph_is_acyclic(w, a) == False:
        return BAD
    at = 0
    while at < n:
        row = a + 64 + 24 * at
        if project_block(s, o, w, a, get(w, row), get(w, row + 8)) == False:
            return BAD
        at = at + 1
    arg_at = reserve(o, w, a, get(w, args + 32))
    if arg_at == NONE or arguments(s, o, w, params, args, arg_at) == False:
        return BAD
    put(o, 0, WIRE)
    put(o, 8, 10000)
    put(o, 16, 256)
    put(o, 24, get(w, a + 8))
    put(o, 32, get(w, a + 16))
    put(o, 40, arg_at)
    put(o, 48, get(w, args + 32))
    put(o, 56, get(w, returns + 32))
    put(o, 64, get(w, a + 40))
    return get(w, a)

def index_blocks(w:mutbuf, a:u64, blocks:u64, entry:u64) -> bool:
    block = child(w, blocks)
    total = 0
    index = 0
    cursor = 72
    put(w, a + 40, 0)
    while block != NONE:
        if object(w, block) == False:
            return False
        ops = lookup(w, block, K_ops)
        label = lookup(w, block, K_id)
        if kind(w, ops) != 5 or kind(w, label) != 4:
            return False
        count = get(w, ops + 32)
        if count > OP_MAX - total:
            return False
        row = a + 64 + 24 * index
        put(w, row, block)
        put(w, row + 8, cursor)
        put(w, row + 16, 0)
        if eq_text(w, entry, label):
            put(w, a + 40, cursor)
        total = total + count
        cursor = cursor + 64 * (count + 1)
        index = index + 1
        block = next(w, block)
    put(w, a, cursor)
    return get(w, a + 40) != 0

def graph_is_acyclic(w:mutbuf, a:u64) -> bool:
    count = get(w, a + 24)
    done = 0
    while done < count:
        prior = done
        index = 0
        while index < count:
            row = a + 64 + 24 * index
            if get(w, row + 16) == 0:
                term = lookup(w, get(w, row), K_term)
                if terminal_ready(w, a, term):
                    put(w, row + 16, 1)
                    done = done + 1
            index = index + 1
        if done == prior:
            return False
    return True

def terminal_ready(w:mutbuf, a:u64, term:u64) -> bool:
    if object(w, term) == False:
        return False
    code = term_code(w, lookup(w, term, K_op))
    if code == RET or code == T_TRAP:
        return True
    if code == T_JUMP:
        return target_ready(w, a, term)
    if code == T_BRANCH:
        return target_ready(w, a, lookup(w, term, K_then)) and target_ready(w, a, lookup(w, term, K_else))
    return False

def target_ready(w:mutbuf, a:u64, edge:u64) -> bool:
    if object(w, edge) == False:
        return False
    row = block_row(w, a, lookup(w, edge, K_target))
    return row != NONE and get(w, row + 16) != 0

def project_block(s:readbuf, o:mutbuf, w:mutbuf, a:u64, block:u64, pc:u64) -> bool:
    params = lookup(w, block, K_params)
    if kind(w, params) != 5:
        return False
    put(w, a + 32, 0)
    item = child(w, params)
    while item != NONE:
        if define_value(w, a, item) == NONE:
            return False
        item = next(w, item)
    ins = child(w, lookup(w, block, K_ops))
    while ins != NONE:
        if emit_instruction(s, o, w, a, ins, pc) == False:
            return False
        pc = pc + 64
        ins = next(w, ins)
    slots = get(w, a + 32)
    if slots > get(w, a + 8):
        put(w, a + 8, slots)
    return emit_terminal(o, w, a, lookup(w, block, K_term), pc)

def emit_instruction(s:readbuf, o:mutbuf, w:mutbuf, a:u64, ins:u64, pc:u64) -> bool:
    if object(w, ins) == False:
        return False
    output = lookup(w, ins, K_out)
    args = lookup(w, ins, K_args)
    if kind(w, output) != 5 or kind(w, args) != 5 or get(w, output + 32) != 1:
        return False
    result = child(w, output)
    typ = def_type(w, result)
    dest = define_value(w, a, result)
    if typ == NONE or dest == NONE:
        return False
    op = opcode(w, lookup(w, ins, K_op))
    clear_command(o, pc)
    put(o, pc + 8, dest)
    if op == CONST:
        attrs = lookup(w, ins, K_attrs)
        if object(w, attrs) == False or get(w, args + 32) != 0:
            return False
        value = lookup(w, attrs, K_value)
        parsed = capture_value(s, w, a, value, typ)
        if parsed == False:
            return False
        put(o, pc, CONST)
        put(o, pc + 16, get(w, a + 48))
        return True
    if op == NONE:
        attrs = lookup(w, ins, K_attrs)
        if object(w, attrs) == False or cast_name(w, lookup(w, ins, K_op)) == False:
            return False
        op = cast_opcode(w, lookup(w, attrs, K_mode))
        if op == NONE:
            return False
    put(o, pc, op)
    put(o, pc + 40, width(typ))
    put(o, pc + 56, typ)
    return scalar_operands(o, w, a, args, pc, signed_type(typ))

def scalar_operands(o:mutbuf, w:mutbuf, a:u64, args:u64, pc:u64, flags:u64) -> bool:
    count = get(w, args + 32)
    if count == 0 or count > 3:
        return False
    arg = child(w, args)
    index = 0
    while arg != NONE:
        row = value_row(w, a, arg)
        if row == NONE or get(w, row + 16) + 1 >= get(w, a + 32):
            return False
        put(o, pc + 16 + index * 8, get(w, row + 16))
        flags = flags | (signed_type(get(w, row + 8)) << (index + 1))
        index = index + 1
        arg = next(w, arg)
    put(o, pc + 48, flags)
    return True

def emit_terminal(o:mutbuf, w:mutbuf, a:u64, term:u64, pc:u64) -> bool:
    code = term_code(w, lookup(w, term, K_op))
    clear_command(o, pc)
    put(o, pc, code)
    if code == RET:
        values = lookup(w, term, K_values)
        if kind(w, values) != 5:
            return False
        at = value_list(o, w, a, values)
        if at == NONE:
            return False
        put(o, pc + 8, at)
        put(o, pc + 16, get(w, values + 32))
        return True
    if code == T_TRAP:
        trap = trap_code(w, lookup(w, term, K_code))
        if trap == NONE:
            return False
        put(o, pc + 8, trap)
        return True
    if code == T_JUMP:
        at = emit_edge(o, w, a, term)
        if at == NONE:
            return False
        put(o, pc + 8, at)
        return True
    cond = value_row(w, a, lookup(w, term, K_cond))
    if code != T_BRANCH or cond == NONE:
        return False
    yes = emit_edge(o, w, a, lookup(w, term, K_then))
    no = emit_edge(o, w, a, lookup(w, term, K_else))
    if yes == NONE or no == NONE:
        return False
    put(o, pc + 8, get(w, cond + 16))
    put(o, pc + 16, yes)
    put(o, pc + 24, no)
    return True

def emit_edge(o:mutbuf, w:mutbuf, a:u64, edge:u64) -> u64:
    if object(w, edge) == False:
        return NONE
    block = block_row(w, a, lookup(w, edge, K_target))
    args = lookup(w, edge, K_args)
    if block == NONE or kind(w, args) != 5:
        return NONE
    values = value_list(o, w, a, args)
    at = reserve(o, w, a, 3)
    if values == NONE or at == NONE:
        return NONE
    put(o, at, get(w, block + 8))
    put(o, at + 8, values)
    put(o, at + 16, get(w, args + 32))
    return at

def value_list(o:mutbuf, w:mutbuf, a:u64, values:u64) -> u64:
    count = get(w, values + 32)
    at = reserve(o, w, a, count)
    if at == NONE:
        return NONE
    if count > get(w, a + 16):
        put(w, a + 16, count)
    value = child(w, values)
    index = 0
    while value != NONE:
        row = value_row(w, a, value)
        if row == NONE:
            return NONE
        put(o, at + 8 * index, get(w, row + 16))
        value = next(w, value)
        index = index + 1
    return at

def arguments(s:readbuf, o:mutbuf, w:mutbuf, params:u64, args:u64, at:u64) -> bool:
    # Only the historical pure finite domain (at most 12 input bits).
    if get(w, params + 32) > 12:
        return False
    param = child(w, params)
    arg = child(w, args)
    bits = 0
    while param != NONE:
        typ = def_type(w, param)
        if typ == NONE or typ == 1:
            return False
        bits = bits + width(typ)
        if bits > 12 or capture_value(s, w, 0, arg, typ) == False:
            return False
        put(o, at, get(w, 48))
        at = at + 8
        param = next(w, param)
        arg = next(w, arg)
    return True

def capture_value(s:readbuf, w:mutbuf, a:u64, value:u64, typ:u64) -> bool:
    tag = kind(w, value)
    if typ == 0:
        if tag != 1 and tag != 2:
            return False
        put(w, a + 48, tag - 1)
        return True
    if typ == 1:
        put(w, a + 48, 0)
        return tag == 0
    if tag != 3:
        return False
    at = get(w, value + 24)
    extent = get(w, value + 32)
    if extent < 1 or extent > 20:
        return False
    end = at + extent
    minus = byte(s, at) == 45
    if minus:
        at = at + 1
    bits = width(typ)
    sign = signed_type(typ) != 0
    limit = NONE
    if bits < 64:
        limit = (1 << bits) - 1
    if sign:
        limit = (limit >> 1) + choose(minus, 1, 0)
    elif minus:
        return False
    magnitude = 0
    while at < end:
        digit = widen(byte(s, at))
        if digit < 48 or digit > 57 or magnitude > 1844674407370955161:
            return False
        magnitude = magnitude * 10
        if magnitude > limit or digit - 48 > limit - magnitude:
            return False
        magnitude = magnitude + digit - 48
        at = at + 1
    put(w, a + 48, choose(minus, 0 - magnitude, magnitude))
    return True

def define_value(w:mutbuf, a:u64, node:u64) -> u64:
    typ = def_type(w, node)
    if typ == NONE:
        return NONE
    name = lookup(w, node, K_name)
    cursor = get(w, a + 32)
    if kind(w, name) != 4 or cursor == VALUE_MAX:
        return NONE
    row = a + VALUE_BASE + cursor * 24
    put(w, row, name)
    put(w, row + 8, typ)
    put(w, row + 16, cursor)
    put(w, a + 32, cursor + 1)
    return cursor

def def_type(w:mutbuf, node:u64) -> u64:
    if object(w, node) == False:
        return NONE
    return type_code(w, lookup(w, node, K_type))

def value_row(w:mutbuf, a:u64, name:u64) -> u64:
    if kind(w, name) != 4:
        return NONE
    index = 0
    while index < get(w, a + 32):
        row = a + VALUE_BASE + 24 * index
        if eq_text(w, name, get(w, row)):
            return row
        index = index + 1
    return NONE

def block_row(w:mutbuf, a:u64, name:u64) -> u64:
    index = 0
    while index < get(w, a + 24):
        row = a + 64 + 24 * index
        if eq_text(w, name, lookup(w, get(w, row), K_id)):
            return row
        index = index + 1
    return NONE

def named(w:mutbuf, array:u64, name:u64, key:u64) -> u64:
    if kind(w, array) != 5:
        return NONE
    item = child(w, array)
    while item != NONE:
        if object(w, item) and eq_text(w, name, lookup(w, item, key)):
            return item
        item = next(w, item)
    return NONE

def reserve(o:mutbuf, w:mutbuf, a:u64, count:u64) -> u64:
    at = get(w, a)
    if at > length(o) or count > (length(o) - at) >> 3:
        return NONE
    put(w, a, at + 8 * count)
    return at

def clear_command(o:mutbuf, at:u64) -> u64:
    offset = 0
    while offset < 64:
        put(o, at + offset, 0)
        offset = offset + 8
    return 0

def object(w:mutbuf, node:u64) -> bool:
    return kind(w, node) == 6

def kind(w:mutbuf, node:u64) -> u64:
    if node == NONE:
        return NONE
    return get(w, node)

def child(w:mutbuf, node:u64) -> u64:
    index = get(w, node + 24)
    return choose(index == NONE, NONE, 64 + index * 72)

def next(w:mutbuf, node:u64) -> u64:
    index = get(w, node + 16)
    return choose(index == NONE, NONE, 64 + index * 72)

def eq_text(w:mutbuf, left:u64, right:u64) -> bool:
    if kind(w, left) != 4 or kind(w, right) != 4:
        return False
    size = get(w, left + 32)
    if get(w, right + 32) != size:
        return False
    a = get(w, left + 24)
    b = get(w, right + 24)
    index = 0
    while index < size:
        if byte(w, a + index) != byte(w, b + index):
            return False
        index = index + 1
    return True
'''

EVIDENCE = r'''
def observation_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(s) > INPUT_MAX or length(o) < 256 or length(w) < 65536:
        return BAD
    if input_word(s, 0) == JOIN:
        return confirm_observations(s, o)
    if input_word(s, 0) == COMPLETE_JOIN:
        return confirm_complete(s, o)
    put(o, 48, 262144)
    put(o, 56, 128)
    if widen(decode_json(s, w, o)) >= 4294967292 or get(w, 64) != 5:
        return BAD
    if get(w, 96) == 3:
        return evidence_projection(s, o, w, child(w, 64))
    if get(w, 96) == 1:
        return complete_expectation(s, o, w, child(w, 64))
    return BAD

def complete_expectation(s:readbuf, o:mutbuf, w:mutbuf, evidence:u64) -> u64:
    if object(w, evidence) == False:
        return BAD
    fields = get(w, evidence + 32)
    if fields != 8 and (fields != 9 or object(w, lookup(w, evidence, K_proof_binding)) == False):
        return BAD
    if finite_name(w, lookup(w, evidence, K_method)) == False or kind(w, lookup(w, evidence, K_complete)) != 2:
        return BAD
    if kind(w, lookup(w, evidence, K_all_inputs_in_declared_widths)) != 2:
        return BAD
    if capture_value(s, w, 0, lookup(w, evidence, K_checked), U64_TYPE) == False:
        return BAD
    checked = get(w, 48)
    if checked == 0 or checked > 4096 or capture_value(s, w, 0, lookup(w, evidence, K_required), U64_TYPE) == False:
        return BAD
    if checked != get(w, 48):
        return BAD
    digest = lookup(w, evidence, K_transcript_sha256)
    if kind(w, digest) != 4 or get(w, digest + 32) != 64:
        return BAD
    at = get(w, digest + 24)
    index = 0
    while index < 64:
        ch = byte(w, at + index)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return BAD
        store(o, 24 + index, ch)
        index = index + 1
    put(o, 0, COMPLETE_PROJECTION)
    put(o, 8, 0)
    put(o, 16, checked)
    return 88

# [tag, exact plan extent, number of summaries, projected expectation,
#  independently computed transcript SHA-256, HIA plan, HIA summary rows].
def confirm_complete(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 328 or input_word(s, 24) != COMPLETE_PROJECTION or input_word(s, 32) != 0:
        return BAD
    count = input_word(s, 16)
    plan_size = input_word(s, 8)
    if count < 1 or count > 1024 or plan_size != 32 + 56 * count or length(s) != 176 + plan_size + 64 * count:
        return BAD
    if input_word(s, 176) != DOMAIN_PLAN or input_word(s, 184) > 3 or input_word(s, 192) != count:
        return BAD
    required = input_word(s, 40)
    if required < 1 or required > 4096 or input_word(s, 200) != required:
        return BAD
    summary = 176 + plan_size
    if exact_coverage(s, summary, count, required) == False:
        return BAD
    index = 0
    while index < 64:
        if byte(s, 48 + index) != byte(s, 112 + index):
            return BAD
        index = index + 1
    put(o, 0, COMPLETE_OBSERVED)
    put(o, 8, 0)
    put(o, 16, 1)
    return 24

def exact_coverage(s:readbuf, at:u64, count:u64, total:u64) -> bool:
    index = 0
    checked = 0
    while index < count:
        expected = input_word(s, 232 + 56 * index)
        if expected == 0 or expected > total - checked or complete_row(s, at, expected) == False:
            return False
        checked = checked + expected
        index = index + 1
        at = at + 64
    return checked == total

def complete_row(s:readbuf, at:u64, expected:u64) -> bool:
    return input_word(s, at) == TRANSCRIPT_ROW and input_word(s, at + 8) == 0 and input_word(s, at + 16) == expected and input_word(s, at + 24) == expected and input_word(s, at + 32) == NONE and input_word(s, at + 56) != 0

# [independently admitted base Core, candidate Core, physical evidence].
# The result is a read span and two expected observations, not proof that the
# interpreter produced either observation.
def evidence_projection(s:readbuf, o:mutbuf, w:mutbuf, base:u64) -> u64:
    candidate = next(w, base)
    evidence = next(w, candidate)
    if object(w, evidence) == False:
        return BAD
    fields = get(w, evidence + 32)
    if fields != 7 and (fields != 8 or object(w, lookup(w, evidence, K_proof_binding)) == False):
        return BAD
    if finite_name(w, lookup(w, evidence, K_method)) == False or kind(w, lookup(w, evidence, K_complete)) != 1:
        return BAD
    if capture_value(s, w, 0, lookup(w, evidence, K_checked), U64_TYPE) == False:
        return BAD
    checked = get(w, 48)
    if capture_value(s, w, 0, lookup(w, evidence, K_required), U64_TYPE) == False:
        return BAD
    required = get(w, 48)
    if checked == 0 or checked > required or required > 4096:
        return BAD
    witness = lookup(w, evidence, K_counterexample)
    if object(w, witness) == False or get(w, witness + 32) != 2 or kind(w, lookup(w, witness, K_arguments)) != 5:
        return BAD
    name = lookup(w, witness, K_function)
    left = public_function(w, base, name)
    right = public_function(w, candidate, name)
    if left == NONE or right == NONE or same_interface(w, left, right) == False:
        return BAD
    if expected_observation(s, o, w, base, left, lookup(w, evidence, K_before), 32) == False:
        return BAD
    if expected_observation(s, o, w, candidate, right, lookup(w, evidence, K_after), 72) == False:
        return BAD
    put(o, 0, PROJECTION)
    put(o, 8, 0)
    put(o, 16, get(w, witness + 56))
    put(o, 24, get(w, witness + 64))
    return 112

def same_interface(w:mutbuf, left:u64, right:u64) -> bool:
    a = lookup(w, left, K_returns)
    b = lookup(w, right, K_returns)
    if kind(w, a) != 5 or kind(w, b) != 5:
        return False
    count = get(w, a + 32)
    if count != get(w, b + 32) or count > 1:
        return False
    if count == 1 and eq_text(w, child(w, a), child(w, b)) == False:
        return False
    a = lookup(w, left, K_effects)
    b = lookup(w, right, K_effects)
    if kind(w, a) != 5 or kind(w, b) != 5:
        return False
    count = get(w, a + 32)
    if count != get(w, b + 32) or count > 1:
        return False
    if count == 1 and (trap_name(w, child(w, a)) == False or trap_name(w, child(w, b)) == False):
        return False
    a = lookup(w, left, K_params)
    b = lookup(w, right, K_params)
    if kind(w, a) != 5 or kind(w, b) != 5 or get(w, a + 32) != get(w, b + 32):
        return False
    first = child(w, a)
    second = child(w, b)
    while first != NONE:
        left_type = def_type(w, first)
        if left_type == NONE or left_type != def_type(w, second):
            return False
        first = next(w, first)
        second = next(w, second)
    return True

# Observation row: returned/trapped, return count/trap code, value bits,
# scalar return type or NONE, and the schema-selected resource-ledger shape.
def expected_observation(s:readbuf, o:mutbuf, w:mutbuf, core:u64, fn:u64, row:u64, at:u64) -> bool:
    if object(w, row) == False or get(w, row + 32) != 4:
        return False
    chains = chain_ledger(w, lookup(w, core, K_schema))
    if chains > 1 or zero_resources(s, w, lookup(w, row, K_resources), chains) == False:
        return False
    values = lookup(w, row, K_values)
    first = lookup(w, row, K_first_trap)
    status = lookup(w, row, K_status)
    put(o, at + 16, 0)
    put(o, at + 24, NONE)
    put(o, at + 32, chains)
    if trapped_name(w, status):
        trap = trap_code(w, first)
        if trap == NONE or kind(w, values) != 0:
            return False
        put(o, at, 1)
        put(o, at + 8, trap)
        return True
    returns = lookup(w, fn, K_returns)
    count = get(w, returns + 32)
    if returned_name(w, status) == False or kind(w, first) != 0 or kind(w, values) != 5 or get(w, values + 32) != count:
        return False
    if count == 1:
        typ = type_code(w, child(w, returns))
        if typ == NONE or capture_value(s, w, 0, child(w, values), typ) == False:
            return False
        put(o, at + 16, get(w, 48))
        put(o, at + 24, typ)
    put(o, at, 0)
    put(o, at + 8, count)
    return True

# [tag, before length, after length, projected evidence, two raw interpreter replies].
# Results are consumed from the two pinned interpreter executions, not read
# from the retained Store. Steps aren't an observable, but must be in budget.
def confirm_observations(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 200 or length(s) > 216:
        return BAD
    left_size = input_word(s, 8)
    right_size = input_word(s, 16)
    if (left_size != 32 and left_size != 40) or (right_size != 32 and right_size != 40):
        return BAD
    if length(s) != 136 + left_size + right_size or input_word(s, 24) != PROJECTION or input_word(s, 32) != 0:
        return BAD
    if match_observation(s, 56, 136, left_size) == False:
        return BAD
    if match_observation(s, 96, 136 + left_size, right_size) == False:
        return BAD
    index = 0
    while index < 24 and input_word(s, 56 + index) == input_word(s, 96 + index):
        index = index + 8
    if index == 24 and input_word(s, 88) == input_word(s, 128):
        return BAD
    put(o, 0, OBSERVED)
    put(o, 8, 0)
    put(o, 16, 2)
    return 24

def match_observation(s:readbuf, plan:u64, at:u64, extent:u64) -> bool:
    if input_word(s, at) != PROGRAM_REPLY or input_word(s, plan + 32) > 1:
        return False
    steps = input_word(s, at + 16)
    if steps == 0 or steps > 10000:
        return False
    expected = input_word(s, plan)
    count = input_word(s, plan + 8)
    actual = input_word(s, at + 8)
    detail = input_word(s, at + 24)
    if expected == 1:
        return extent == 32 and count < TRAP_COUNT and first_trap(actual, detail) == count and input_word(s, plan + 16) == 0 and input_word(s, plan + 24) == NONE
    if expected != 0 or actual != 0 or detail != 0 or count > 1 or extent != 32 + count * 8:
        return False
    if count == 0:
        return input_word(s, plan + 16) == 0 and input_word(s, plan + 24) == NONE
    return input_word(s, plan + 24) < TYPE_COUNT and input_word(s, plan + 16) == input_word(s, at + 32)

def first_trap(status:u64, detail:u64) -> u64:
    if status >= 1 and status <= 4 and detail < TYPE_COUNT:
        return choose(status == 2, DIV_ZERO, OVERFLOW)
    if status >= 7 and status < 7 + TRAP_COUNT:
        return status - 7
    return NONE

def zero_field(s:readbuf, w:mutbuf, row:u64, key:u64) -> bool:
    node = lookup(w, row, key)
    return kind(w, node) == 3 and get(w, node + 32) == 1 and byte(s, get(w, node + 24)) == 48
'''


def enum_reader(name, members):
    checks, tests = [], [f'def {name}(w:mutbuf, node:u64) -> u64:']
    for index, (label, code) in enumerate(members):
        match = f'{name}_match_{index}'
        checks.append(literal_match(match, label))
        tests.extend((f'    if {match}(w, node):', f'        return {code}'))
    return '\n'.join((*tests, f'    return {NONE}', *checks))


def key_reader(keys):
    lines = ['def key_id(w:mutbuf, at:u64, size:u64) -> u64:']
    for index, name in enumerate(keys, 1):
        raw = name.encode('ascii')
        parts = []
        for offset in range(0, len(raw), 8):
            chunk = raw[offset:offset + 8]
            parts.append(f'match_word(w, at + {offset}, {len(chunk)}) == {int.from_bytes(chunk, "little")}')
        lines.extend((f'    if size == {len(raw)} and ' + ' and '.join(parts) + ':',
                      f'        return {index}'))
    return '\n'.join((*lines, '    return 0'))


def program(*, observation=False):
    values = dict(BAD=INVALID, NONE=NONE, INPUT_MAX=MAX_INPUT, WIRE=PROGRAM_MAGIC,
                  BLOCK_MAX=MAX_BLOCKS, OP_MAX=MAX_OPERATIONS, VALUE_MAX=MAX_VALUES,
                  VALUE_BASE=64 + 24 * MAX_BLOCKS, MAP_BYTES=64 + 24 * (MAX_BLOCKS + MAX_VALUES),
                  CONST=CONSTANT, RET=RETURN, T_TRAP=TRAP, T_JUMP=JUMP, T_BRANCH=BRANCH,
                  PROJECTION=PROJECTION, JOIN=JOIN, OBSERVED=FINITE_OBSERVATION, PROGRAM_REPLY=PROGRAM_RESULT,
                  COMPLETE_PROJECTION=COMPLETE_PROJECTION, COMPLETE_JOIN=COMPLETE_JOIN,
                  COMPLETE_OBSERVED=FINITE_COMPLETION,
                  DOMAIN_PLAN=int.from_bytes(b'HIAVFD01', 'little'),
                  TRANSCRIPT_ROW=int.from_bytes(b'HIAVFJ01', 'little'),
                  TYPE_COUNT=len(TYPES), TRAP_COUNT=len(TRAPS), U64_TYPE=TYPES.index('u64'),
                  DIV_ZERO=TRAPS.index('division_by_zero'), OVERFLOW=TRAPS.index('overflow'))
    keys = OBSERVATION_KEYS if observation else KEYS
    values.update({f'K_{name}': index for index, name in enumerate(keys, 1)})
    kinds = ['def width(typ:u64) -> u64:']
    for size in (8, 16, 32, 64):
        tests = ' or '.join(f'typ == {index}' for index, name in enumerate(TYPES) if WIDTHS.get(name) == size)
        kinds.extend((f'    if {tests}:', f'        return {size}'))
    kinds.append('    return 1')
    kinds.extend(('', 'def signed_type(typ:u64) -> u64:',
                  '    return choose(' + ' or '.join(f'typ == {index}' for index, name in
                                                     enumerate(TYPES) if name.startswith('i')) + ', 1, 0)'))
    if observation:
        shared = ('public_function', 'published', 'capture_value', 'def_type', 'named',
                  'object', 'kind', 'child', 'next', 'eq_text')
        policy = '\n'.join((EVIDENCE, resource_checks(), *(function(POLICY, name) for name in shared)))
        readers = (
            enum_reader('chain_ledger', [(schema, int(supports_feature(schema, 'recursive_chain')))
                                         for schema in PRIMITIVE_PROFILES]),
            literal_match('finite_name', 'finite_domain'), literal_match('returned_name', 'returned'),
            literal_match('trapped_name', 'trapped'), function(authority(), 'input_word'),
        )
    else:
        policy = POLICY
        core_ops = [(op, OPCODES[op]) for op in sorted(PURE - {'const', 'int.cast'})]
        readers = (
            enum_reader('opcode', [('const', CONSTANT), *core_ops]),
            enum_reader('cast_opcode', [(key[5:], value) for key, value in OPCODES.items() if key.startswith('cast.')]),
            enum_reader('term_code', (('ret', RETURN), ('trap', TRAP), ('jump', JUMP), ('branch', BRANCH))),
            literal_match('cast_name', 'int.cast'),
        )
    policy = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda hit: str(values[hit[0]]), policy)
    return '\n'.join((
        policy, key_reader(keys), WIRE_HELPERS.split('\ndef signed_id', 1)[0].replace('NONE', str(NONE)),
        enum_reader('type_code', [(name, index) for index, name in enumerate(TYPES)]),
        enum_reader('trap_code', [(name, index) for index, name in enumerate(TRAPS)]),
        literal_match('trap_name', 'trap'), '\n'.join(kinds), *readers,
        json_decoder(wire_spans=True),
    ))


def resource_checks():
    lines = ['def zero_resources(s:readbuf, w:mutbuf, row:u64, chains:u64) -> bool:',
             '    if object(w, row) == False or get(w, row + 32) != '
             f'{len(EXECUTION_RESOURCE_FIELDS)} + chains * {len(EXECUTION_CHAIN_FIELDS)}:',
             '        return False']
    for fields, indent in ((EXECUTION_RESOURCE_FIELDS, 4), (EXECUTION_CHAIN_FIELDS, 8)):
        if indent == 8:
            lines.append('    if chains == 1:')
        for key in sorted(fields):
            lines.extend((' ' * indent + f'if zero_field(s, w, row, K_{key}) == False:',
                          ' ' * (indent + 4) + 'return False'))
    return '\n'.join((*lines, '    return True'))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
    OBSERVATION_SOURCE.write_text(
        render_assembly(document(program(observation=True), OBSERVATION_SOURCE.stem)), encoding='utf-8')
