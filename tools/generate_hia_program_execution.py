"""Author a complete finite HIA machine, with fixed raw-storage continuations.

The generated HIA is authoritative executable policy. This authoring module is
never imported by the installed runtime. The public Core declaration domain is
not limited to the compiler kernel's own 16-argument/three-result profile.
"""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import OPCODES
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAVM001', 'little')
ABI = 0xfffffff1
BASE = 8192
TYPES = ('i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64',
         'isize', 'usize', 'bool', 'unit', 'buffer', 'readbuf', 'mutbuf', 'chain')
FIELDS = ('schema', 'module', 'functions', 'exports', 'name', 'params', 'returns',
          'effects', 'entry', 'blocks', 'return_loans', 'id', 'ops', 'term', 'op',
          'args', 'out', 'attrs', 'type', 'value', 'mode', 'function', 'values',
          'target', 'then', 'else', 'cond', 'code')
OP_IDS = {name: index for index, name in enumerate(OPCODES, 1)}
CONSTANTS = {'MAGIC': MAGIC, 'ABI': ABI, 'BASE': BASE, 'N': (1 << 64) - 1}

# Header: magic/phase/sequence/request, four request words, ACK sequence/two
# reply words, outcome/error/error-type. Counters start at byte 256.
# Requests: 1 immutable arguments; 2 grow private arena; 3 raw zeroed storage;
# 4 release raw storage; 5 borrow raw source/destination windows.
# Phases: 1 prepare; 2 argument packet; 3 root frame; 4 execute; 5 allocation
# reply; 7 byte access; 10 push frame; 11 dropped owner; 12 popped chain;
# 13 chain storage drop; 14 completed node drop; 15 iterative chain destruction.
BODY = r'''
def program_execution(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return ABI
    if get(w, 0) == 0:
        if initialize(s, w) == 0:
            return ABI
    else:
        if get(w, 0) != MAGIC or get(w, 88) != 0:
            return ABI
        request = get(w, 24)
        if request == 0 or get(w, 64) != get(w, 16):
            return ABI
        if request == 2:
            if length(w) != get(w, 32) or get(w, 72) != length(w):
                return ABI
        elif request == 3:
            if get(w, 8) != 5:
                return ABI
            put(w, 608, get(w, 72))
        elif request == 4:
            if get(w, 72) != 1:
                return ABI
            put(w, 8, get(w, 688))
        elif request == 5:
            if get(w, 8) != 7 or length(s) != get(w, 48) or length(o) != get(w, 56):
                return ABI
        elif request == 1:
            if get(w, 8) != 2 or get(w, 72) != length(s):
                return ABI
        else:
            return ABI
        put(w, 24, 0)
        put(w, 64, 0)
    going = True
    while going:
        phase = get(w, 8)
        if phase == 1:
            prepare(w)
        elif phase == 2:
            arguments(s, w)
        elif phase == 3 or phase == 10:
            push_frame(w)
        elif phase == 4:
            execute(w)
        elif phase == 5:
            allocation_reply(w)
        elif phase == 7:
            memory_operation(s, o, w)
        elif phase == 11:
            consumed_owner(w)
        elif phase == 12:
            popped_chain(w)
        elif phase == 13:
            chain_storage_drop(w)
        elif phase == 14:
            chain_node_done(w)
        elif phase == 15:
            chain_drop_next(w)
        else:
            return ABI
        if get(w, 24) != 0 or get(w, 88) != 0:
            going = False
    if get(w, 88) != 0:
        if get(w, 88) <= 3 and validate_ledger(w) == 0:
            put(w, 88, 5)
            put(w, 96, 254)
            put(w, 104, 0)
        put(w, 24, 0)
        put(w, 16, get(w, 16) + 1)
        return 0
    return get(w, 24)

def issue(w:mutbuf, request:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    put(w, 16, get(w, 16) + 1)
    put(w, 24, request)
    put(w, 32, a)
    put(w, 40, b)
    put(w, 48, c)
    put(w, 56, d)
    return 0

def stop(w:mutbuf, status:u64, error:u64, typ:u64) -> u64:
    if get(w, 88) == 0:
        put(w, 88, status)
        put(w, 96, error)
        put(w, 104, typ)
    return 0

def tick(w:mutbuf) -> u64:
    put(w, 256, get(w, 256) + 1)
    if get(w, 256) > get(w, 392):
        stop(w, 3, 20, 0)
        return 0
    return 1

def initialize(s:readbuf, w:mutbuf) -> u64:
    if length(s) > length(w) - BASE:
        return 0
    if src_validate(s, w) == 0 or src_word(s, 0) != 5 or src_word(s, 16) != 6:
        return 0
    fill_range(w, 0, 4096, 0)
    copy_in(w, s, BASE, 0, length(s))
    put(w, 0, MAGIC)
    put(w, 8, 1)
    put(w, 472, (BASE + length(s) + 7) & (N - 7))
    document = element(w, BASE, 0)
    put(w, 712, document)
    put(w, 528, element(w, BASE, 1))
    put(w, 536, decimal(w, element(w, BASE, 2)))
    limits = element(w, BASE, 3)
    if tag(w, limits) != 5 or total(w, limits) != 4:
        return 0
    put(w, 392, decimal(w, element(w, limits, 0)))
    put(w, 400, decimal(w, element(w, limits, 1)))
    put(w, 408, decimal(w, element(w, limits, 2)))
    failure = element(w, limits, 3)
    put(w, 424, decimal(w, element(w, failure, 0)))
    put(w, 416, decimal(w, element(w, failure, 1)))
    put(w, 560, decimal(w, element(w, BASE, 4)))
    put(w, 720, element(w, BASE, 5))
    if get(w, 392) == 0 or get(w, 392) > 10000000 or get(w, 400) > 1073741824:
        return 0
    if get(w, 408) == 0 or get(w, 408) > 256 or get(w, 560) > 1:
        return 0
    version = schema_id(w, field(w, document, 1))
    put(w, 384, choose(version >= 7, 1, 0))
    functions = field(w, document, 3)
    if version == 0 or tag(w, functions) != 5 or total(w, functions) == 0 or total(w, functions) > 1024:
        return 0
    put(w, 496, total(w, functions))
    put(w, 728, functions + 24)
    return 1

def arena(w:mutbuf, amount:u64) -> u64:
    size = (amount + 23) & (N - 7)
    previous = 0
    block = get(w, 480)
    best = 0
    best_previous = 0
    best_size = N
    while block != 0 and best_size != size:
        available = get(w, block)
        if available >= size and available < best_size:
            best = block
            best_previous = previous
            best_size = available
        previous = block
        block = get(w, block + 8)
    if best != 0:
        tail = get(w, best + 8)
        if best_size >= size + 32:
            tail = best + size
            put(w, tail, best_size - size)
            put(w, tail + 8, get(w, best + 8))
        else:
            size = best_size
        if best_previous == 0:
            put(w, 480, tail)
        else:
            put(w, best_previous + 8, tail)
        put(w, best, size)
        return best + 16
    block = get(w, 472)
    if size > length(w) - block:
        capacity = length(w) * 2
        if capacity < block + size:
            capacity = block + size
        issue(w, 2, capacity, 0, 0, 0)
        return 0
    put(w, 472, block + size)
    put(w, block, size)
    put(w, block + 8, 0)
    return block + 16

def arena_free(w:mutbuf, address:u64) -> u64:
    block = address - 16
    put(w, block + 8, get(w, 480))
    put(w, 480, block)
    return 0

def field(w:mutbuf, node:u64, ident:u64) -> u64:
    if node == N or tag(w, node) != 6:
        return N
    cursor = node + 24
    count = total(w, node)
    while count != 0:
        value = end(w, cursor)
        if field_id(w, cursor) == ident:
            return value
        cursor = end(w, value)
        count = count - 1
    return N

def decimal(w:mutbuf, node:u64) -> u64:
    value = 0
    at = node + 16
    while at < end(w, node):
        value = value * 10 + byte(w, at) - 48
        at = at + 1
    return value

def hash_name(w:mutbuf, node:u64) -> u64:
    value = 14695981039346656037
    at = node + 16
    while at < end(w, node):
        value = (value ^ byte(w, at)) * 1099511628211
        at = at + 1
    return value

def prepare(w:mutbuf) -> u64:
    if get(w, 488) == 0:
        at = arena(w, get(w, 496) * 128)
        if at == 0:
            return 0
        fill_range(w, at, get(w, 496) * 128, 0)
        put(w, 488, at)
    while get(w, 504) < get(w, 496):
        record = get(w, 488) + get(w, 504) * 128
        if get(w, record) == 0:
            put(w, record, get(w, 728))
            scan_function(w, record)
        if prepare_function(w, record) == 0:
            return 0
        put(w, 728, end(w, get(w, 728)))
        put(w, 504, get(w, 504) + 1)
    function = function_named(w, get(w, 528))
    if function == 0 or get(w, function + 88) != get(w, 536):
        return stop(w, 4, 40, 0)
    if get(w, 560) == 0 and scalar_signature(w, function) == 0:
        return stop(w, 4, 41, 0)
    put(w, 736, function)
    put(w, 8, 2)
    return issue(w, 1, get(w, 536), 0, 0, 0)

def scan_function(w:mutbuf, record:u64) -> u64:
    node = get(w, record)
    params = field(w, node, 6)
    returns = field(w, node, 7)
    blocks = field(w, node, 10)
    put(w, record + 8, params)
    put(w, record + 16, returns)
    put(w, record + 24, field(w, node, 11))
    put(w, record + 40, blocks)
    put(w, record + 88, total(w, params))
    put(w, record + 96, total(w, returns))
    borrowed = 0
    result = returns + 24
    remaining = total(w, returns)
    while remaining != 0:
        typ = type_id(w, result)
        if typ == 14 or typ == 15:
            borrowed = borrowed + 1
        result = end(w, result)
        remaining = remaining - 1
    put(w, record + 112, borrowed)
    put(w, record + 80, total(w, params))
    cursor = blocks + 24
    count = total(w, blocks)
    while count != 0:
        scan_block(w, record, cursor)
        cursor = end(w, cursor)
        count = count - 1
    capacity = 2
    while capacity < get(w, record + 48) * 2:
        capacity = capacity * 2
    put(w, record + 72, capacity)
    put(w, record + 104, 128 + get(w, record + 48) * 16 + get(w, record + 88) * 8 + get(w, record + 80) * 8 + get(w, record + 96) * 16)
    put(w, record + 32, block_named(w, record, field(w, node, 9)))
    return 0

def max_arguments(w:mutbuf, record:u64, array:u64) -> u64:
    if array != N and total(w, array) > get(w, record + 80):
        put(w, record + 80, total(w, array))
    return 0

def scan_block(w:mutbuf, record:u64, block:u64) -> u64:
    put(w, record + 48, get(w, record + 48) + total(w, field(w, block, 6)))
    instructions = field(w, block, 13)
    at = instructions + 24
    count = total(w, instructions)
    while count != 0:
        put(w, record + 48, get(w, record + 48) + total(w, field(w, at, 17)))
        max_arguments(w, record, field(w, at, 16))
        at = end(w, at)
        count = count - 1
    term = field(w, block, 14)
    code = term_id(w, field(w, term, 15))
    if code == 2:
        max_arguments(w, record, field(w, term, 16))
    elif code == 3:
        max_arguments(w, record, field(w, field(w, term, 25), 16))
        max_arguments(w, record, field(w, field(w, term, 26), 16))
    return 0

def prepare_function(w:mutbuf, record:u64) -> u64:
    if get(w, record + 120) != 0:
        return 1
    if get(w, record + 56) == 0:
        memory = arena(w, get(w, record + 48) * 16)
        if memory == 0:
            return 0
        put(w, record + 56, memory)
    if get(w, record + 64) == 0:
        memory = arena(w, get(w, record + 72) * 8)
        if memory == 0:
            return 0
        fill_range(w, memory, get(w, record + 72) * 8, 0)
        put(w, record + 64, memory)
    put(w, 760, 0)
    blocks = get(w, record + 40)
    at = blocks + 24
    count = total(w, blocks)
    while count != 0:
        register_parameters(w, record, field(w, at, 6))
        operations = field(w, at, 13)
        operation = operations + 24
        remaining = total(w, operations)
        while remaining != 0:
            register_parameters(w, record, field(w, operation, 17))
            operation = end(w, operation)
            remaining = remaining - 1
        at = end(w, at)
        count = count - 1
    put(w, record + 120, 1)
    return 1

def register_parameters(w:mutbuf, record:u64, parameters:u64) -> u64:
    at = parameters + 24
    count = total(w, parameters)
    while count != 0:
        index = get(w, 760)
        name = field(w, at, 5)
        entry = get(w, record + 56) + index * 16
        put(w, entry, name)
        put(w, entry + 8, type_id(w, field(w, at, 19)))
        slot = hash_name(w, name) & (get(w, record + 72) - 1)
        while get(w, get(w, record + 64) + slot * 8) != 0:
            slot = (slot + 1) & (get(w, record + 72) - 1)
        put(w, get(w, record + 64) + slot * 8, index + 1)
        put(w, 760, index + 1)
        at = end(w, at)
        count = count - 1
    return 0

def slot(w:mutbuf, record:u64, name:u64) -> u64:
    index = hash_name(w, name) & (get(w, record + 72) - 1)
    found = get(w, get(w, record + 64) + index * 8)
    while found != 0:
        other = get(w, get(w, record + 56) + (found - 1) * 16)
        if same_text(w, name, other) != 0:
            return found - 1
        index = (index + 1) & (get(w, record + 72) - 1)
        found = get(w, get(w, record + 64) + index * 8)
    stop(w, 5, 253, 0)
    return 0

def function_named(w:mutbuf, name:u64) -> u64:
    index = 0
    while index < get(w, 496):
        record = get(w, 488) + index * 128
        if same_text(w, name, field(w, get(w, record), 5)) != 0:
            return record
        index = index + 1
    return 0

def block_named(w:mutbuf, record:u64, name:u64) -> u64:
    blocks = get(w, record + 40)
    at = blocks + 24
    count = total(w, blocks)
    while count != 0:
        if same_text(w, name, field(w, at, 12)) != 0:
            return at
        at = end(w, at)
        count = count - 1
    return 0

def scalar_signature(w:mutbuf, record:u64) -> u64:
    at = get(w, record + 8) + 24
    count = get(w, record + 88)
    while count != 0:
        if type_id(w, field(w, at, 19)) > 12:
            return 0
        at = end(w, at)
        count = count - 1
    at = get(w, record + 16) + 24
    count = get(w, record + 96)
    while count != 0:
        if type_id(w, at) > 12:
            return 0
        at = end(w, at)
        count = count - 1
    return 1

def frame_value(w:mutbuf, frame:u64, name:u64) -> u64:
    index = slot(w, get(w, frame + 8), name)
    at = get(w, frame + 56) + index * 16
    if get(w, at) != get(w, frame + 48):
        stop(w, 5, 253, 0)
    return get(w, at + 8)

def frame_type(w:mutbuf, frame:u64, name:u64) -> u64:
    record = get(w, frame + 8)
    return get(w, get(w, record + 56) + slot(w, record, name) * 16 + 8)

def frame_set(w:mutbuf, frame:u64, name:u64, value:u64) -> u64:
    index = slot(w, get(w, frame + 8), name)
    at = get(w, frame + 56) + index * 16
    put(w, at, get(w, frame + 48))
    put(w, at + 8, value)
    return 0

def frame_consume(w:mutbuf, frame:u64, name:u64) -> u64:
    index = slot(w, get(w, frame + 8), name)
    put(w, get(w, frame + 56) + index * 16, 0)
    return 0

def start_block(w:mutbuf, frame:u64, block:u64) -> u64:
    operations = field(w, block, 13)
    put(w, frame + 16, block)
    put(w, frame + 24, operations)
    put(w, frame + 32, operations + 24)
    put(w, frame + 40, total(w, operations))
    return 0

def push_frame(w:mutbuf) -> u64:
    if get(w, 768) == 0:
        if get(w, 520) >= get(w, 408):
            return stop(w, 3, 22, 0)
        if tick(w) == 0:
            return 0
        put(w, 768, 1)
    function = get(w, 736)
    frame = arena(w, get(w, function + 104))
    if frame == 0:
        return 0
    fill_range(w, frame, get(w, function + 104), 0)
    put(w, frame, get(w, 512))
    put(w, frame + 8, function)
    put(w, frame + 48, 1)
    put(w, frame + 56, frame + 128)
    put(w, frame + 64, frame + 128 + get(w, function + 48) * 16)
    put(w, frame + 72, get(w, frame + 64) + get(w, function + 88) * 8)
    put(w, frame + 80, get(w, frame + 72) + get(w, function + 80) * 8)
    put(w, frame + 88, get(w, 752))
    parameters = get(w, function + 8) + 24
    count = get(w, function + 88)
    index = 0
    while index < count:
        value = get(w, get(w, 744) + index * 8)
        put(w, get(w, frame + 64) + index * 8, value)
        frame_set(w, frame, field(w, parameters, 5), value)
        parameters = end(w, parameters)
        index = index + 1
    start_block(w, frame, get(w, function + 32))
    put(w, 512, frame)
    put(w, 520, get(w, 520) + 1)
    put(w, 768, 0)
    put(w, 8, 4)
    return 0

def execute(w:mutbuf) -> u64:
    frame = get(w, 512)
    if get(w, 968) == 0:
        if tick(w) == 0:
            return 0
        put(w, 968, 1)
    if get(w, frame + 40) == 0:
        if reserve_resources(w, get(w, get(w, frame + 8) + 112)) == 0:
            return 0
        put(w, 968, 0)
        return terminator(w, frame, field(w, get(w, frame + 16), 14))
    if reserve_resources(w, 4) == 0:
        return 0
    put(w, 968, 0)
    instruction = get(w, frame + 32)
    put(w, 576, instruction)
    put(w, 584, frame)
    code = opcode_id(w, field(w, instruction, 15))
    put(w, 696, code)
    if code == 50:
        return call_instruction(w, frame, instruction)
    operands(w, frame, field(w, instruction, 16))
    outputs = field(w, instruction, 17)
    typ = 0
    if total(w, outputs) != 0:
        typ = type_id(w, field(w, outputs + 24, 19))
    put(w, 704, typ)
    put(w, 640, 0)
    if code == 1:
        value = literal_value(w, field(w, field(w, instruction, 18), 20), typ)
        put(w, 616, value)
        put(w, 640, 1)
    elif code <= 27:
        mode = cast_id(w, field(w, field(w, instruction, 18), 21))
        value = vm_scalar(w, code, typ, get(w, 840), get(w, 800), get(w, 808), get(w, 816), mode)
        if get(w, 96) != 0:
            put(w, 88, 2)
            return 0
        put(w, 616, value)
        put(w, 640, 1)
    else:
        return resource_operation(w, code)
    return finish_operation(w)

def operands(w:mutbuf, frame:u64, names:u64) -> u64:
    at = names + 24
    count = total(w, names)
    index = 0
    while index < count:
        put(w, 800 + index * 8, frame_value(w, frame, at))
        put(w, 840 + index * 8, frame_type(w, frame, at))
        at = end(w, at)
        index = index + 1
    return 0

def finish_operation(w:mutbuf) -> u64:
    frame = get(w, 584)
    instruction = get(w, 576)
    outputs = field(w, instruction, 17)
    if total(w, outputs) != get(w, 640):
        return stop(w, 5, 252, 0)
    at = outputs + 24
    index = 0
    while index < get(w, 640):
        frame_set(w, frame, field(w, at, 5), get(w, 616 + index * 8))
        at = end(w, at)
        index = index + 1
    put(w, frame + 32, end(w, instruction))
    put(w, frame + 40, get(w, frame + 40) - 1)
    put(w, 8, 4)
    return 0

def call_instruction(w:mutbuf, frame:u64, instruction:u64) -> u64:
    function = function_named(w, field(w, field(w, instruction, 18), 22))
    names = field(w, instruction, 16)
    at = names + 24
    parameter = get(w, function + 8) + 24
    count = total(w, names)
    index = 0
    while index < count:
        put(w, get(w, frame + 72) + index * 8, frame_value(w, frame, at))
        typ = type_id(w, field(w, parameter, 19))
        if typ == 13 or typ == 16:
            frame_consume(w, frame, at)
        at = end(w, at)
        parameter = end(w, parameter)
        index = index + 1
    put(w, 736, function)
    put(w, 744, get(w, frame + 72))
    put(w, 752, instruction)
    put(w, 768, 0)
    put(w, 8, 10)
    return 0

def terminator(w:mutbuf, frame:u64, term:u64) -> u64:
    code = term_id(w, field(w, term, 15))
    if code == 1:
        return return_values(w, frame, field(w, term, 23))
    if code == 4:
        return stop(w, 2, 14 + trap_id(w, field(w, term, 28)), 0)
    edge = term
    if code == 3:
        edge = field(w, term, 26)
        if frame_value(w, frame, field(w, term, 27)) != 0:
            edge = field(w, term, 25)
    names = field(w, edge, 16)
    at = names + 24
    count = total(w, names)
    index = 0
    while index < count:
        put(w, get(w, frame + 72) + index * 8, frame_value(w, frame, at))
        at = end(w, at)
        index = index + 1
    target = block_named(w, get(w, frame + 8), field(w, edge, 24))
    parameters = field(w, target, 6) + 24
    put(w, frame + 48, get(w, frame + 48) + 1)
    index = 0
    while index < count:
        frame_set(w, frame, field(w, parameters, 5), get(w, get(w, frame + 72) + index * 8))
        parameters = end(w, parameters)
        index = index + 1
    return start_block(w, frame, target)

def original_parameter(w:mutbuf, frame:u64, name:u64) -> u64:
    function = get(w, frame + 8)
    at = get(w, function + 8) + 24
    index = 0
    while index < get(w, function + 88):
        if same_text(w, name, field(w, at, 5)) != 0:
            return get(w, get(w, frame + 64) + index * 8)
        at = end(w, at)
        index = index + 1
    stop(w, 5, 251, 0)
    return 0

def return_values(w:mutbuf, frame:u64, names:u64) -> u64:
    function = get(w, frame + 8)
    at = names + 24
    typ = get(w, function + 16) + 24
    origins = get(w, function + 24)
    origin = 0
    if origins != N:
        origin = origins + 24
    index = 0
    while index < total(w, names):
        value = frame_value(w, frame, at)
        kind = type_id(w, typ)
        if kind == 14 or kind == 15:
            parent = original_parameter(w, frame, origin)
            value = returned_view(w, value, parent, kind)
            if get(w, 88) != 0:
                return 0
        put(w, get(w, frame + 80) + index * 16, kind)
        put(w, get(w, frame + 80) + index * 16 + 8, value)
        at = end(w, at)
        typ = end(w, typ)
        if origin != 0:
            origin = end(w, origin)
        index = index + 1
    previous = get(w, frame)
    if previous == 0:
        put(w, 544, get(w, frame + 80))
        put(w, 552, total(w, names))
        put(w, 88, 1)
        return 0
    instruction = get(w, frame + 88)
    outputs = field(w, instruction, 17) + 24
    index = 0
    while index < total(w, names):
        frame_set(w, previous, field(w, outputs, 5), get(w, get(w, frame + 80) + index * 16 + 8))
        outputs = end(w, outputs)
        index = index + 1
    put(w, previous + 32, end(w, instruction))
    put(w, previous + 40, get(w, previous + 40) - 1)
    put(w, 512, previous)
    put(w, 520, get(w, 520) - 1)
    arena_free(w, frame)
    return 0

def literal_value(w:mutbuf, node:u64, typ:u64) -> u64:
    if typ == 12:
        return 0
    if typ == 11:
        return byte(w, node + 16)
    negative = byte(w, node + 16) == 45
    at = node + 16
    if negative:
        at = at + 1
    value = 0
    while at < end(w, node):
        value = value * 10 + byte(w, at) - 48
        at = at + 1
    if negative:
        value = 0 - value
    return value & vm_type_mask(typ)
'''

def source_program():
    from tools.hia_program_execution_resources import BODY as RESOURCE_BODY
    from tools.hia_program_execution_scalars import BODY as SCALAR_BODY
    own = ast.parse(BODY + RESOURCE_BODY + SCALAR_BODY)
    common = {'word', 'put', 'get', 'tag', 'size_of', 'end', 'total', 'element', 'text_is', 'same_text'}
    raw = TRANSPORT_SOURCE.replace('    DISPATCH', '    pass')
    reader = ast.parse(raw)
    for node in reader.body:
        if isinstance(node, ast.FunctionDef) and node.name in common:
            for argument in node.args.args:
                if argument.annotation.id == 'readbuf':
                    argument.annotation.id = 'mutbuf'
            own.body.append(node)
    source_reader = ast.parse(raw)
    for node in source_reader.body:
        if isinstance(node, ast.FunctionDef) and node.name in {'validate', 'word'}:
            class InputReader(ast.NodeTransformer):
                def visit_FunctionDef(self, node):
                    node.name = 'src_' + node.name
                    return self.generic_visit(node)
                def visit_Name(self, node):
                    return ast.copy_location(ast.Name(id='src_word', ctx=node.ctx), node) if node.id == 'word' else node
                def visit_Constant(self, node):
                    if type(node.value) is int and node.value in (128, 136):
                        return ast.copy_location(ast.Constant(node.value + 3968), node)
                    return node
                def visit_Compare(self, node):
                    if (isinstance(node.left, ast.Name) and node.left.id in {'nodes', 'children'}
                            and len(node.comparators) == 1
                            and isinstance(node.comparators[0], ast.Constant)
                            and node.comparators[0].value == 1048576):
                        # Every represented node needs its own 16-byte header.
                        # Count limits follow this actual packet/container extent,
                        # never a presumed public normalization node budget.
                        expr = 'length(s) // 16' if node.left.id == 'nodes' else '(size - 8) // 16'
                        node.comparators[0] = ast.parse(expr, mode='eval').body
                    return self.generic_visit(node)
            # Scratch depth follows verified Core grammar, not the public
            # structure traversal: at most ten enclosing containers including
            # the private wrapper. Argument packets need only three levels.
            node = InputReader().visit(node)
            for item in ast.walk(node):
                if isinstance(item, ast.Compare) and isinstance(item.left, ast.Name) and item.left.id == 'depth':
                    if isinstance(item.comparators[0], ast.Constant) and item.comparators[0].value == 4096:
                        item.comparators[0].value = 128
            own.body.append(node)
    tables = {'field_id': FIELDS, 'opcode_id': tuple(OPCODES), 'type_id': TYPES,
              'schema_id': tuple('hepta.hia.program.v' + str(i) for i in range(1, 9)),
              'term_id': ('ret', 'jump', 'branch', 'trap'),
              'trap_id': ('user', 'overflow', 'division_by_zero', 'bounds', 'allocation'),
              'cast_id': ('checked', 'wrap')}
    for name, words in tables.items():
        lines = [f'def {name}(w:mutbuf, node:u64) -> u64:', '    if node == N:', '        return 0']
        for ident, value in enumerate(words, 1):
            lines += ['    if text_is(w, node, ' + ', '.join(map(str, packed(value))) + ') != 0:',
                      f'        return {ident}']
        lines.append('    return 0')
        own.body.extend(ast.parse('\n'.join(lines)).body)
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node) if node.id in CONSTANTS else node
    return ast.unparse(ast.fix_missing_locations(Expand().visit(own))) + '\n'

def document():
    from tools.hia_program_execution_scalars import ScalarBuilder
    class ExecutionBuilder(ScalarBuilder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in {'copy_in', 'move_within'}:
                    args = [self.expr(arg) for arg in node.args]
                    if name == 'copy_in':
                        return self.op('buffer.copy_range', [args[0], args[1], *[self.cast(v, 'usize') for v in args[2:]]])
                    return self.op('buffer.move_within', [args[0], *[self.cast(v, 'usize') for v in args[1:]]])
            return super().expr(node)
    nodes = ast.parse(source_program()).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name:'f' + str(index) for index,node in enumerate(nodes)}
    signatures = {node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions=[]
    for node in nodes:
        builder=ExecutionBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name], 'params':[builder.param(v) for v in builder.params],
                          'returns':[builder.returns], 'effects':['read','write','trap'],
                          'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'program_execution','functions':functions})

if __name__ == '__main__':
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/program_execution.hepta'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)

