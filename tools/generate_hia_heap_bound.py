"""Author the public heap policy controller as HIA.

The controller orders all public admissions, owns scalar policy and report
construction, and issues once-only opaque-object and pinned native operations.
The live transfer and structural analysis kernels remain separate images.
"""
from __future__ import annotations
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_instruction_policy import SOURCE as TRANSPORT_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_program_execution_scalars import ScalarBuilder
from tools.generate_hia_static_budget import BODY as STATIC_BODY, WRITERS as STATIC_WRITERS
from tools.hia_heap_bound_graphs import BODY as GRAPH_BODY

MAGIC = int.from_bytes(b'HIAHEP01', 'little')
ABI = 0xfffffff1
BASE = 8192
N = (1 << 64) - 1
FIELDS = ('schema','functions','name','params','returns','blocks','id','term','op',
          'ops','out','type','attrs','function','entry','target','then','else',
          'exports','args','value','max_vm_ticks','max_allocator_interactions',
          'max_call_depth','sha256','bounds')
TYPES = ('i8','i16','i32','i64','isize','u8','u16','u32','u64','usize','bool','unit')

BODY = r'''
def heap_policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < BASE:
        return ABI
    if get(w, 0) == 0:
        if initialize(s, w) == 0:
            return ABI
    else:
        if get(w, 0) != MAGIC or get(w, 96) != 0 or get(w, 24) == 0:
            return ABI
        if get(w, 88) != get(w, 16):
            return ABI
        request = get(w, 24)
        if request != 100 and request != 101:
            if capture(s, w) == 0:
                return ABI
        put(w, 24, 0)
        put(w, 88, 0)
    going = True
    while going:
        phase = get(w, 8)
        if phase < 100:
            admission(w, o, phase)
        elif phase < 200:
            analyze(w, o, phase)
        elif phase < 300:
            reporting(w, o, phase)
        elif phase < 400:
            error_report(w, o)
        else:
            return ABI
        if get(w, 24) != 0 or get(w, 96) != 0:
            going = False
    if get(w, 96) != 0:
        if get(w, 96) > 6 or get(w, 16) == N:
            return ABI
        put(w, 16, get(w, 16) + 1)
        put(w, 24, 0)
        return 0
    return get(w, 24)

def initialize(s:readbuf, w:mutbuf) -> u64:
    if src_validate(s, w) == 0 or length(s) > length(w) - BASE:
        return 0
    fill_range(w, 0, 4096, 0)
    copy_in(w, s, BASE, 0, length(s))
    put(w, 64, (BASE + length(s) + 7) & (N - 7))
    if tag(w, BASE) != 5 or total(w, BASE) != 6:
        return 0
    mode = decimal(w, element(w, BASE, 0))
    if mode > 6:
        return 0
    put(w, 0, MAGIC)
    put(w, 8, 1)
    put(w, 120, mode)
    put(w, 128, decimal(w, element(w, BASE, 1)))
    put(w, 136, decimal(w, element(w, BASE, 2)))
    put(w, 144, decimal(w, element(w, BASE, 3)))
    put(w, 168, decimal(w, element(w, BASE, 4)))
    put(w, 176, decimal(w, element(w, BASE, 5)))
    return 1

def issue(w:mutbuf, request:u64, a:u64, b:u64, c:u64, d:u64, phase:u64) -> u64:
    if get(w, 16) == N:
        put(w, 96, 7)
        return 0
    put(w, 16, get(w, 16) + 1)
    put(w, 24, request)
    put(w, 32, a)
    put(w, 40, b)
    put(w, 48, c)
    put(w, 56, d)
    put(w, 8, phase)
    put(w, 104, 0)
    return 0

def need_arena(w:mutbuf, mark:u64) -> u64:
    put(w, 64, mark)
    if get(w, 80) != 0:
        put(w, 96, 7)
        return 0
    return issue(w, 100, get(w, 72), 0, 0, 0, get(w, 8))

def fail(w:mutbuf, kind:u64) -> u64:
    put(w, 400, kind)
    put(w, 8, 390)
    return 0

def decimal(w:mutbuf, node:u64) -> u64:
    if tag(w, node) == 12:
        size = size_of(w, node)
        if size == 0 or size > 9 or byte(w, node + 16) != 0:
            put(w, 96, 7)
            return 0
        value = 0
        index = 1
        while index < size:
            value = value | (byte(w, node + 16 + index) << ((index - 1) * 8))
            index = index + 1
        return value
    value = 0
    index = 0
    while index < size_of(w, node):
        value = value * 10 + byte(w, node + 16 + index) - 48
        index = index + 1
    return value

def response(w:mutbuf, index:u64) -> u64:
    return element(w, get(w, 112), index)

def bool_value(w:mutbuf, node:u64) -> bool:
    return tag(w, node) == 1 and size_of(w, node) == 1 and byte(w, node + 16) != 0

def exact_metadata(w:mutbuf, node:u64, kind:u64) -> bool:
    return tag(w, node) == 5 and total(w, node) == 4 and decimal(w, element(w, node, 0)) == kind

def integer_within(w:mutbuf, node:u64, maximum:u64) -> bool:
    if tag(w, node) == 12:
        count = size_of(w, node)
        if count == 0 or count > 9 or byte(w, node + 16) != 0:
            return False
        index = 1
        number = 0
        while index < count:
            number = number | (byte(w, node + 16 + index) << ((index - 1) * 8))
            index = index + 1
        return number <= maximum
    if tag(w, node) != 2 or size_of(w, node) == 0:
        return False
    index = 0
    number = 0
    while index < size_of(w, node):
        digit = byte(w, node + 16 + index)
        if digit < 48 or digit > 57:
            return False
        digit = digit - 48
        if number > maximum // 10 or (number == maximum // 10 and digit > maximum % 10):
            return False
        number = number * 10 + digit
        index = index + 1
    return True

def find_function(w:mutbuf, name:u64) -> u64:
    functions = field(w, get(w, 192), F_functions)
    index = 0
    while index < total(w, functions):
        fn = element(w, functions, index)
        if same_text(w, field(w, fn, F_name), name) != 0:
            return fn
        index = index + 1
    return N

def static_outcome(w:mutbuf, wrap:bool) -> bool:
    if decimal(w, response(w, 0)) != 0:
        put(w, 344, decimal(w, response(w, 1)))
        put(w, 352, choose(wrap, 5, 4))
        fail(w, 30)
        return False
    return True

def admission(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    mode = get(w, 120)
    reply = get(w, 112)
    if phase == 1:
        if mode == 0 or mode == 6:
            return issue(w, 2, get(w, 128), 0, 0, 0, 10)
        return issue(w, 1, get(w, 168), 0, 0, 0, 2)
    if phase == 2:
        if not exact_metadata(w, reply, 2):
            return fail(w, 1)
        if decimal(w, element(w, reply, 1)) != 0 or decimal(w, element(w, reply, 2)) > 63:
            return fail(w, 1)
        put(w, 256, decimal(w, element(w, reply, 3)))
        if mode == 2:
            return issue(w, 1, get(w, 136), 0, 0, 0, 3)
        return issue(w, 2, get(w, 128), 0, 0, 0, 10)
    if phase == 3:
        if not exact_metadata(w, reply, 4):
            return fail(w, 1)
        return issue(w, 2, get(w, 128), 0, 0, 0, 10)
    if phase == 10:
        put(w, 184, decimal(w, reply))
        if mode == 1:
            return issue(w, 2, get(w, 184), 0, 0, 0, 11)
        return issue(w, 28, get(w, 184), 0, 0, 0, 13)
    if phase == 11:
        return issue(w, 28, decimal(w, reply), 0, 0, 0, 13)
    if phase == 13:
        if tag(w, reply) != 5 or total(w, reply) != 2:
            put(w, 96, 7)
            return 0
        put(w, 456, decimal(w, response(w, 0)))
        put(w, 192, response(w, 1))
        schema = schema_id(w, field(w, get(w, 192), F_schema))
        if mode < 2:
            if schema < 1 or schema > 6:
                return fail(w, 2)
            put(w, 8, 100)
            return 0
        if mode == 6:
            if schema != 1:
                return fail(w, 8)
            return issue(w, 3, get(w, 184), 3, 0, 0, 12)
        target = 8
        if mode == 3:
            target = 7
        return issue(w, 20, get(w, 456), target, 0, 0, 20)
    if phase == 12:
        if bool_value(w, reply):
            return fail(w, 8)
        return issue(w, 1, get(w, 136), 0, 0, 0, 30)
    if phase == 20:
        if not static_outcome(w, mode >= 3):
            return 0
        if mode == 2:
            return issue(w, 3, get(w, 184), 2, 0, 0, 31)
        return issue(w, 21, get(w, 184), 0, 0, 0, 21)
    if phase == 21:
        if not static_outcome(w, True):
            return 0
        put(w, 232, response(w, 1))
        return issue(w, 1, get(w, 136), 0, 0, 0, 30)
    if phase == 30:
        if not exact_metadata(w, reply, 4):
            return fail(w, 4)
        return issue(w, 3, get(w, 184), 2, 0, 0, 31)
    if phase == 31:
        put(w, 248, decimal(w, reply))
        return issue(w, 4, get(w, 136), get(w, 248), 0, 0, 32)
    if phase == 32:
        if not bool_value(w, reply):
            return fail(w, 4)
        if mode >= 3 and mode <= 5:
            return issue(w, 6, get(w, 144), 0, 0, 0, 33)
        return issue(w, 5, get(w, 136), 0, 0, 0, 40)
    if phase == 33:
        if not bool_value(w, reply):
            return fail(w, 4)
        return issue(w, 7, get(w, 144), 0, 0, 0, 34)
    if phase == 34:
        put(w, 208, decimal(w, reply))
        return issue(w, 10, get(w, 144), 0, 0, 0, 35)
    if phase == 35:
        return issue(w, 8, get(w, 208), 0, 0, 0, 36)
    if phase == 36:
        put(w, 440, decimal(w, reply))
        return issue(w, 5, get(w, 136), 0, 0, 0, 40)
    if phase == 40:
        put(w, 200, reply)
        fn = find_function(w, reply)
        if fn == N:
            return fail(w, 4)
        put(w, 272, fn)
        if mode >= 3 and mode <= 5:
            params = field(w, fn, F_params)
            put(w, 280, params)
            count = get(w, 440)
            if total(w, params) != count:
                return fail(w, 5)
            mark = get(w, 64)
            ids = heap_alloc(w, (count + 1) * 8)
            if ids == 0:
                return need_arena(w, mark)
            put(w, ids, count)
            put(w, 216, ids)
            put(w, 224, 0)
            if count != 0:
                return issue(w, 9, get(w, 208), 0, 0, 0, 41)
        put(w, 8, 100)
        return 0
    if phase == 41:
        index = get(w, 224)
        ident = decimal(w, reply)
        put(w, get(w, 216) + 8 + index * 8, ident)
        return issue(w, 1, ident, 0, 0, 0, 42)
    if phase == 42:
        index = get(w, 224)
        param = element(w, get(w, 280), index)
        typ = type_id(w, field(w, param, F_type))
        if not scalar_valid(w, reply, typ):
            return fail(w, 5)
        index = index + 1
        put(w, 224, index)
        if index < get(w, 440):
            return issue(w, 9, get(w, 208), index, 0, 0, 41)
        put(w, 8, 100)
        return 0
    put(w, 96, 7)
    return 0

def scalar_valid(w:mutbuf, node:u64, typ:u64) -> bool:
    if typ == 11:
        return exact_metadata(w, node, 1)
    if typ == 12:
        return exact_metadata(w, node, 0)
    if typ < 1 or typ > 10 or not exact_metadata(w, node, 2):
        return False
    bits = 64
    if typ == 1 or typ == 6:
        bits = 8
    if typ == 2 or typ == 7:
        bits = 16
    if typ == 3 or typ == 8:
        bits = 32
    negative = decimal(w, element(w, node, 1))
    width = decimal(w, element(w, node, 2))
    value = decimal(w, element(w, node, 3))
    if typ >= 6:
        return negative == 0 and width <= bits
    if negative == 0:
        return width < bits
    if width < bits:
        return True
    if width != bits:
        return False
    return value == (0 - (1 << (bits - 1)))

def analyze(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    mode = get(w, 120)
    if phase == 100:
        graph_reset(w)
        packet = graph_begin(w, o, 5, 5)
        kernel_mode = 0
        if mode == 2:
            kernel_mode = 1
        if mode >= 3 and mode <= 5:
            kernel_mode = mode - 1
        graph_u64(w, o, kernel_mode)
        graph_copy(w, o, get(w, 192))
        if mode >= 3:
            graph_copy(w, o, get(w, 200))
        else:
            graph_null(w, o)
        args = graph_begin(w, o, 5, choose(mode >= 3 and mode <= 5, get(w, 440), 0))
        if mode >= 3 and mode <= 5:
            index = 0
            while index < get(w, 440):
                graph_object(w, o, get(w, get(w, 216) + 8 + index * 8))
                index = index + 1
        graph_end(w, o, args)
        graph_object(w, o, get(w, 456))
        graph_end(w, o, packet)
        if graph_ready(w, o) == 0:
            return 0
        request = 22
        if mode == 6:
            request = 23
        return query(w, request, 0, 0, 101)
    if phase == 101:
        if mode == 6:
            put(w, 464, decimal(w, response(w, 0)))
            put(w, 240, response(w, 1))
            if decimal(w, element(w, get(w, 240), 0)) != 0:
                return fail(w, 31)
            put(w, 8, 120)
            return 0
        if decimal(w, response(w, 0)) != 0:
            put(w, 240, get(w, 112))
            return fail(w, 31)
        put(w, 240, get(w, 112))
        if mode == 0:
            put(w, 8, 200)
            return 0
        if mode == 1:
            rows = response(w, 1)
            index = 0
            while index < total(w, rows):
                row = element(w, rows, index)
                if not integer_within(w, element(w, row, 1), get(w, 256)):
                    return fail(w, 3)
                index = index + 1
        elif mode == 2:
            rows = response(w, 1)
            index = 0
            found = False
            while index < total(w, rows):
                row = element(w, rows, index)
                if same_text(w, element(w, row, 0), get(w, 200)) != 0:
                    put(w, 328, element(w, row, 1))
                    put(w, 552, decimal(w, element(w, row, 3)))
                    found = True
                index = index + 1
            if not found:
                put(w, 96, 7)
                return 0
            if not integer_within(w, get(w, 328), get(w, 256)):
                return fail(w, 6)
        elif mode <= 5:
            put(w, 328, response(w, 2))
            put(w, 552, decimal(w, response(w, 6)))
            if not integer_within(w, get(w, 328), get(w, 256)):
                return fail(w, 7)
        if mode >= 2:
            put(w, 8, 108)
            return 0
        return issue(w, 3, get(w, 184), 0, 0, 0, 110)
    if phase == 108:
        return key_query(w, o, get(w, 456), lit('schema'), 109)
    if phase == 109:
        put(w, 544, decimal(w, get(w, 112)))
        return issue(w, 3, get(w, 184), 0, 0, 0, 110)
    if phase == 110:
        put(w, 296, decimal(w, get(w, 112)))
        if mode >= 2:
            return issue(w, 3, get(w, 184), 1, 0, 0, 111)
        put(w, 8, 200)
        return 0
    if phase == 111:
        put(w, 304, decimal(w, get(w, 112)))
        put(w, 8, 200)
        return 0
    if phase == 120:
        return issue(w, 26, get(w, 464), 1, 0, 0, 121)
    if phase == 121:
        put(w, 472, decimal(w, get(w, 112)))
        return issue(w, 26, get(w, 464), 2, 0, 0, 122)
    if phase == 122:
        put(w, 480, decimal(w, get(w, 112)))
        return issue(w, 26, get(w, 464), 3, 0, 0, 123)
    if phase == 123:
        put(w, 488, decimal(w, get(w, 112)))
        rows = element(w, get(w, 240), 3)
        index = 0
        found = N
        while index < total(w, rows):
            if same_text(w, field(w, element(w, rows, index), F_function), get(w, 200)) != 0:
                found = index
            index = index + 1
        if found == N:
            put(w, 96, 7)
            return 0
        return issue(w, 26, get(w, 488), found, 0, 0, 124)
    if phase == 124:
        put(w, 504, decimal(w, get(w, 112)))
        put(w, 8, 125)
        return 0
    if phase == 125:
        return key_query(w, o, get(w, 504), lit('bounds'), 126)
    if phase == 126:
        put(w, 512, decimal(w, get(w, 112)))
        put(w, 8, 127)
        return 0
    if phase == 127:
        return key_query(w, o, get(w, 512), lit('max_allocation_op_executions'), 128)
    if phase == 128:
        put(w, 520, decimal(w, get(w, 112)))
        put(w, 8, 129)
        return 0
    if phase == 129:
        return key_query(w, o, get(w, 512), lit('max_nonzero_allocation_requests'), 130)
    if phase == 130:
        put(w, 528, decimal(w, get(w, 112)))
        put(w, 8, 131)
        return 0
    if phase == 131:
        return key_query(w, o, get(w, 512), lit('max_cumulative_requested_payload_bytes'), 132)
    if phase == 132:
        put(w, 536, decimal(w, get(w, 112)))
        put(w, 8, 108)
        return 0
    put(w, 96, 7)
    return 0

def sorted_rows(w:mutbuf, rows:u64) -> u64:
    count = total(w, rows)
    result = heap_alloc(w, 8 + count * 8)
    if result == 0:
        return 0
    put(w, result, count)
    index = 0
    while index < count:
        row = element(w, rows, index)
        at = index
        going = True
        while going and at > 0:
            previous = get(w, result + at * 8)
            if heap_text_cmp(w, element(w, previous, 0), element(w, row, 0)) <= 1:
                going = False
            else:
                put(w, result + 8 + at * 8, previous)
                at = at - 1
        put(w, result + 8 + at * 8, row)
        index = index + 1
    return result

def peak_mapping(w:mutbuf, o:mutbuf, sorted:u64) -> u64:
    rows = element(w, get(w, 240), 1)
    count = total(w, rows)
    root = graph_begin(w, o, 6, count)
    index = 0
    while index < count:
        row = element(w, rows, index)
        if sorted != 0:
            row = get(w, sorted + 8 + index * 8)
        graph_object(w, o, decimal(w, element(w, row, 2)))
        graph_object(w, o, decimal(w, element(w, row, 3)))
        index = index + 1
    graph_end(w, o, root)
    return 0

def local_summaries(w:mutbuf, o:mutbuf) -> u64:
    rows = element(w, get(w, 240), 1)
    root = graph_begin(w, o, 5, total(w, rows))
    index = 0
    while index < total(w, rows):
        row = element(w, rows, index)
        item = graph_begin(w, o, 6, 2)
        graph_literal(w, o, lit('function'))
        graph_object(w, o, decimal(w, element(w, row, 2)))
        graph_literal(w, o, lit('max_additional_local_payload_bytes'))
        graph_object(w, o, decimal(w, element(w, row, 3)))
        graph_end(w, o, item)
        index = index + 1
    graph_end(w, o, root)
    return 0

def static_row(w:mutbuf) -> u64:
    rows = field(w, get(w, 232), F_functions)
    index = 0
    while index < total(w, rows):
        row = element(w, rows, index)
        if same_text(w, field(w, row, F_function), get(w, 200)) != 0:
            return row
        index = index + 1
    return N

def arguments_graph(w:mutbuf, o:mutbuf) -> u64:
    root = graph_begin(w, o, 5, get(w, 440))
    index = 0
    while index < get(w, 440):
        graph_object(w, o, get(w, get(w, 216) + 8 + index * 8))
        index = index + 1
    graph_end(w, o, root)
    return 0

def reporting(w:mutbuf, o:mutbuf, phase:u64) -> u64:
    mode = get(w, 120)
    if phase == 200:
        mark = get(w, 64)
        order = 0
        if mode == 1:
            order = sorted_rows(w, element(w, get(w, 240), 1))
            if order == 0:
                return need_arena(w, mark)
        graph_reset(w)
        if mode == 0:
            peak_mapping(w, o, 0)
        elif mode == 1:
            live_report(w, o, order)
        elif mode == 2:
            borrowed_report(w, o)
        elif mode <= 5:
            finite_report(w, o)
        else:
            payload_report(w, o)
        put(w, 64, mark)
        if graph_ready(w, o) == 0:
            return 0
        if mode <= 1:
            put(w, 104, get(w, 152))
            put(w, 96, 1)
            return 0
        return query(w, 24, 0, 0, 201)
    if phase == 201:
        put(w, 312, decimal(w, response(w, 0)))
        put(w, 320, response(w, 1))
        put(w, 8, 202)
        return 0
    if phase == 202:
        graph_reset(w)
        pair = graph_begin(w, o, 5, 2)
        graph_literal(w, o, lit('sha256'))
        graph_copy(w, o, get(w, 320))
        graph_end(w, o, pair)
        if graph_ready(w, o) == 0:
            return 0
        return query(w, 25, get(w, 312), 0, 203)
    if phase == 203:
        graph_reset(w)
        graph_object(w, o, get(w, 312))
        if graph_ready(w, o) == 0:
            return 0
        put(w, 104, get(w, 152))
        put(w, 96, 1)
        return 0
    put(w, 96, 7)
    return 0
'''

LIVE_CLAIMS = {
 'canonical_core_reverified':True,'requested_live_payload_bounded':True,
 'source_origin_authenticated':False,'allocator_interactions_bounded':False,
 'vm_ticks_bounded':False,'process_rss_bounded':False,
 'native_backend_refinement_proved':False,'whole_language_soundness_proved':False}
BORROWED_CLAIMS = {
 'canonical_core_and_return_origins_reverified':True,
 'public_entry_total_requested_payload_bounded':True,
 'callee_external_payload_excluded_from_local_summaries':True,
 'all_private_entry_total_payload_bounded':False,
 'caller_values_or_external_extent_promises_trusted':False,
 'owned_call_transfer_or_chain_storage_bounded':False,
 'allocator_interactions_or_vm_ticks_bounded':False,
 'termination_or_unwinding_proved':False,'process_rss_or_native_stack_bytes_bounded':False,
 'source_or_native_backend_refinement_proved':False,'whole_language_soundness_proved':False}
FINITE_CLAIMS = {
 'canonical_core_reverified':True,'whole_module_acyclic_byte_profile_checked':True,
 'exact_scalar_invocation_only':True,'owned_call_transfer_accounted':True,
 'external_borrow_payload_counted_in_caller':True,
 'allocation_failure_and_stop_prefixes_in_bound':True,
 'all_function_input_extents_bounded':False,'caller_supplied_resource_extents_trusted':False,
 'branch_reachability_proved':False,'cleanup_after_trap_or_budget_stop_proved':False,
 'recursive_chain_storage_bounded':False,'process_rss_or_native_stack_bytes_bounded':False,
 'source_or_native_backend_refinement_proved':False,'whole_language_soundness_proved':False}
V8_CLAIMS={'canonical_return_origins_reverified':True,'returned_loan_caller_roots_preserved':True,
 'borrowed_returns_allocate_payload':False}
EXTENT_CLAIMS={'borrowed_extents_derived_from_canonical_caller_roots':True,
 'borrowed_extents_in_call_context_key':True,'borrowed_length_upper_bounds_propagated':True,
 'borrowed_lengths_assumed_exact':False}

def _literal(value):
    return 'graph_literal(w, o, lit('+repr(value)+'))'

def _claims(name, values):
    lines=[f'def {name}(w:mutbuf, o:mutbuf) -> u64:',
           f'    root = graph_begin(w, o, 6, {len(values)})']
    for key,value in values.items():
        lines += ['    '+_literal(key), f'    graph_bool(w, o, {value})']
    lines += ['    graph_end(w, o, root)','    return 0']
    return '\n'.join(lines)+'\n'

def reports():
    source=_claims('live_claims',LIVE_CLAIMS)+_claims('borrowed_claims',BORROWED_CLAIMS)
    for mode,extra in ((3,{}),(4,V8_CLAIMS),(5,{**V8_CLAIMS,**EXTENT_CLAIMS})):
        source+=_claims('finite_claims_'+str(mode),{**FINITE_CLAIMS,**extra})
    def record(name, fields, parameters=''):
        lines=[f'def {name}(w:mutbuf, o:mutbuf{parameters}) -> u64:',
               f'    root = graph_begin(w, o, 6, {len(fields)})']
        for key,statements in fields:
            lines+=['    '+_literal(key)]
            lines+=['    '+line for line in statements]
        return '\n'.join(lines+['    graph_end(w, o, root)','    return 0'])+'\n'
    source+=record('live_report',[
        ('schema',[_literal('hepta.hia.live-heap-admission.v1')]),
        ('status',[_literal('standalone_verified_hia_payload_only')]),
        ('program_sha256',['graph_object(w, o, get(w, 296))']),
        ('limit_bytes',['graph_object(w, o, get(w, 168))']),
        ('peak_bounds',['peak_mapping(w, o, order)']),
        ('claims',['live_claims(w, o)'])],', order:u64')
    source+=record('borrowed_report',[
        ('schema',[_literal('hepta.hia.entry-live-heap-admission.v1')]),
        ('profile',[_literal('borrowed-call-local-peaks-v8')]),
        ('status',[_literal('qualified_public_entry_requested_payload_only')]),
        ('core_schema',['graph_object(w, o, get(w, 544))']),
        ('core_sha256',['graph_object(w, o, get(w, 296))']),
        ('input_sha256',['graph_object(w, o, get(w, 304))']),
        ('function',['graph_object(w, o, get(w, 136))']),
        ('limit_bytes',['graph_object(w, o, get(w, 168))']),
        ('peak_bound_bytes',['graph_object(w, o, get(w, 552))']),
        ('local_peak_summaries',['local_summaries(w, o)']),
        ('claims',['borrowed_claims(w, o)'])])
    source+=record('analysis_work',[
        ('contexts',['graph_object(w, o, decimal(w, element(w, get(w, 240), 7)))']),
        ('transfer_steps',['graph_object(w, o, decimal(w, element(w, get(w, 240), 8)))']),
        ('peak_analysis_call_depth',['graph_object(w, o, decimal(w, element(w, get(w, 240), 9)))']),
        ('max_contexts',['graph_u64(w, o, 1024)']),
        ('max_transfer_steps',['graph_u64(w, o, 32768)']),
        ('max_analysis_call_depth',['graph_u64(w, o, 64)'])])
    source+=record('finite_report',[
        ('schema',["mode = get(w, 120)","if mode == 3:","    "+_literal('hepta.hia.finite-entry-live-heap-admission.v1'),
                    "elif mode == 4:","    "+_literal('hepta.hia.finite-entry-live-heap-admission.v2'),
                    "else:","    "+_literal('hepta.hia.finite-entry-live-heap-admission.v3')]),
        ('profile',["if mode == 3:","    "+_literal('acyclic-byte-owner-transfer-v7'),
                     "elif mode == 4:","    "+_literal('acyclic-byte-owner-transfer-parameter-loans-v8'),
                     "else:","    "+_literal('acyclic-byte-owner-transfer-caller-borrowed-extents-v8')]),
        ('status',[_literal('qualified_exact_scalar_invocation_requested_payload_only')]),
        ('core_schema',['graph_object(w, o, get(w, 544))']),
        ('core_sha256',['graph_object(w, o, get(w, 296))']),
        ('input_sha256',['graph_object(w, o, get(w, 304))']),
        ('function',['graph_object(w, o, get(w, 136))']),
        ('arguments',['arguments_graph(w, o)']),
        ('limit_bytes',['graph_object(w, o, get(w, 168))']),
        ('peak_bound_bytes',['graph_object(w, o, get(w, 552))']),
        ('max_vm_ticks',['row = static_row(w)','graph_copy(w, o, field(w, row, F_max_vm_ticks))']),
        ('max_allocator_interactions',['graph_copy(w, o, field(w, row, F_max_allocator_interactions))']),
        ('max_call_depth',['graph_copy(w, o, field(w, row, F_max_call_depth))']),
        ('static_budget_sha256',['graph_copy(w, o, field(w, get(w, 232), F_sha256))']),
        ('analysis_work',['analysis_work(w, o)']),
        ('claims',['if mode == 3:','    finite_claims_3(w, o)','elif mode == 4:',
                   '    finite_claims_4(w, o)','else:','    finite_claims_5(w, o)'])])
    return source

ERRORS = r'''
def error_report(w:mutbuf, o:mutbuf) -> u64:
    kind = get(w, 400)
    mode = get(w, 120)
    graph_reset(w)
    if kind == 30:
        graph_u64(w, o, get(w, 344))
        if graph_ready(w, o) == 0:
            return 0
        put(w, 104, get(w, 152))
        put(w, 96, get(w, 352))
        return 0
    if kind == 31:
        kernel_error(w, o)
        return 0
    root = graph_begin(w, o, 5, 2)
    if kind == 1:
        graph_literal(w, o, lit('E_HIA_BUDGET_POLICY'))
        if mode == 1:
            graph_literal(w, o, lit('requested-live-payload policy must be an integer in 0..2^63-1'))
        elif mode == 2:
            graph_literal(w, o, lit('entry requires a function name and integer payload policy in 0..2^63-1'))
        else:
            graph_literal(w, o, lit('finite invocation payload policy must be an integer in 0..2^63-1'))
    elif kind == 2:
        graph_literal(w, o, lit('E_HIA_BUDGET_UNBOUNDED'))
        graph_literal(w, o, lit('unknown HIA executable schema needs a fresh heap-bound review'))
    elif kind == 4:
        if mode == 2:
            graph_literal(w, o, lit('E_HIA_BUDGET_PROFILE'))
            graph_literal(w, o, lit('payload entry must be an admitted public scalar function'))
        elif mode == 6:
            graph_literal(w, o, lit('E_HIA_BUDGET_INPUT'))
            graph_literal(w, o, lit('payload bound requires an admitted public scalar entry'))
        else:
            graph_literal(w, o, lit('E_HIA_BUDGET_INPUT'))
            graph_literal(w, o, lit('finite invocation requires a public scalar entry and exact arguments'))
    elif kind == 5:
        graph_literal(w, o, lit('E_HIA_BUDGET_INPUT'))
        graph_literal(w, o, lit('entry arguments are not exactly typed machine values'))
    elif kind == 8:
        graph_literal(w, o, lit('E_HIA_BUDGET_PROFILE'))
        graph_literal(w, o, lit('entry payload analysis requires primitive Core v1'))
    elif kind == 6 or kind == 7:
        graph_literal(w, o, lit('E_HIA_BUDGET_EXCEEDED'))
        at = get(w, 152)
        graph_word(w, o, 4)
        graph_word(w, o, 0)
        text_bytes(w, o, get(w, 200))
        if kind == 6:
            literal_bytes(w, o, lit(': live payload entry bound exceeds policy'))
        else:
            literal_bytes(w, o, lit(': finite invocation payload bound exceeds policy'))
        graph_end(w, o, at)
    else:
        graph_literal(w, o, lit('E_HIA_BUDGET_EXCEEDED'))
        at = get(w, 152)
        graph_word(w, o, 4)
        graph_word(w, o, 0)
        literal_bytes(w, o, lit('live payload budget is exceeded by '))
        mark = get(w, 64)
        order = sorted_rows(w, element(w, get(w, 240), 1))
        if order == 0:
            return need_arena(w, mark)
        index = 0
        emitted = 0
        while index < get(w, order):
            row = get(w, order + 8 + index * 8)
            if not integer_within(w, element(w, row, 1), get(w, 256)):
                if emitted != 0:
                    literal_bytes(w, o, lit(', '))
                text_bytes(w, o, element(w, row, 0))
                emitted = emitted + 1
            index = index + 1
        put(w, 64, mark)
        graph_end(w, o, at)
    graph_end(w, o, root)
    if graph_ready(w, o) == 0:
        return 0
    put(w, 104, get(w, 152))
    put(w, 96, 2)
    return 0
'''

def _selected(text, names):
    return [n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name in names]

def source_program():
    # The imported functions are representation-only HIA routines, not the
    # static controller, its policy, its report builders or its heap callbacks.
    own=ast.parse(BODY+reports()+ERRORS+PAYLOAD_AND_ERRORS)
    own.body += _selected(STATIC_BODY,{'capture','field'})
    own.body += _selected(STATIC_WRITERS,{
      'graph_reset','append_byte','graph_word','graph_begin','graph_end','graph_null',
      'graph_bool','graph_u64','graph_object','graph_copy','text_bytes','emit',
      'graph_literal','graph_ready','query'})
    own.body += _selected(GRAPH_BODY,{'heap_alloc','heap_text_cmp'})
    raw=TRANSPORT_SOURCE.replace('    DISPATCH','    pass')
    for n in _selected(raw,{'word','put','get','tag','size_of','end','total','element','text_is','same_text'}):
        for a in n.args.args:
            if a.annotation.id=='readbuf':a.annotation.id='mutbuf'
        own.body.append(n)
    class Reader(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            n.name='src_'+n.name
            return self.generic_visit(n)
        def visit_Name(self,n):
            if n.id=='word':return ast.copy_location(ast.Name(id='src_word',ctx=n.ctx),n)
            return n
        def visit_Constant(self,n):
            if type(n.value) is int and n.value in (128,136):
                return ast.copy_location(ast.Constant(n.value+3968),n)
            return n
        def visit_Compare(self,n):
            if isinstance(n.left,ast.Name) and n.left.id in {'nodes','children'} and len(n.comparators)==1 and isinstance(n.comparators[0],ast.Constant) and n.comparators[0].value==1048576:
                n.comparators[0]=ast.parse('length(s) // 16' if n.left.id=='nodes' else '(size - 8) // 16',mode='eval').body
            return self.generic_visit(n)
    for n in _selected(raw,{'validate','word'}):
        n=Reader().visit(n)
        for item in ast.walk(n):
            if isinstance(item,ast.Compare) and isinstance(item.left,ast.Name) and item.left.id=='depth' and isinstance(item.comparators[0],ast.Constant) and item.comparators[0].value==4096:
                item.comparators[0].value=128
        if n.name=='src_validate':
            text=ast.unparse(n).replace('if kind > 7:','if kind > 7 and kind != 12:')
            text=text.replace('if kind == 0 and size != 0:', 'if kind == 12:\n                    if size == 0 or byte(s, at + 16) > 1:\n                        return 0\n                    if size == 1 and byte(s, at + 16) != 0:\n                        return 0\n                    if size > 1 and byte(s, finish - 1) == 0:\n                        return 0\n                if kind == 0 and size != 0:')
            n=ast.parse(text).body[0]
        own.body.append(n)
    for name,values in {'field_id':FIELDS,'type_id':TYPES,
                       'schema_id':tuple('hepta.hia.program.v'+str(i) for i in range(1,9))}.items():
        lines=[f'def {name}(w:mutbuf, node:u64) -> u64:',
               '    if node == N or tag(w, node) != 4:', '        return 0']
        for index,value in enumerate(values,1):
            b=value.encode(); checks=[f'size_of(w, node) == {len(b)}']
            for start in range(0,len(b),8):
                part=b[start:start+8];mask=(1<<(8*len(part)))-1
                checks.append(f'(word(w, node + {16+start}) & {mask}) == {int.from_bytes(part,"little")}')
            lines += ['    if '+' and '.join(checks)+':',f'        return {index}']
        lines += ['    return 0']
        own.body += ast.parse('\n'.join(lines)).body
    literals=[]
    class Literals(ast.NodeTransformer):
        def visit_Call(self,n):
            if isinstance(n.func,ast.Name) and n.func.id=='lit':
                value=n.args[0].value
                if value not in literals:literals.append(value)
                return ast.copy_location(ast.Constant(literals.index(value)+1),n)
            return self.generic_visit(n)
    own=Literals().visit(own)
    # Keep every literal ID and emitted byte unchanged while respecting the
    # original per-function 256-block limit. Each group has at most 48 exact
    # choices; the dispatcher only chooses its immutable numbered group.
    lines=['def literal_bytes(w:mutbuf, o:mutbuf, ident:u64) -> u64:']
    for start in range(0,len(literals),48):
        stop=min(start+48,len(literals))
        lines += [f'    if ident <= {stop}:',
                  f'        return literal_group_{start//48}(w, o, ident)']
    lines.append('    return 0')
    for start in range(0,len(literals),48):
        lines.append(f'def literal_group_{start//48}(w:mutbuf, o:mutbuf, ident:u64) -> u64:')
        for index,value in enumerate(literals[start:start+48],start+1):
            lines.append(f'    if ident == {index}:')
            data=value.encode('utf-8')
            for at in range(0,len(data),24):
                part=data[at:at+24];padded=part+b'\0'*(24-len(part))
                words=[len(part),*(int.from_bytes(padded[k:k+8],'little') for k in (0,8,16))]
                lines.append('        emit(w, o, '+', '.join(map(str,words))+')')
            lines.append('        return 0')
        lines.append('    return 0')
    own.body+=ast.parse('\n'.join(lines)).body
    constants={'MAGIC':MAGIC,'ABI':ABI,'BASE':BASE,'N':N,**{'F_'+n:i for i,n in enumerate(FIELDS,1)}}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,n):
            return ast.copy_location(ast.Constant(constants[n.id]),n) if n.id in constants else n
    own=ast.fix_missing_locations(Expand().visit(own))
    names={n.name:n for n in own.body}
    reachable={'heap_policy'};todo=['heap_policy']
    while todo:
        node=names[todo.pop()]
        for call in ast.walk(node):
            if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id in names and call.func.id not in reachable:
                reachable.add(call.func.id);todo.append(call.func.id)
    own.body=[n for n in own.body if n.name in reachable]
    return ast.unparse(own)+'\n'

def document():
    class HeapBuilder(ScalarBuilder):
        def expr(self,node):
            if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not):
                return self.op('bool.not',[self.expr(node.operand)],'bool')
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='copy_in':
                args=[self.expr(a) for a in node.args]
                return self.op('buffer.copy_range',[args[0],args[1],*[self.cast(v,'usize') for v in args[2:]]])
            return super().expr(node)
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=HeapBuilder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
          'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'heap_bound','functions':functions})

PAYLOAD_CLAIMS = {
 'canonical_core_reverified':True,'entire_module_closed_v1_profile_checked':True,
 'all_typed_scalar_inputs_and_allocation_outcomes':True,
 'finite_trace_prefixes_including_trap_and_budget_stop':True,
 'private_summaries_count_only_new_requests':True,
 'owner_transfer_not_counted_as_new_allocation':True,
 'branch_feasibility_or_tightest_bound_proved':False,
 'private_external_owner_extents_bounded':False,
 'termination_or_cleanup_after_abort_proved':False,
 'free_calls_vm_ticks_or_owner_metadata_bounded':False,
 'native_stack_allocator_overhead_or_rss_bounded':False,
 'source_or_native_backend_refinement_proved':False,
 'whole_language_soundness_proved':False,
 'native_runtime_or_optimizer_admission_authority':False}

PAYLOAD_AND_ERRORS = r'''
def key_query(w:mutbuf, o:mutbuf, ident:u64, key:u64, phase:u64) -> u64:
    graph_reset(w)
    graph_literal(w, o, key)
    if graph_ready(w, o) == 0:
        return 0
    return query(w, 27, ident, 0, phase)

def maybe_text(w:mutbuf, o:mutbuf, node:u64) -> u64:
    if tag(w, node) == 0:
        literal_bytes(w, o, lit('None'))
    else:
        text_bytes(w, o, node)
    return 0

def kernel_error(w:mutbuf, o:mutbuf) -> u64:
    data = get(w, 240)
    code = decimal(w, element(w, data, 1))
    fn = element(w, data, 2)
    block = element(w, data, 3)
    extra = element(w, data, 4)
    mode = get(w, 120)
    root = graph_begin(w, o, 5, 2)
    state = 2
    if code == 40:
        graph_literal(w, o, lit('E_HIA_BUDGET_GRAPH'))
    elif code == 50 or code == 51:
        graph_literal(w, o, lit('E_HIA_BUDGET_LIMIT'))
    elif code >= 1001 and code <= 1003:
        graph_literal(w, o, lit('E_HIA_BUDGET_PROFILE'))
    elif code == 1000:
        graph_literal(w, o, lit('E_HIA_BUDGET_INPUT'))
    else:
        graph_literal(w, o, lit('E_HIA_BUDGET_UNBOUNDED'))
    at = get(w, 152)
    graph_word(w, o, 4)
    graph_word(w, o, 0)
    if code == 40 or code == 41:
        if mode == 6:
            literal_bytes(w, o, lit('entry payload call graph'))
        elif tag(w, fn) != 0:
            text_bytes(w, o, fn)
            literal_bytes(w, o, lit(' heap control flow'))
        elif mode <= 1:
            literal_bytes(w, o, lit('HIA heap call graph'))
        else:
            literal_bytes(w, o, lit('v8 borrowed-call heap graph'))
        if code == 40:
            literal_bytes(w, o, lit(': unknown dependency'))
        else:
            literal_bytes(w, o, lit(': recursion or CFG cycle requires a separate invariant'))
        state = 3
        if mode >= 3:
            state = 6
    elif code >= 1000:
        payload_error_detail(w, o, code, fn, block, extra)
    else:
        if code >= 10 and code <= 15:
            maybe_text(w, o, fn)
            literal_bytes(w, o, lit(': '))
        elif (code >= 1 and code <= 5) or (code >= 20 and code <= 36) or code == 105:
            maybe_text(w, o, fn)
            literal_bytes(w, o, lit('/'))
            maybe_text(w, o, block)
            literal_bytes(w, o, lit(': '))
        live_error_detail(w, o, code, extra)
    if get(w, 96) == 7:
        return 0
    graph_end(w, o, at)
    graph_end(w, o, root)
    if graph_ready(w, o) == 0:
        return 0
    put(w, 104, get(w, 152))
    put(w, 96, state)
    return 0

def payload_error_detail(w:mutbuf, o:mutbuf, code:u64, fn:u64, block:u64, extra:u64) -> u64:
    if code == 1004 or code > 1008:
        put(w, 96, 7)
        return 0
    if code == 1000:
        return literal_bytes(w, o, lit('payload bound requires an admitted public scalar entry'))
    if code == 1001:
        return literal_bytes(w, o, lit('unreviewed v1 terminator'))
    if code == 1002 or code == 1003:
        text_bytes(w, o, fn)
        literal_bytes(w, o, lit(': '))
        if code == 1002:
            return literal_bytes(w, o, lit('unreviewed v1 payload opcode'))
        return literal_bytes(w, o, lit('unreviewed v1 type'))
    text_bytes(w, o, fn)
    literal_bytes(w, o, lit('/'))
    text_bytes(w, o, block)
    literal_bytes(w, o, lit(': '))
    if code == 1005:
        return literal_bytes(w, o, lit('allocator opcode in a CFG cycle'))
    if code == 1006:
        return literal_bytes(w, o, lit('allocation size needs an earlier same-block const usize in 0..2^63-1'))
    if code == 1007:
        literal_bytes(w, o, lit('CFG cycle calls allocator-bearing '))
        return text_bytes(w, o, extra)
    return literal_bytes(w, o, lit('nonzero cyclic call payload summary'))

def payload_report(w:mutbuf, o:mutbuf) -> u64:
    root = graph_begin(w, o, 6, 12)
    graph_literal(w, o, lit('schema'))
    graph_literal(w, o, lit('hepta.hia.entry-payload-analysis.v1'))
    graph_literal(w, o, lit('profile'))
    graph_literal(w, o, lit('primitive-v1-local-constant-allocation-free-cycles'))
    graph_literal(w, o, lit('status'))
    graph_literal(w, o, lit('checked_static_payload_bound_not_runtime_admission'))
    graph_literal(w, o, lit('core_schema'))
    graph_object(w, o, get(w, 544))
    graph_literal(w, o, lit('core_sha256'))
    graph_object(w, o, get(w, 296))
    graph_literal(w, o, lit('input_sha256'))
    graph_object(w, o, get(w, 304))
    graph_literal(w, o, lit('function'))
    graph_object(w, o, get(w, 136))
    graph_literal(w, o, lit('entry_bounds'))
    bounds = graph_begin(w, o, 6, 4)
    graph_literal(w, o, lit('max_allocation_op_executions'))
    graph_object(w, o, get(w, 520))
    graph_literal(w, o, lit('max_nonzero_allocation_requests'))
    graph_object(w, o, get(w, 528))
    graph_literal(w, o, lit('max_cumulative_requested_payload_bytes'))
    graph_object(w, o, get(w, 536))
    graph_literal(w, o, lit('max_live_payload_bytes'))
    graph_object(w, o, get(w, 536))
    graph_end(w, o, bounds)
    graph_literal(w, o, lit('call_graph'))
    graph_object(w, o, get(w, 472))
    graph_literal(w, o, lit('callee_first_order'))
    graph_object(w, o, get(w, 480))
    graph_literal(w, o, lit('function_summaries'))
    graph_object(w, o, get(w, 488))
    graph_literal(w, o, lit('claims'))
    payload_claims(w, o)
    graph_end(w, o, root)
    return 0
'''

def _live_error_detail():
    from tools.hia_heap_live_engine import ERROR_DETAILS
    lines=['def live_error_detail(w:mutbuf, o:mutbuf, code:u64, extra:u64) -> u64:']
    for code,detail in ERROR_DETAILS.items():
        lines.append(f'    if code == {code}:')
        if '{extra}' in detail:
            before,after=detail.split('{extra}')
            lines += [f'        literal_bytes(w, o, lit({before!r}))',
                      '        maybe_text(w, o, extra)',
                      f'        return literal_bytes(w, o, lit({after!r}))']
        else:
            lines.append(f'        return literal_bytes(w, o, lit({detail!r}))')
    lines += ['    put(w, 96, 7)','    return 0']
    return '\n'.join(lines)+'\n'
PAYLOAD_AND_ERRORS += _claims('payload_claims',PAYLOAD_CLAIMS)+_live_error_detail()


if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args=parser.parse_args()
    target=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/heap_bound.hepta'
    generated=render_assembly(document()).encode('utf-8')
    if args.check:
        if target.read_bytes()!=generated:
            raise SystemExit('native heap controller source differs')
    else:
        target.write_bytes(generated)
