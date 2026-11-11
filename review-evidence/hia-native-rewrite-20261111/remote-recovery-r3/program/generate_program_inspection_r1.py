"""Author a native program-report Graph projector, new reconstruction r1.

This private projector consumes an actually issued readonly Core Graph and a
controller-owned metadata command. It is not a verifier: the enclosing HIA
service must finish complete program admission before calling it and bind both
canonical digests to that actual child result. Python here only authors HIA.
No generation, compilation, or semantic success is inferred from this source.
"""
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REFERENCE=BASE/"root-recovery/reference-0ef-r2"
WORK=BASE/"root-recovery/workspace"
ROOT=WORK/"native-program-service-reconstructed-r1"
HELPER=WORK/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
sys.path.insert(0,str(REFERENCE))
from hepta.hia_agent_assembly import render_assembly,assemble_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
import importlib.util
_spec=importlib.util.spec_from_file_location("program_projection_copy_builder",HELPER)
_helper=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_helper)
CopyBuilder=_helper.CopyBuilder

LITERALS=[
 "schema","ok","profile","program_sha256","input_sha256","normalization",
 "word_bits","functions_checked","blocks_checked","source_required","claims",
 "status","native_executed","standalone_core_checked",
 "core_sha256","input_schema","input_profile","core_schema","core_profile",
 "structured_elaboration_rechecked","primitive_core_rechecked","source_ast_required",
 "public_scalar_entrypoints","typed_closed_ssa_checked",
 "linear_resources_and_loan_provenance_checked","whole_language_soundness_proved",
 "backend_refinement_proved","foreign_code_supported","escaping_loans_supported",
 "parameter_bound_loan_returns_supported","concurrency_supported",
 "nominal_products_and_enums_checked","local_stored_loan_identity_checked",
 "record_field_borrow_provenance_checked","cooperative_task_protocol_checked",
 "background_tasks_supported","recursive_heap_adts_supported",
 "recursive_buffer_chains_supported","preemptive_or_async_cancellation_supported",
 "module","functions","name","params","returns","effects","return_loans","blocks",
 "id","operations","term","ops","index","op","args","out","attrs","exports","type",
 "hepta.hia.program-verification.v1","hepta.hia.inspect.v1","hepta.hia.inspect.v2",
 "i8","i16","i32","i64","isize","u8","u16","u32","u64","usize","bool","unit",
]
SCHEMAS=["hepta.hia.program.v"+str(i) for i in range(1,9)]+[
 "hepta.hia.composite.v"+str(i) for i in range(1,5)]
PROFILES=[
 "closed-ssa-integer-byte-resources-64-v1",
 "closed-ssa-integer-byte-resources-bulk-64-v2",
 "closed-ssa-integer-byte-resources-overlap-64-v3",
 "closed-ssa-integer-byte-resources-swap-64-v4",
 "closed-ssa-integer-byte-resources-offset-copy-64-v5",
 "closed-ssa-integer-byte-resources-range-fill-64-v6",
 "closed-ssa-integer-recursive-buffer-chain-64-v7",
 "closed-ssa-parameter-loan-returns-64-v8",
 "nominal-products-enums-cooperative-tasks-over-closed-ssa-v6",
 "nominal-products-enums-cooperative-tasks-over-closed-ssa-v7",
 "nominal-partial-records-enums-cooperative-tasks-over-closed-ssa-v7",
 "nominal-partial-records-parameter-field-loan-returns-over-closed-ssa-v8",
]
LITERALS+=SCHEMAS+PROFILES
assert len(set(LITERALS))==len(LITERALS)
CODES={name:i+1 for i,name in enumerate(LITERALS)}
CONSTANTS={
 "GRAPH_MAGIC":int.from_bytes(b"HIAGRF01","little"),
 "COMMAND_MAGIC":int.from_bytes(b"HIAPIC01","little"),
 "EVENT_MAGIC":int.from_bytes(b"HIAPIE01","little"),
 "MAX":(1<<64)-1,"BAD":0xfffffffd,"GROW":0xfffffffe,
 "MIN_WORK":65536,"OUT_BASE":65536,"LIT_INDEX":2048,"LIT_DATA":4096,
 "SORT_BASE":16384,"SAVED_COMMAND":512,
}
_NAMES=("STATUS","ERROR","PASS","NEW_N","NEW_E","NEW_D","OUT_N","OUT_E","OUT_D",
 "OUT_SIZE","ROOT","NN","NE","ND","DB","COREVER","INSCHEMA","NFN","NBLOCK",
 "NEXPORT","TRUE","FALSE","NULL","NEED","LEASE","SEQ","COMMAND_MODE")
CONSTANTS.update({"S_"+name:256+i*8 for i,name in enumerate(_NAMES)})
CONSTANTS.update({"K_"+name:CODES[name] for name in LITERALS if name.isidentifier()})
CONSTANTS.update(VERIFICATION_SCHEMA=CODES["hepta.hia.program-verification.v1"],
 INSPECT_V1=CODES["hepta.hia.inspect.v1"],INSPECT_V2=CODES["hepta.hia.inspect.v2"])
SOURCE=r'''
def project_report(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < MIN_WORK:
        return BAD
    if get(w, S_STATUS) >= 2:
        return refused(w, 1)
    if length(r) != 160 or length(s) < 64:
        return refused(w, 2)
    if word(r, 0) != COMMAND_MAGIC or word(r, 8) == 0 or word(r, 16) == 0:
        return refused(w, 3)
    if word(r, 24) == 0 or word(r, 24) > 4:
        return refused(w, 4)
    if word(r, 128) != length(s) or word(r, 136) != 0 or word(r, 144) != 0 or word(r, 152) != 0:
        return refused(w, 5)
    if word(s, 0) != GRAPH_MAGIC or word(s, 8) != word(r, 8) or word(s, 24) != word(r, 32):
        return refused(w, 6)
    if word(s, 48) != length(s) or word(s, 56) != 0:
        return refused(w, 7)
    nodes = word(s, 16)
    edges = word(s, 32)
    if nodes == 0 or nodes > (length(s) - 64) >> 6:
        return refused(w, 8)
    edgebase = 64 + nodes * 64
    if edges > (length(s) - edgebase) >> 3:
        return refused(w, 9)
    database = edgebase + edges * 8
    if word(s, 40) != length(s) - database or word(r, 32) == 0 or word(r, 32) > nodes:
        return refused(w, 10)
    if word(r, 40) == 0 or word(r, 40) > 12 or word(r, 48) == 0 or word(r, 48) > 8:
        return refused(w, 11)
    expected_core = word(r, 40)
    if expected_core == 9:
        expected_core = 6
    elif expected_core == 10 or expected_core == 11:
        expected_core = 7
    elif expected_core == 12:
        expected_core = 8
    if word(r, 48) != expected_core or word(r, 56) != choose(word(r, 40) >= 9, 1, 0):
        return refused(w, 12)
    if word(r, 40) <= 8:
        i = 64
        while i < 96:
            if byte(r, i) != byte(r, i + 32):
                return refused(w, 52)
            i = i + 1
    if get(w, S_STATUS) == 0:
        put(w, S_LEASE, word(r, 8))
        put(w, S_SEQ, word(r, 16))
        put(w, S_NN, nodes)
        put(w, S_NE, edges)
        put(w, S_ND, word(s, 40))
        put(w, S_DB, database)
        put(w, S_ROOT, word(r, 32))
        put(w, S_COREVER, word(r, 48))
        put(w, S_INSCHEMA, word(r, 40))
        put(w, S_COMMAND_MODE, word(r, 24))
        copy_bytes(w, r, SAVED_COMMAND, 0, 160)
        initialize_literals(w)
        put(w, S_STATUS, 1)
    else:
        i = 0
        while i < 160:
            if byte(r, i) != byte(w, SAVED_COMMAND + i):
                return refused(w, 13)
            i = i + 1
        if get(w, S_NN) != nodes or get(w, S_NE) != edges or get(w, S_ND) != word(s, 40) or get(w, S_DB) != database:
            return refused(w, 14)
    if validate_nodes(s, w) == 0 or inspect_shape(s, w) == 0:
        return refused(w, get(w, S_ERROR))
    put(w, S_PASS, 0)
    reset_counts(w)
    root = projection(s, r, w)
    if get(w, S_ERROR) != 0:
        return refused(w, get(w, S_ERROR))
    nn = nodes + get(w, S_NEW_N)
    ne = edges + get(w, S_NEW_E)
    nd = get(w, S_ND) + get(w, S_NEW_D)
    if nn < nodes or ne < edges or nd < get(w, S_ND) or nn > (MAX - 64) >> 6:
        return refused(w, 15)
    size = 64 + nn * 64
    if ne > (MAX - size) >> 3:
        return refused(w, 16)
    size = size + ne * 8
    if nd > MAX - size:
        return refused(w, 17)
    size = size + nd
    if size > MAX - OUT_BASE:
        return refused(w, 18)
    put(w, S_OUT_N, nn)
    put(w, S_OUT_E, ne)
    put(w, S_OUT_D, nd)
    put(w, S_OUT_SIZE, size)
    put(w, S_NEED, OUT_BASE + size)
    if length(w) < OUT_BASE + size:
        event(w, 1, root)
        return GROW
    copy_original(s, w)
    put(w, S_PASS, 1)
    reset_counts(w)
    actual = projection(s, r, w)
    if actual != root or get(w, S_ERROR) != 0:
        return refused(w, 19)
    if nodes + get(w, S_NEW_N) != nn or edges + get(w, S_NEW_E) != ne or get(w, S_ND) + get(w, S_NEW_D) != nd:
        return refused(w, 20)
    put(w, OUT_BASE, GRAPH_MAGIC)
    put(w, OUT_BASE + 8, get(w, S_LEASE))
    put(w, OUT_BASE + 16, nn)
    put(w, OUT_BASE + 24, root)
    put(w, OUT_BASE + 32, ne)
    put(w, OUT_BASE + 40, nd)
    put(w, OUT_BASE + 48, size)
    put(w, OUT_BASE + 56, 0)
    put(w, S_STATUS, 2)
    return event(w, 0, root)

def word(s:readbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def fail(w:mutbuf, reason:u64) -> u64:
    if get(w, S_ERROR) == 0:
        put(w, S_ERROR, reason)
    return 0

def refused(w:mutbuf, reason:u64) -> u32:
    fail(w, reason)
    put(w, S_STATUS, 3)
    event(w, 2, 0)
    return BAD

def event(w:mutbuf, action:u64, root:u64) -> u32:
    put(w, 0, EVENT_MAGIC)
    put(w, 8, action)
    put(w, 16, get(w, S_LEASE))
    put(w, 24, get(w, S_SEQ))
    put(w, 32, root)
    put(w, 40, choose(action == 0, OUT_BASE, 0))
    put(w, 48, choose(action == 0, get(w, S_OUT_SIZE), 0))
    put(w, 56, choose(action == 1, get(w, S_NEED), 0))
    put(w, 64, get(w, S_ERROR))
    i = 72
    while i < 128:
        put(w, i, 0)
        i = i + 8
    return 128

def node_at(s:readbuf, node:u64) -> u64:
    if node == 0 or node > word(s, 16):
        return 0
    return 64 + (node - 1) * 64

def kind(s:readbuf, node:u64) -> u64:
    at = node_at(s, node)
    if at == 0:
        return MAX
    return word(s, at)

def count(s:readbuf, node:u64) -> u64:
    at = node_at(s, node)
    if at == 0:
        return 0
    return word(s, at + 32)

def edge(s:readbuf, node:u64, index:u64) -> u64:
    at = node_at(s, node)
    if at == 0:
        return 0
    n = word(s, at + 32)
    if word(s, at) == 6:
        n = n * 2
    if index >= n:
        return 0
    base = 64 + word(s, 16) * 64
    return word(s, base + (word(s, at + 24) + index) * 8)

def is_text(s:readbuf, w:mutbuf, node:u64, code:u64) -> u64:
    at = node_at(s, node)
    if at == 0 or word(s, at) != 4:
        return 0
    n = get(w, LIT_INDEX + code * 16 + 8)
    if word(s, at + 16) != n:
        return 0
    a = word(s, at + 8)
    b = get(w, LIT_INDEX + code * 16)
    i = 0
    while i < n:
        if byte(s, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def field(s:readbuf, w:mutbuf, node:u64, code:u64) -> u64:
    if kind(s, node) != 6:
        return 0
    i = 0
    while i < count(s, node):
        key = edge(s, node, i * 2)
        if is_text(s, w, key, code) != 0:
            return edge(s, node, i * 2 + 1)
        i = i + 1
    return 0

def validate_nodes(s:readbuf, w:mutbuf) -> u64:
    i = 1
    while i <= get(w, S_NN):
        at = node_at(s, i)
        k = word(s, at)
        if k > 6 or k == 3 or word(s, at + 56) != 0:
            return fail(w, 30)
        if k == 5 or k == 6:
            if word(s, at + 8) != 0 or word(s, at + 16) != 0 or word(s, at + 40) == 0 or word(s, at + 48) != 0:
                return fail(w, 31)
            first = word(s, at + 24)
            n = word(s, at + 32)
            if k == 6:
                if n > MAX >> 1:
                    return fail(w, 32)
                n = n * 2
            if first > get(w, S_NE) or n > get(w, S_NE) - first:
                return fail(w, 33)
            j = 0
            while j < n:
                child = edge(s, i, j)
                if child == 0 or child > get(w, S_NN):
                    return fail(w, 34)
                if k == 6 and (j & 1) == 0 and kind(s, child) != 4:
                    return fail(w, 35)
                j = j + 1
        else:
            if word(s, at + 24) != 0 or word(s, at + 32) != 0 or word(s, at + 40) != 0:
                return fail(w, 36)
            begin = word(s, at + 8)
            n = word(s, at + 16)
            aux = word(s, at + 48)
            if k <= 1:
                if begin != 0 or n != 0 or aux > k:
                    return fail(w, 37)
            else:
                if begin < get(w, S_DB) or begin > length(s) or n > length(s) - begin:
                    return fail(w, 38)
                if k == 2:
                    if aux > 1 or (n == 0 and aux != 0):
                        return fail(w, 39)
                    if n > 0 and byte(s, begin + n - 1) == 0:
                        return fail(w, 40)
        i = i + 1
    return 1

def scalar_type(s:readbuf, w:mutbuf, node:u64) -> u64:
    return choose(is_text(s, w, node, K_i8) != 0 or is_text(s, w, node, K_i16) != 0 or is_text(s, w, node, K_i32) != 0 or is_text(s, w, node, K_i64) != 0 or is_text(s, w, node, K_isize) != 0 or is_text(s, w, node, K_u8) != 0 or is_text(s, w, node, K_u16) != 0 or is_text(s, w, node, K_u32) != 0 or is_text(s, w, node, K_u64) != 0 or is_text(s, w, node, K_usize) != 0 or is_text(s, w, node, K_bool) != 0 or is_text(s, w, node, K_unit) != 0, 1, 0)

def scalar_function(s:readbuf, w:mutbuf, fn:u64) -> u64:
    params = field(s, w, fn, K_params)
    returns = field(s, w, fn, K_returns)
    if kind(s, params) != 5 or kind(s, returns) != 5:
        return 0
    i = 0
    while i < count(s, params):
        p = edge(s, params, i)
        if scalar_type(s, w, field(s, w, p, K_type)) == 0:
            return 0
        i = i + 1
    i = 0
    while i < count(s, returns):
        if scalar_type(s, w, edge(s, returns, i)) == 0:
            return 0
        i = i + 1
    return 1

def text_less(s:readbuf, left:u64, right:u64) -> u64:
    a = node_at(s, left)
    b = node_at(s, right)
    an = word(s, a + 16)
    bn = word(s, b + 16)
    ap = word(s, a + 8)
    bp = word(s, b + 8)
    i = 0
    while i < an and i < bn:
        x = byte(s, ap + i)
        y = byte(s, bp + i)
        if x != y:
            return choose(x < y, 1, 0)
        i = i + 1
    return choose(an < bn, 1, 0)

def add_entry(s:readbuf, w:mutbuf, name:u64) -> u64:
    if kind(s, name) != 4 or get(w, S_NEXPORT) >= 1024:
        return fail(w, 41)
    i = get(w, S_NEXPORT)
    while i > 0:
        previous = get(w, SORT_BASE + (i - 1) * 8)
        if text_less(s, name, previous) == 0:
            put(w, SORT_BASE + i * 8, name)
            put(w, S_NEXPORT, get(w, S_NEXPORT) + 1)
            return 1
        put(w, SORT_BASE + i * 8, previous)
        i = i - 1
    put(w, SORT_BASE, name)
    put(w, S_NEXPORT, get(w, S_NEXPORT) + 1)
    return 1

def inspect_shape(s:readbuf, w:mutbuf) -> u64:
    root = get(w, S_ROOT)
    if kind(s, root) != 6 or is_text(s, w, field(s, w, root, K_schema), schema_code(get(w, S_COREVER))) == 0:
        return fail(w, 42)
    fns = field(s, w, root, K_functions)
    if kind(s, fns) != 5 or count(s, fns) == 0 or count(s, fns) > 1024:
        return fail(w, 43)
    if kind(s, field(s, w, root, K_module)) != 4:
        return fail(w, 44)
    put(w, S_NFN, count(s, fns))
    put(w, S_NBLOCK, 0)
    put(w, S_NEXPORT, 0)
    exports = field(s, w, root, K_exports)
    if exports != 0 and kind(s, exports) != 5:
        return fail(w, 45)
    i = 0
    while i < count(s, fns):
        fn = edge(s, fns, i)
        name = field(s, w, fn, K_name)
        blocks = field(s, w, fn, K_blocks)
        if kind(s, fn) != 6 or kind(s, name) != 4 or kind(s, blocks) != 5:
            return fail(w, 46)
        if kind(s, field(s, w, fn, K_params)) != 5 or kind(s, field(s, w, fn, K_returns)) != 5 or kind(s, field(s, w, fn, K_effects)) != 5:
            return fail(w, 47)
        nb = count(s, blocks)
        if nb == 0 or nb > 4096:
            return fail(w, 48)
        put(w, S_NBLOCK, get(w, S_NBLOCK) + nb)
        j = 0
        while j < nb:
            block = edge(s, blocks, j)
            ops = field(s, w, block, K_ops)
            if kind(s, block) != 6 or kind(s, field(s, w, block, K_id)) != 4 or kind(s, field(s, w, block, K_params)) != 5 or kind(s, ops) != 5 or kind(s, field(s, w, block, K_term)) != 6:
                return fail(w, 49)
            k = 0
            while k < count(s, ops):
                op = edge(s, ops, k)
                if kind(s, op) != 6 or count(s, op) != 4:
                    return fail(w, 50)
                if field(s, w, op, K_op) == 0 or field(s, w, op, K_args) == 0 or field(s, w, op, K_out) == 0 or field(s, w, op, K_attrs) == 0:
                    return fail(w, 51)
                k = k + 1
            j = j + 1
        if exports == 0 and scalar_function(s, w, fn) != 0:
            if add_entry(s, w, name) == 0:
                return 0
        i = i + 1
    if exports != 0:
        i = 0
        while i < count(s, exports):
            if add_entry(s, w, edge(s, exports, i)) == 0:
                return 0
            i = i + 1
    return 1

def reset_counts(w:mutbuf) -> u64:
    put(w, S_NEW_N, 0)
    put(w, S_NEW_E, 0)
    put(w, S_NEW_D, 0)
    return 0

def output_database(w:mutbuf) -> u64:
    return 64 + get(w, S_OUT_N) * 64 + get(w, S_OUT_E) * 8

def new_node(w:mutbuf, k:u64) -> u64:
    id = get(w, S_NN) + get(w, S_NEW_N) + 1
    put(w, S_NEW_N, get(w, S_NEW_N) + 1)
    if get(w, S_PASS) == 1:
        at = OUT_BASE + 64 + (id - 1) * 64
        i = 0
        while i < 64:
            put(w, at + i, 0)
            i = i + 8
        put(w, at, k)
    return id

def new_scalar(w:mutbuf, k:u64, size:u64, aux:u64) -> u64:
    id = new_node(w, k)
    data = get(w, S_NEW_D)
    put(w, S_NEW_D, data + size)
    if get(w, S_PASS) == 1:
        at = OUT_BASE + 64 + (id - 1) * 64
        put(w, at + 8, output_database(w) + get(w, S_ND) + data)
        put(w, at + 16, size)
        put(w, at + 48, aux)
    return id

def scalar_position(w:mutbuf, id:u64) -> u64:
    return OUT_BASE + get(w, OUT_BASE + 64 + (id - 1) * 64 + 8)

def literal(w:mutbuf, code:u64) -> u64:
    at = get(w, LIT_INDEX + code * 16)
    size = get(w, LIT_INDEX + code * 16 + 8)
    id = new_scalar(w, 4, size, size)
    if get(w, S_PASS) == 1:
        target = scalar_position(w, id)
        i = 0
        while i < size:
            store(w, target + i, byte(w, at + i))
            i = i + 1
    return id

def unsigned(w:mutbuf, value:u64) -> u64:
    size = 0
    rest = value
    while rest != 0:
        size = size + 1
        rest = rest >> 8
    id = new_scalar(w, 2, size, 0)
    if get(w, S_PASS) == 1:
        at = scalar_position(w, id)
        i = 0
        while i < size:
            store(w, at + i, (value >> (i * 8)) & 255)
            i = i + 1
    return id

def boolean(w:mutbuf, value:u64) -> u64:
    id = new_node(w, 1)
    if get(w, S_PASS) == 1:
        put(w, OUT_BASE + 64 + (id - 1) * 64 + 48, value)
    return id

def container(w:mutbuf, k:u64, count:u64) -> u64:
    id = new_node(w, k)
    first = get(w, S_NE) + get(w, S_NEW_E)
    n = count
    if k == 6:
        n = n * 2
    put(w, S_NEW_E, get(w, S_NEW_E) + n)
    if get(w, S_PASS) == 1:
        at = OUT_BASE + 64 + (id - 1) * 64
        put(w, at + 24, first)
        put(w, at + 32, count)
        put(w, at + 40, id)
    return id

def set_edge(w:mutbuf, parent:u64, index:u64, value:u64) -> u64:
    if get(w, S_PASS) == 1:
        at = OUT_BASE + 64 + (parent - 1) * 64
        first = get(w, at + 24)
        target = OUT_BASE + 64 + get(w, S_OUT_N) * 64 + (first + index) * 8
        put(w, target, value)
    return 0

def pair(w:mutbuf, parent:u64, index:u64, code:u64, value:u64) -> u64:
    key = literal(w, code)
    set_edge(w, parent, index * 2, key)
    set_edge(w, parent, index * 2 + 1, value)
    return 0

def hash_text(r:readbuf, w:mutbuf, at:u64) -> u64:
    id = new_scalar(w, 4, 64, 64)
    if get(w, S_PASS) == 1:
        target = scalar_position(w, id)
        i = 0
        while i < 32:
            b = byte(r, at + i)
            hi = b >> 4
            lo = b & 15
            store(w, target + i * 2, choose(hi < 10, hi + 48, hi + 87))
            store(w, target + i * 2 + 1, choose(lo < 10, lo + 48, lo + 87))
            i = i + 1
    return id

def truth(w:mutbuf, condition:bool) -> u64:
    return choose(condition, get(w, S_TRUE), get(w, S_FALSE))

def normalization(s:readbuf, r:readbuf, w:mutbuf, input_hash:u64, core_hash:u64) -> u64:
    result = container(w, 6, 10)
    pair(w, result, 0, K_input_sha256, input_hash)
    pair(w, result, 1, K_core_sha256, core_hash)
    pair(w, result, 2, K_input_schema, literal(w, schema_code(get(w, S_INSCHEMA))))
    pair(w, result, 3, K_input_profile, literal(w, profile_code(get(w, S_INSCHEMA))))
    pair(w, result, 4, K_core_schema, literal(w, schema_code(get(w, S_COREVER))))
    pair(w, result, 5, K_core_profile, literal(w, profile_code(get(w, S_COREVER))))
    pair(w, result, 6, K_structured_elaboration_rechecked, truth(w, get(w, S_INSCHEMA) >= 9))
    pair(w, result, 7, K_primitive_core_rechecked, get(w, S_TRUE))
    pair(w, result, 8, K_source_ast_required, get(w, S_FALSE))
    entries = container(w, 5, get(w, S_NEXPORT))
    i = 0
    while i < get(w, S_NEXPORT):
        set_edge(w, entries, i, get(w, SORT_BASE + i * 8))
        i = i + 1
    pair(w, result, 9, K_public_scalar_entrypoints, entries)
    return result

def verification_claims(w:mutbuf) -> u64:
    result = container(w, 6, 16)
    pair(w, result, 0, K_typed_closed_ssa_checked, get(w, S_TRUE))
    pair(w, result, 1, K_linear_resources_and_loan_provenance_checked, get(w, S_TRUE))
    pair(w, result, 2, K_whole_language_soundness_proved, get(w, S_FALSE))
    pair(w, result, 3, K_backend_refinement_proved, get(w, S_FALSE))
    pair(w, result, 4, K_foreign_code_supported, get(w, S_FALSE))
    pair(w, result, 5, K_escaping_loans_supported, get(w, S_FALSE))
    pair(w, result, 6, K_parameter_bound_loan_returns_supported, truth(w, get(w, S_COREVER) == 8))
    pair(w, result, 7, K_concurrency_supported, get(w, S_FALSE))
    pair(w, result, 8, K_nominal_products_and_enums_checked, truth(w, get(w, S_INSCHEMA) >= 9))
    pair(w, result, 9, K_local_stored_loan_identity_checked, truth(w, get(w, S_INSCHEMA) >= 9))
    pair(w, result, 10, K_record_field_borrow_provenance_checked, truth(w, get(w, S_INSCHEMA) >= 9))
    pair(w, result, 11, K_cooperative_task_protocol_checked, truth(w, get(w, S_INSCHEMA) >= 9))
    pair(w, result, 12, K_background_tasks_supported, get(w, S_FALSE))
    pair(w, result, 13, K_recursive_heap_adts_supported, get(w, S_FALSE))
    pair(w, result, 14, K_recursive_buffer_chains_supported, truth(w, get(w, S_COREVER) >= 7))
    pair(w, result, 15, K_preemptive_or_async_cancellation_supported, get(w, S_FALSE))
    return result

def operation(s:readbuf, w:mutbuf, op:u64, index:u64) -> u64:
    result = container(w, 6, 5)
    pair(w, result, 0, K_index, unsigned(w, index))
    pair(w, result, 1, K_op, field(s, w, op, K_op))
    pair(w, result, 2, K_args, field(s, w, op, K_args))
    pair(w, result, 3, K_out, field(s, w, op, K_out))
    pair(w, result, 4, K_attrs, field(s, w, op, K_attrs))
    return result

def block_view(s:readbuf, w:mutbuf, block:u64) -> u64:
    result = container(w, 6, 4)
    pair(w, result, 0, K_id, field(s, w, block, K_id))
    pair(w, result, 1, K_params, field(s, w, block, K_params))
    ops = field(s, w, block, K_ops)
    out = container(w, 5, count(s, ops))
    i = 0
    while i < count(s, ops):
        set_edge(w, out, i, operation(s, w, edge(s, ops, i), i))
        i = i + 1
    pair(w, result, 2, K_operations, out)
    pair(w, result, 3, K_term, field(s, w, block, K_term))
    return result

def function_view(s:readbuf, w:mutbuf, fn:u64) -> u64:
    v8 = get(w, S_COREVER) == 8
    result = container(w, 6, choose(v8, 6, 5))
    pair(w, result, 0, K_name, field(s, w, fn, K_name))
    pair(w, result, 1, K_params, field(s, w, fn, K_params))
    returns = field(s, w, fn, K_returns)
    pair(w, result, 2, K_returns, returns)
    pair(w, result, 3, K_effects, field(s, w, fn, K_effects))
    blocks = field(s, w, fn, K_blocks)
    out = container(w, 5, count(s, blocks))
    i = 0
    while i < count(s, blocks):
        set_edge(w, out, i, block_view(s, w, edge(s, blocks, i)))
        i = i + 1
    pair(w, result, 4, K_blocks, out)
    if v8:
        loans = field(s, w, fn, K_return_loans)
        if loans == 0:
            loans = container(w, 5, count(s, returns))
            i = 0
            while i < count(s, returns):
                set_edge(w, loans, i, get(w, S_NULL))
                i = i + 1
        pair(w, result, 5, K_return_loans, loans)
    return result

def inspection(s:readbuf, w:mutbuf, input_hash:u64, core_hash:u64, norm:u64) -> u64:
    result = container(w, 6, 8)
    schema = INSPECT_V1
    if get(w, S_COREVER) == 8:
        schema = INSPECT_V2
    pair(w, result, 0, K_schema, literal(w, schema))
    pair(w, result, 1, K_ok, get(w, S_TRUE))
    pair(w, result, 2, K_program_sha256, core_hash)
    pair(w, result, 3, K_module, field(s, w, get(w, S_ROOT), K_module))
    pair(w, result, 4, K_input_sha256, input_hash)
    pair(w, result, 5, K_normalization, norm)
    fns = field(s, w, get(w, S_ROOT), K_functions)
    out = container(w, 5, count(s, fns))
    i = 0
    while i < count(s, fns):
        set_edge(w, out, i, function_view(s, w, edge(s, fns, i)))
        i = i + 1
    pair(w, result, 6, K_functions, out)
    claims = container(w, 6, 2)
    pair(w, claims, 0, K_native_executed, get(w, S_FALSE))
    pair(w, claims, 1, K_whole_language_soundness_proved, get(w, S_FALSE))
    pair(w, result, 7, K_claims, claims)
    return result

def verification(w:mutbuf, input_hash:u64, core_hash:u64, norm:u64) -> u64:
    cli = get(w, S_COMMAND_MODE) == 4
    result = container(w, 6, choose(cli, 13, 11))
    pair(w, result, 0, K_schema, literal(w, VERIFICATION_SCHEMA))
    pair(w, result, 1, K_ok, get(w, S_TRUE))
    pair(w, result, 2, K_profile, literal(w, profile_code(get(w, S_COREVER))))
    pair(w, result, 3, K_program_sha256, core_hash)
    pair(w, result, 4, K_input_sha256, input_hash)
    pair(w, result, 5, K_normalization, norm)
    pair(w, result, 6, K_word_bits, unsigned(w, 64))
    pair(w, result, 7, K_functions_checked, unsigned(w, get(w, S_NFN)))
    pair(w, result, 8, K_blocks_checked, unsigned(w, get(w, S_NBLOCK)))
    pair(w, result, 9, K_source_required, get(w, S_FALSE))
    pair(w, result, 10, K_claims, verification_claims(w))
    if cli:
        pair(w, result, 11, K_status, literal(w, K_standalone_core_checked))
        pair(w, result, 12, K_native_executed, get(w, S_FALSE))
    return result

def projection(s:readbuf, r:readbuf, w:mutbuf) -> u64:
    if get(w, S_COMMAND_MODE) == 3:
        return get(w, S_ROOT)
    put(w, S_TRUE, boolean(w, 1))
    put(w, S_FALSE, boolean(w, 0))
    put(w, S_NULL, new_node(w, 0))
    input_hash = hash_text(r, w, 64)
    core_hash = hash_text(r, w, 96)
    norm = normalization(s, r, w, input_hash, core_hash)
    if get(w, S_COMMAND_MODE) == 2:
        return inspection(s, w, input_hash, core_hash, norm)
    return verification(w, input_hash, core_hash, norm)

def copy_original(s:readbuf, w:mutbuf) -> u64:
    nodes = get(w, S_NN)
    edges = get(w, S_NE)
    copy_bytes(w, s, OUT_BASE + 64, 64, nodes * 64)
    source_edges = 64 + nodes * 64
    target_edges = OUT_BASE + 64 + get(w, S_OUT_N) * 64
    copy_bytes(w, s, target_edges, source_edges, edges * 8)
    source_data = get(w, S_DB)
    target_data = output_database(w)
    copy_bytes(w, s, OUT_BASE + target_data, source_data, get(w, S_ND))
    delta = target_data - source_data
    i = 1
    while i <= nodes:
        at = OUT_BASE + 64 + (i - 1) * 64
        k = get(w, at)
        if k == 2 or k == 4:
            put(w, at + 8, get(w, at + 8) + delta)
        i = i + 1
    return 0
'''

def expanded_source():
    table=[]
    data=bytearray()
    for code,text in enumerate(LITERALS,1):
        raw=text.encode("ascii")
        table.append((code,CONSTANTS["LIT_DATA"]+len(data),len(raw)))
        data.extend(raw)
    assert CONSTANTS["LIT_INDEX"]+(len(LITERALS)+1)*16<=CONSTANTS["LIT_DATA"]
    assert CONSTANTS["LIT_DATA"]+len(data)<CONSTANTS["SORT_BASE"]
    initialize=["def initialize_literals(w:mutbuf) -> u64:"]
    for code,at,size in table:
        initialize += [
            f'    put(w, {CONSTANTS["LIT_INDEX"]+code*16}, {at})',
            f'    put(w, {CONSTANTS["LIT_INDEX"]+code*16+8}, {size})']
    for at in range(0,len(data),8):
        raw=data[at:at+8]
        if len(raw)==8:
            initialize.append(f'    put(w, {CONSTANTS["LIT_DATA"]+at}, {int.from_bytes(raw,"little")})')
        else:
            for i,value in enumerate(raw):
                initialize.append(f'    store(w, {CONSTANTS["LIT_DATA"]+at+i}, {value})')
    initialize.append("    return 0")
    mappings=[]
    for name,values in (("schema_code",SCHEMAS),("profile_code",PROFILES)):
        mappings.append(f"def {name}(value:u64) -> u64:")
        for i,value in enumerate(values,1):
            mappings += [f"    if value == {i}:",f"        return {CODES[value]}"]
        mappings += ["    return 0"]
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]),node)
            return node
    parsed=ast.parse(SOURCE+"\n"+"\n".join(initialize)+"\n"+"\n".join(mappings))
    return ast.unparse(ast.fix_missing_locations(Expand().visit(parsed)))+"\n"

def document():
    nodes=ast.parse(expanded_source()).body
    names={n.name:"f"+str(i+1) for i,n in enumerate(nodes)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[{"name":"v0","type":"readbuf"},{"name":"v1","type":"mutbuf"},{"name":"v2","type":"mutbuf"}]
    functions=[{"name":"f0","params":params,"returns":["u32"],"effects":["read","write","trap"],"entry":"b0",
      "blocks":[{"id":"b0","params":params,"ops":[
        {"op":"borrow.read","args":["v1"],"out":[{"name":"v3","type":"readbuf"}],"attrs":{}},
        {"op":"call","args":["v0","v3","v2"],"out":[{"name":"v4","type":"u32"}],"attrs":{"function":names["project_report"]}},
        {"op":"loan.end","args":["v3"],"out":[],"attrs":{}}],
        "term":{"op":"ret","values":["v4"]}}]}]
    for n in nodes:
        b=CopyBuilder(n,names,sigs,total);b.statements(n.body)
        functions.append({"name":names[n.name],"params":[b.param(p) for p in b.params],
         "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"program_inspection_reconstructed_r1","functions":functions})

def main():
    assert sha256(HELPER.read_bytes()).hexdigest()=="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
    assert not ROOT.exists(),"Preserve previous reconstruction attempts"
    (ROOT/"tools").mkdir(parents=True)
    (ROOT/"examples/hia_bootstrap").mkdir(parents=True)
    (ROOT/"development").mkdir()
    raw=Path(__file__).read_bytes()
    (ROOT/"tools"/Path(__file__).name).write_bytes(raw)
    text=expanded_source()
    (ROOT/"development/program_inspection.authoring.py").write_text(text)
    doc=document()
    assembly=render_assembly(doc).encode()
    target=ROOT/"examples/hia_bootstrap/program_inspection.hiaasm"
    target.write_bytes(assembly)
    assemble_program(assembly)
    profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
      max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
      ops=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
      max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]),
      source_bytes=len(assembly),source_sha256=sha256(assembly).hexdigest())
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
    assert profile["ops"]<=8192 and profile["max_block_params"]<=16 and len(assembly)<=1<<20
    report=dict(status="GENERATED_ONLY",profile=profile,source_path=str(target),
      generator_sha256=sha256(raw).hexdigest(),whole_stack_closed=False,
      actual_program_admission_is_required_before_projection=True,
      no_compilation_or_native_semantics_claim=True)
    (ROOT/"development/source-r1.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True),flush=True)

if __name__=="__main__":main()
