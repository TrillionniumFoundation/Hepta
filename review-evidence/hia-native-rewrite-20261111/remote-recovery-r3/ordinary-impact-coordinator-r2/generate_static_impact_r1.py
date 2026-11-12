"""HIA static impact analysis for actual admitted old/new Core and an issued patch receipt.

This pure component is development authoring. It performs complete native
receipt validation, whole-function/interface comparison, both call graph scans,
reverse reachability, canonical report construction and native SHA-256. The
ordinary coordinator must still execute original admission, the full patch,
fresh candidate admission/equality, and retain the actual input identity.
No caller-provided digest or this component's success grants Core authority.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import source_program as frontend_source
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

BAD=0xfffffffd
NEED=0xfffffffe
NIL=0xffffffffffffffff
MAGIC=int.from_bytes(b"HIAIMP01","little")
SCRATCH_BYTES=331776
KEYS=("schema","ok","status","before_sha256","after_sha256","edits",
    "interface_changes","interface_policy","edit_domain","original_input_sha256",
    "claims","whole_module_rechecked","behavior_equivalence_proved","native_executed",
    "interface_preserved","external_callers_revalidated","functions","name",
    "params","returns","effects","return_loans","blocks","ops","op","attrs","function")
LITERALS={"result_v1":"hepta.hia.patch-result.v1","result_v2":"hepta.hia.patch-result.v2",
    "status":"verified_unpublished","domain":"independently_verified_normalized_core",
    "preserve":"preserve","migrate":"migrate","call":"call"}
MESSAGES={
 1:"E_HIA_IMPACT: unqualified or fabricated Agent patch receipt",
 2:"E_HIA_IMPACT: invalid function inventory",
 3:"E_HIA_IMPACT: unreviewed function identity",
 4:"E_HIA_IMPACT: patch unexpectedly removed a function",
 5:"E_HIA_IMPACT: Agent interface change receipt contradicts actual programs",
 6:"E_HIA_IMPACT: Agent migration-policy receipt contradicts verified program",
 7:"E_HIA_IMPACT: legacy patch may not claim changed interface",
 8:"E_HIA_IMPACT: verified program has unlisted callee",
}
BODY = r'''

def impact(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128 or length(w) < 128:
        return BAD
    if length(s) == 0 or length(s) > 25167872:
        return impact_event(o, 3, 1, 0, 0, 0)
    if measure_transport(s, w) == 0:
        return impact_event(o, 3, 2, 0, 0, 0)
    nodes = get(w, 64)
    depth = get(w, 72)
    need_w = 64 + nodes * 56 + length(s) + SCRATCH_BYTES + 8
    need_o = length(s) + 128
    if need_o < 128 + (depth + 1) * 48:
        need_o = 128 + (depth + 1) * 48
    bound = nodes
    if bound > (length(s) >> 2) + 1:
        bound = (length(s) >> 2) + 1
    slots = 2
    while slots < bound * 2:
        slots = slots * 2
    if need_o < slots * 8:
        need_o = slots * 8
    if length(w) < need_w or length(o) < need_o:
        return impact_event(o, 1, 0, need_o, need_w, 0)
    put(o, 48, nodes)
    put(o, 56, depth)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return impact_event(o, 3, 3, need_o, need_w, 0)
    if kind(w, 0) != 5 or count(w, 0) != 4:
        return impact_event(o, 3, 4, need_o, need_w, 0)
    old = child(w, 0)
    new = next_node(w, old)
    receipt = next_node(w, new)
    identity = next_node(w, receipt)
    if kind(w, old) != 6 or kind(w, new) != 6 or kind(w, identity) != 4:
        return impact_event(o, 3, 5, need_o, need_w, 0)
    scratch = (get(w, 32) + 7) & 18446744073709551608
    if scratch > length(w) or length(w) - scratch < SCRATCH_BYTES:
        return impact_event(o, 3, 6, need_o, need_w, 0)
    put(w, 40, scratch)
    put(w, scratch + 2048, old)
    put(w, scratch + 2056, new)
    put(w, scratch + 2064, receipt)
    put(w, scratch + 2072, identity)
    put(w, scratch + 2080, 0)
    put(w, scratch + 2088, 0)
    put(w, scratch + 2096, 0)
    put(w, scratch + 2104, 0)
    put(w, scratch + 2112, 0)
    put(w, scratch + 2120, 0)
    put(w, scratch + 2128, 0)
    if digest_node(s, o, w, old, scratch + 1200) == 0:
        return impact_event(o, 3, 7, need_o, need_w, 0)
    if digest_node(s, o, w, new, scratch + 1232) == 0:
        return impact_event(o, 3, 7, need_o, need_w, 0)
    reason = receipt_prefix(s, w, receipt, identity)
    if reason != 0:
        return impact_event(o, 2, reason, need_o, need_w, 0)
    reason = inventory(w, old, scratch + 4096, 2080)
    if reason != 0:
        return impact_event(o, 2, reason, need_o, need_w, 0)
    reason = inventory(w, new, scratch + 12288, 2088)
    if reason != 0:
        return impact_event(o, 2, reason, need_o, need_w, 0)
    reason = compare_inventory(s, o, w)
    if get(w, 48) != 0:
        return impact_event(o, 3, 8, need_o, need_w, 0)
    if reason != 0:
        return impact_event(o, 2, reason, need_o, need_w, 0)
    reason = receipt_interfaces(w, receipt)
    if reason != 0:
        return impact_event(o, 2, reason, need_o, need_w, 0)
    clear_graphs(w)
    reason = scan_graph(w, 0)
    if reason == 0:
        reason = scan_graph(w, 1)
    if reason != 0:
        return impact_event(o, 2, reason, need_o, need_w, 0)
    propagate(w)
    put(w, 48, 0)
    put(w, 56, 128)
    report(o, w, 0)
    size = get(w, 56)
    if size > 4294967295 - 76:
        return impact_event(o, 3, 9, need_o, need_w, 0)
    if size + 76 > length(o):
        return impact_event(o, 1, 0, size + 76, need_w, 0)
    if get(w, 48) != 0:
        return impact_event(o, 3, 10, need_o, need_w, 0)
    if digest_bytes(o, w, 128, size - 128) != 32:
        return impact_event(o, 3, 11, need_o, need_w, 0)
    copy_digest(w, scratch + 1264)
    put(w, 48, 0)
    put(w, 56, 128)
    report(o, w, 1)
    if get(w, 48) != 0 or get(w, 56) != size + 76:
        return impact_event(o, 3, 12, need_o, need_w, 0)
    impact_event(o, 0, 0, need_o, need_w, size + 76 - 128)
    put(o, 64, get(w, scratch + 2088))
    put(o, 72, get(w, scratch + 2112))
    put(o, 80, get(w, scratch + 2120))
    put(o, 88, get(w, scratch + 2096))
    put(o, 96, get(w, scratch + 2104))
    put(o, 104, get(w, scratch + 2128))
    return 128

def impact_event(o:mutbuf, action:u64, reason:u64, need_o:u64, need_w:u64, size:u64) -> u32:
    put(o, 0, MAGIC)
    put(o, 8, 1)
    put(o, 16, action)
    put(o, 24, reason)
    put(o, 32, need_o)
    put(o, 40, need_w)
    put(o, 48, 128)
    put(o, 56, size)
    put(o, 64, 0)
    put(o, 72, 0)
    put(o, 80, 0)
    put(o, 88, 0)
    put(o, 96, 0)
    put(o, 104, 0)
    put(o, 112, 0)
    put(o, 120, 0)
    if action == 1:
        return NEED
    if action == 3:
        return BAD
    return 128

def digest_node(s:readbuf, o:mutbuf, w:mutbuf, node:u64, target:u64) -> u64:
    put(w, 48, 0)
    put(w, 56, 32)
    render_fragment(s, o, w, node)
    if get(w, 48) != 0:
        return 0
    if digest_bytes(o, w, 32, get(w, 56) - 32) != 32:
        return 0
    copy_digest(w, target)
    return 1

def copy_digest(w:mutbuf, target:u64) -> u64:
    source = get(w, 40) + 1088
    i = 0
    while i < 32:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def hex_equals(w:mutbuf, node:u64, expected:u64) -> u64:
    if kind(w, node) != 4 or count(w, node) != 64:
        return 0
    start = get(w, 64 + node * 56 + 24)
    i = 0
    while i < 32:
        value = byte(w, expected + i)
        if byte(w, start + 2 * i) != hex_digit(value >> 4):
            return 0
        if byte(w, start + 2 * i + 1) != hex_digit(value & 15):
            return 0
        i = i + 1
    return 1

def receipt_prefix(s:readbuf, w:mutbuf, receipt:u64, identity:u64) -> u64:
    schema = field(w, receipt, K_schema)
    version = 0
    if text_is(w, schema, L_result_v1) != 0:
        version = 1
    if text_is(w, schema, L_result_v2) != 0:
        version = 2
    if version == 0:
        return 1
    fields = K_schema | K_ok | K_status | K_before_sha256 | K_after_sha256 | K_edits | K_interface_changes | K_edit_domain | K_original_input_sha256 | K_claims
    expected_claims = K_whole_module_rechecked | K_behavior_equivalence_proved | K_native_executed
    if version == 2:
        fields = fields | K_interface_policy
        expected_claims = expected_claims | K_interface_preserved | K_external_callers_revalidated
    claims = field(w, receipt, K_claims)
    if shape(w, receipt, fields) == 0 or shape(w, claims, expected_claims) == 0:
        return 1
    if kind(w, field(w, claims, K_whole_module_rechecked)) != 2:
        return 1
    if kind(w, field(w, claims, K_behavior_equivalence_proved)) != 1:
        return 1
    if kind(w, field(w, claims, K_native_executed)) != 1:
        return 1
    if version == 2 and kind(w, field(w, claims, K_external_callers_revalidated)) != 1:
        return 1
    if kind(w, field(w, receipt, K_ok)) != 2:
        return 1
    if text_is(w, field(w, receipt, K_status), L_status) == 0:
        return 1
    if text_is(w, field(w, receipt, K_edit_domain), L_domain) == 0:
        return 1
    scratch = get(w, 40)
    if hex_equals(w, field(w, receipt, K_before_sha256), scratch + 1200) == 0:
        return 1
    if hex_equals(w, field(w, receipt, K_after_sha256), scratch + 1232) == 0:
        return 1
    if same_text(w, field(w, receipt, K_original_input_sha256), identity) == 0:
        return 1
    if positive_integer(s, w, field(w, receipt, K_edits)) == 0:
        return 1
    put(w, scratch + 2136, version)
    return 0

def positive_integer(s:readbuf, w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 3:
        return 0
    size = count(w, node)
    start = get(w, 64 + node * 56 + 24)
    if size == 0 or byte(s, start) == 45:
        return 0
    i = 0
    while i < size:
        if byte(s, start + i) != 48:
            return 1
        i = i + 1
    return 0

def inventory(w:mutbuf, root:u64, array:u64, count_offset:u64) -> u64:
    functions = field(w, root, K_functions)
    if kind(w, functions) != 5 or count(w, functions) == 0 or count(w, functions) > 1024:
        return 2
    size = 0
    fn = child(w, functions)
    while fn != NIL:
        name = field(w, fn, K_name)
        if kind(w, fn) != 6 or kind(w, name) != 4:
            return 3
        low = 0
        high = size
        while low < high:
            middle = (low + high) >> 1
            other = field(w, get(w, array + middle * 8), K_name)
            if same_text(w, name, other) != 0:
                return 3
            if text_less(w, name, other) != 0:
                high = middle
            else:
                low = middle + 1
        index = size
        while index > low:
            put(w, array + index * 8, get(w, array + (index - 1) * 8))
            index = index - 1
        put(w, array + low * 8, fn)
        size = size + 1
        fn = next_node(w, fn)
    put(w, get(w, 40) + count_offset, size)
    return 0

def find_function(w:mutbuf, name:u64) -> u64:
    if kind(w, name) != 4:
        return NIL
    scratch = get(w, 40)
    low = 0
    high = get(w, scratch + 2088)
    while low < high:
        middle = (low + high) >> 1
        other = get(w, scratch + 20480 + middle * 32)
        if same_text(w, name, other) != 0:
            return middle
        if text_less(w, name, other) != 0:
            high = middle
        else:
            low = middle + 1
    return NIL

def compare_inventory(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    scratch = get(w, 40)
    size = get(w, scratch + 2088)
    i = 0
    while i < size:
        fn = get(w, scratch + 12288 + i * 8)
        entry = scratch + 20480 + i * 32
        put(w, entry, field(w, fn, K_name))
        put(w, entry + 8, NIL)
        put(w, entry + 16, fn)
        put(w, entry + 24, 0)
        i = i + 1
    i = 0
    while i < get(w, scratch + 2080):
        old = get(w, scratch + 4096 + i * 8)
        found = find_function(w, field(w, old, K_name))
        if found == NIL:
            return 4
        put(w, scratch + 20480 + found * 32 + 8, old)
        i = i + 1
    i = 0
    while i < size:
        entry = scratch + 20480 + i * 32
        old = get(w, entry + 8)
        new = get(w, entry + 16)
        flags = 0
        if old == NIL:
            flags = 3
        else:
            if equal_json(s, o, w, old, new) == 0:
                flags = flags | 1
            if same_interface(s, o, w, old, new) == 0:
                flags = flags | 2
        put(w, entry + 24, flags)
        if (flags & 1) != 0:
            put(w, scratch + 2096, get(w, scratch + 2096) + 1)
        if (flags & 2) != 0:
            put(w, scratch + 2104, get(w, scratch + 2104) + 1)
        i = i + 1
    return 0

def receipt_interfaces(w:mutbuf, receipt:u64) -> u64:
    scratch = get(w, 40)
    expected = field(w, receipt, K_interface_changes)
    if kind(w, expected) != 5 or count(w, expected) != get(w, scratch + 2104):
        return 5
    node = child(w, expected)
    i = 0
    while i < get(w, scratch + 2088):
        entry = scratch + 20480 + i * 32
        if (get(w, entry + 24) & 2) != 0:
            if same_text(w, node, get(w, entry)) == 0:
                return 5
            node = next_node(w, node)
        i = i + 1
    if get(w, scratch + 2136) == 2:
        policy = field(w, receipt, K_interface_policy)
        if text_is(w, policy, L_preserve) == 0 and text_is(w, policy, L_migrate) == 0:
            return 6
        claims = field(w, receipt, K_claims)
        required = choose(get(w, scratch + 2104) == 0, 2, 1)
        if kind(w, field(w, claims, K_interface_preserved)) != required:
            return 6
        if kind(w, field(w, claims, K_external_callers_revalidated)) != 1:
            return 6
    elif get(w, scratch + 2104) != 0:
        return 7
    return 0

def clear_graphs(w:mutbuf) -> u64:
    scratch = get(w, 40)
    extent = get(w, scratch + 2088) * 128
    i = 0
    while i < extent:
        put(w, scratch + 61440 + i, 0)
        put(w, scratch + 192512 + i, 0)
        i = i + 8
    return 0

def scan_graph(w:mutbuf, which:u64) -> u64:
    scratch = get(w, 40)
    base = scratch + 61440 + which * 131072
    caller = 0
    while caller < get(w, scratch + 2088):
        fn = get(w, scratch + 20480 + caller * 32 + 8 + which * 8)
        if fn != NIL:
            block = child(w, field(w, fn, K_blocks))
            while block != NIL:
                operation = child(w, field(w, block, K_ops))
                while operation != NIL:
                    if text_is(w, field(w, operation, K_op), L_call) != 0:
                        name = field(w, field(w, operation, K_attrs), K_function)
                        callee = find_function(w, name)
                        if callee == NIL:
                            return 8
                        if which == 0 and get(w, scratch + 20480 + callee * 32 + 8) == NIL:
                            return 8
                        at = base + caller * 128 + (callee >> 3)
                        mask = 1 << (callee & 7)
                        previous = byte(w, at)
                        if (previous & mask) == 0:
                            store(w, at, previous | mask)
                            counter = scratch + 2112 + which * 8
                            put(w, counter, get(w, counter) + 1)
                    operation = next_node(w, operation)
                block = next_node(w, block)
        caller = caller + 1
    return 0

def propagate(w:mutbuf) -> u64:
    scratch = get(w, 40)
    size = get(w, scratch + 2088)
    tail = 0
    i = 0
    while i < size:
        entry = scratch + 20480 + i * 32
        flags = get(w, entry + 24)
        if (flags & 1) != 0:
            put(w, entry + 24, flags | 4)
            put(w, scratch + 323584 + tail * 8, i)
            tail = tail + 1
        i = i + 1
    head = 0
    while head < tail:
        current = get(w, scratch + 323584 + head * 8)
        head = head + 1
        caller = 0
        while caller < size:
            entry = scratch + 20480 + caller * 32
            flags = get(w, entry + 24)
            if (flags & 4) == 0:
                at = caller * 128 + (current >> 3)
                edges = byte(w, scratch + 61440 + at) | byte(w, scratch + 192512 + at)
                if (edges & (1 << (current & 7))) != 0:
                    put(w, entry + 24, flags | 4)
                    put(w, scratch + 323584 + tail * 8, caller)
                    tail = tail + 1
            caller = caller + 1
    put(w, scratch + 2128, tail)
    return 0

def report(o:mutbuf, w:mutbuf, include_digest:u64) -> u64:
    scratch = get(w, 40)
    emit_text(o, w, '{"after_sha256":"')
    emit_digest(o, w, scratch + 1232)
    emit_text(o, w, '","before_sha256":"')
    emit_digest(o, w, scratch + 1200)
    emit_text(o, w, '","claims":{"both_verified_call_graphs_scanned":true,"direct_and_transitive_callers_included":true,"dynamic_reachability_proved":false,"external_callers_revalidated":false,"functional_equivalence_proved":false,"native_execution_qualified":false,"physical_device_qualified":false,"source_and_candidate_reverified":true},"direct_changed_functions":')
    emit_names(o, w, 1, 1)
    emit_text(o, w, ',"interface_changed_functions":')
    emit_names(o, w, 2, 2)
    emit_text(o, w, ',"new_call_edges":')
    emit_edges(o, w, 1)
    emit_text(o, w, ',"old_call_edges":')
    emit_edges(o, w, 0)
    emit_text(o, w, ',"patch_result_schema":"hepta.hia.patch-result.v')
    append_byte(o, w, get(w, scratch + 2136) + 48)
    emit_text(o, w, '","potentially_affected_functions":')
    emit_names(o, w, 4, 4)
    emit_text(o, w, ',"schema":"hepta.hia.patch-impact.v1"')
    if include_digest != 0:
        emit_text(o, w, ',"sha256":"')
        emit_digest(o, w, scratch + 1264)
        append_byte(o, w, 34)
    emit_text(o, w, ',"status":"verified_static_callgraph_impact_not_equivalence","unaffected_by_static_callgraph":')
    emit_names(o, w, 4, 0)
    append_byte(o, w, 125)
    return 0

def emit_digest(o:mutbuf, w:mutbuf, source:u64) -> u64:
    i = 0
    while i < 32:
        value = byte(w, source + i)
        append_byte(o, w, hex_digit(value >> 4))
        append_byte(o, w, hex_digit(value & 15))
        i = i + 1
    return 0

def emit_name(o:mutbuf, w:mutbuf, node:u64) -> u64:
    append_string(o, w, get(w, 64 + node * 56 + 24), count(w, node))
    return 0

def emit_names(o:mutbuf, w:mutbuf, mask:u64, expected:u64) -> u64:
    scratch = get(w, 40)
    append_byte(o, w, 91)
    emitted = 0
    i = 0
    while i < get(w, scratch + 2088):
        entry = scratch + 20480 + i * 32
        if (get(w, entry + 24) & mask) == expected:
            if emitted != 0:
                append_byte(o, w, 44)
            emit_name(o, w, get(w, entry))
            emitted = emitted + 1
        i = i + 1
    append_byte(o, w, 93)
    return 0

def emit_edges(o:mutbuf, w:mutbuf, which:u64) -> u64:
    scratch = get(w, 40)
    size = get(w, scratch + 2088)
    append_byte(o, w, 91)
    emitted = 0
    caller = 0
    while caller < size:
        callee = 0
        while callee < size:
            at = scratch + 61440 + which * 131072 + caller * 128 + (callee >> 3)
            if (byte(w, at) & (1 << (callee & 7))) != 0:
                if emitted != 0:
                    append_byte(o, w, 44)
                emit_text(o, w, '{"callee":')
                emit_name(o, w, get(w, scratch + 20480 + callee * 32))
                emit_text(o, w, ',"caller":')
                emit_name(o, w, get(w, scratch + 20480 + caller * 32))
                append_byte(o, w, 125)
                emitted = emitted + 1
            callee = callee + 1
        caller = caller + 1
    append_byte(o, w, 93)
    return 0

def raw_same(w:mutbuf, start:u64, size:u64, n:u64, a:u64, b:u64, c:u64, d:u64, e:u64) -> u64:
    if size != n:
        return 0
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        if i >= 24:
            word = d
            shift = (i - 24) * 8
        if i >= 32:
            word = e
            shift = (i - 32) * 8
        if byte(w, start + i) != ((word >> shift) & 255):
            return 0
        i = i + 1
    return 1

def text_is(w:mutbuf, node:u64, n:u64, a:u64, b:u64, c:u64, d:u64, e:u64) -> u64:
    if kind(w, node) != 4:
        return 0
    return raw_same(w, get(w, 64 + node * 56 + 24), count(w, node), n, a, b, c, d, e)

def append_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    index = get(w, 56)
    if index < length(o):
        store(o, index, value)
    else:
        put(w, 48, NEED)
    put(w, 56, index + 1)
    return 0

def hash_get(w:mutbuf, index:u64) -> u64:
    at = get(w, 40) + index
    return byte(w, at) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24)

def hash_put(w:mutbuf, index:u64, value:u64) -> u64:
    at = get(w, 40) + index
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, 0)
    store(w, at + 5, 0)
    store(w, at + 6, 0)
    store(w, at + 7, 0)
    return 0
'''

def packed(value):
    raw=value.encode("utf-8")
    assert len(raw)<=40
    return [len(raw),*(int.from_bytes(raw[i:i+8],"little") for i in (0,8,16,24,32))]

def replace_once(source,old,new):
    assert source.count(old)==1,old
    return source.replace(old,new)

def source_program():
    constants={"K_"+key:1<<i for i,key in enumerate(KEYS)}
    constants.update(BAD=BAD,NEED=NEED,NIL=NIL,MAGIC=MAGIC,SCRATCH_BYTES=SCRATCH_BYTES)
    literals={"L_"+key:packed(value) for key,value in LITERALS.items()}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self,node):
            if isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=="emit_text":
                output,work,literal=node.value.args
                assert isinstance(literal,ast.Constant) and type(literal.value)is str
                result=[]
                for start in range(0,len(literal.value),24):
                    value=literal.value[start:start+24].encode()
                    args=[len(value),*(int.from_bytes(value[i:i+8],"little") for i in (0,8,16))]
                    result.append(ast.Expr(value=ast.Call(func=ast.Name(id="emit",ctx=ast.Load()),
                        args=[output,work,*(ast.Constant(v) for v in args)],keywords=[])))
                return result
            return self.generic_visit(node)
        def visit_Name(self,node):
            return ast.copy_location(ast.Constant(constants[node.id]),node) if node.id in constants else node
        def visit_Call(self,node):
            node=self.generic_visit(node);args=[]
            for arg in node.args:
                args.extend(ast.Constant(v) for v in literals[arg.id]) if isinstance(arg,ast.Name) and arg.id in literals else args.append(arg)
            node.args=args;return node
    own=ast.fix_missing_locations(Expand().visit(ast.parse(BODY)))
    front_keep={"kind","count","child","field","shape","render_fragment","hex_digit",
        "append_string","next_node","key_less","sort_object","emit"}
    front=[n for n in ast.parse(frontend_source()).body if n.name in front_keep]
    assert {n.name for n in front}==front_keep
    patch_keep={"same_text","equal_json","default_loans","same_interface","text_less"}
    # The original patch source expands its own key numbers. Rebuild the
    # retained comparison helpers from its unexpanded BODY under this key map.
    from tools.generate_hia_core_patch import BODY as PATCH_BODY
    patches=[n for n in ast.parse(PATCH_BODY).body if n.name in patch_keep]
    assert {n.name for n in patches}==patch_keep
    patches=Expand().visit(ast.Module(body=patches,type_ignores=[])).body
    key=["def key_id(w:mutbuf, node:u64) -> u64:",
         "    start = get(w, 64 + node * 56 + 40)",
         "    size = get(w, 64 + node * 56 + 48)"]
    for i,name in enumerate(KEYS):
        key+=["    if raw_same(w, start, size, "+", ".join(map(str,packed(name)))+") == 1:",
              "        return "+str(1<<i)]
    key+=["    return 0"]
    decoder=decoder_source()
    decoder=decoder.replace("length(s) > 8388608","length(s) > 25167872")
    decoder=decoder.replace("maximum > 1048576 or maximum_depth > 128",
        "maximum > length(s) or maximum_depth > length(s)")
    digest_nodes=[n for n in ast.parse(sha_source()).body if n.name not in {"get","put"}]
    digest=ast.unparse(ast.fix_missing_locations(ast.Module(body=digest_nodes,type_ignores=[])))
    digest=replace_once(digest,"def sha256(s: readbuf, o: mutbuf, w: mutbuf) -> u32:",
        "def digest_bytes(s: mutbuf, w: mutbuf, start: u64, size: u64) -> u64:")
    digest=replace_once(digest,"def padded_byte(s: readbuf, index: u64, total: u64) -> u64:",
        "def padded_byte(s: mutbuf, index: u64, total: u64, start: u64, size: u64) -> u64:")
    digest=digest.replace("length(s)","size")
    digest=replace_once(digest,"size > 8388608 or length(o) < 32 or length(w) < 1088",
        "start > length(s) or size > length(s) - start or size > 4294967295")
    digest=replace_once(digest,"padded_byte(s, block + i * 4 + j, padded)",
        "padded_byte(s, block + i * 4 + j, padded, start, size)")
    digest=replace_once(digest,"byte(s, index)","byte(s, start + index)")
    digest=digest.replace("get(w,","hash_get(w,").replace("put(w,","hash_put(w,")
    digest=replace_once(digest,"store(o, i * 4 + j,",
        "store(w, get(w, 40) + 1088 + i * 4 + j,")
    # Measurement only reserves transport capacity. It never admits Core.
    from importlib import util
    measure_path=Path(__file__).with_name("issued_object_prefix_reference.py")
    spec=util.spec_from_file_location("impact_issued_measure",measure_path)
    module=util.module_from_spec(spec);spec.loader.exec_module(module)
    measure=[n for n in ast.parse(module.BODY).body if n.name=="measure_transport"]
    assert len(measure)==1
    nodes=own.body+front+patches+measure+ast.parse("\n".join(key)+"\n"+decoder+"\n"+digest).body
    names=[n.name for n in nodes];assert len(names)==len(set(names)),names
    for fn in nodes:
        if fn.name=="get":
            fn.body=ast.parse("return "+" | ".join("(byte(w, index + %d) << %d)"%(i,8*i) for i in range(8))).body
        elif fn.name=="put":
            fn.body=ast.parse("\n".join("store(w, index + %d, (value >> %d) & 255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])))+"\n"

def document():
    nodes=ast.parse(source_program()).body
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({"name":names[node.name],"params":[builder.param(v) for v in builder.params],
            "returns":[builder.returns],"effects":["read","write","trap"],"entry":"b0","blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"static_patch_impact","functions":functions})

if __name__=="__main__":
    destination=Path(__file__).resolve().with_suffix(".hiaasm")
    destination.write_text(render_assembly(document()))
    print(destination)
