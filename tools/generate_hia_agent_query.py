"""Complete native HIA prepare_edit payload owner.

Generation validates the original static profile; native qualification is separate.
The runtime input is an immutable already-verified Core transport; no host
graph encoder, query construction, selector decision or query hashing runs.
The adjacent whole-Core verifier remains required and is not retired here.
"""
from __future__ import annotations
import argparse
import ast
import copy
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_agent_slice import source_program as slice_source
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_core_json_frontend import FRONTEND

CORE_LENGTH_FIELD = 16
INPUT_OFFSET = 3392
KEYS = ('schema', 'functions', 'name', 'blocks', 'id', 'ops', 'out', 'args',
        'attrs', 'term', 'op', 'params', 'returns', 'effects', 'return_loans',
        'then', 'else', 'target', 'values', 'cond', 'function')
LITERALS = {'hepta_hia_program_v8': 'hepta.hia.program.v8',
            'call': 'call', 'ret': 'ret', 'jump': 'jump',
            'branch': 'branch', 'trap': 'trap'}

ENTRY = "\n# Exact existing flat native entry ABI.  Existing verify_program remains the\n# adjacent first authority; malformed internal transport is a custody error.\n\ndef prepare_query(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(s) < 3392 or length(o) < 4194304 or length(w) < 128:\n        return 4294967268\n    if uint(s, 0) != QUERY_MAGIC or uint(s, 8) != 1:\n        return 4294967268\n    if uint(s, 16) == 0 or uint(s, 16) > 8388608 or uint(s, 24) > 8388608:\n        return 4294967268\n    if uint(s, 48) > 1 or (uint(s, 48) == 0 and uint(s, 24) != 0) or (uint(s, 48) == 1 and uint(s, 24) == 0):\n        return 4294967268\n    if length(s) != 3392 + uint(s, 16) + uint(s, 24):\n        return 4294967268\n    index = 56\n    while index < 128:\n        if uint(s, index) != 0:\n            return 4294967268\n        index = index + 8\n    # Preserve the public fields/type refusal order before lookup.\n    status = query_fields(s)\n    if status == 4294967280:\n        return status\n    if uint(s, 1760) != 1 or uint(s, 2304) != 1 or uint(s, 2848) != 1:\n        return 4294967279\n    put(o, 48, 262144)\n    put(o, 56, 64)\n    status = widen(decode_json(s, w, o))\n    if status >= 4294967292:\n        return 4294967268\n    if get(w, 8) == 0 or get(w, 8) > 262144 or get(w, 24) > length(w):\n        return 4294967268\n    state = (get(w, 24) + 7) & 18446744073709551608\n    if state > length(w) or length(w) - state < 4096:\n        return 4294967268\n    put(w, 40, state)\n    index = 0\n    while index < 4096:\n        store(w, state + index, 0)\n        index = index + 1\n    qput(w, 360, get(w, 8))\n    qput(w, 352, state + 4096)\n    initialize_query_constants(w)\n    status = query_select(s, w)\n    if status != 0:\n        return status\n    qput(w, 56, choose(text_is(w, field(w, 0, K_schema), L_hepta_hia_program_v8) == 1, 1, 0))\n    graph_counts(w)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    graph_allocate(w)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    graph_index(w)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    graph_fill(w)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    status = widen(sl_slice(w))\n    if status == 4294967292 or status == 4294967291 or status == 4294967290:\n        return status\n    if status != qget(w, 144):\n        return 4294967268\n    if get(w, qget(w, 136)) != SLICE_RESULT_MAGIC:\n        return 4294967268\n    query_collect_calls(w)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    status = query_hash(s, o, w, 0, 3392, uint(s, 16), 0)\n    if status != 0:\n        return status\n    if uint(s, 48) == 1:\n        status = query_hash(s, o, w, 0, 3392 + uint(s, 16), uint(s, 24), 1)\n    else:\n        status = query_hash(s, o, w, 0, 3392, uint(s, 16), 1)\n    if status != 0:\n        return status\n    operation = qclone(w, qget(w, 16))\n    if qw_error(w) != 0:\n        return qw_error(w)\n    status = query_wire(s, o, w, operation)\n    if status >= 4294967268:\n        return status\n    status = query_hash(s, o, w, 1, 64, status, 2)\n    if status != 0:\n        return status\n    root = build_query_tree(w, operation)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    status = query_wire(s, o, w, root)\n    if status >= 4294967268:\n        return status\n    # Output scratch is never a published query until this final header.\n    put(o, 0, QUERY_RESULT_MAGIC)\n    put(o, 8, 1)\n    put(o, 16, status)\n    put(o, 24, 0)\n    put(o, 32, 0)\n    put(o, 40, 0)\n    put(o, 48, 0)\n    put(o, 56, 0)\n    return status + 64\n\ndef query_hash(s:readbuf, o:mutbuf, w:mutbuf, mode:u64, start:u64, size:u64, slot:u64) -> u64:\n    if mode > 1 or slot > 2 or size > 8388608:\n        return 4294967268\n    if mode == 0:\n        if start > length(s) or size > length(s) - start:\n            return 4294967268\n    else:\n        if start > length(o) or size > length(o) - start:\n            return 4294967268\n    qput(w, 400, mode)\n    qput(w, 408, start)\n    qput(w, 416, size)\n    qput(w, 424, slot)\n    if widen(query_sha256(s, o, w)) != 32:\n        return 4294967268\n    return 0\n\ndef query_hash_byte(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:\n    if qget(w, 400) == 0:\n        return byte(s, qget(w, 408) + index)\n    return byte(o, qget(w, 408) + index)\n\ndef query_hash_emit(w:mutbuf, index:u64, value:u64) -> u64:\n    start = get(w, 40) + 512 + qget(w, 424) * 64 + index * 2\n    store(w, start, qw_hex(value >> 4))\n    store(w, start + 1, qw_hex(value & 15))\n    return 0\n"

SELECTION = "# Native authoring-source draft.  All policy below executes as HIA.\n# qget/qput address the private query state after the decoded Core arena.\n# Source arena functions are the existing HIA JSON decoder helpers.\n# record layout is fixed in transport.py; no Python selector decision exists.\n\ndef query_fields(s:readbuf) -> u64:\n    tag = uint(s, 32)\n    size = uint(s, 40)\n    if (tag != 1 and tag != 2) or size < 1 or size > 3:\n        return 4294967280\n    found = 0\n    i = 0\n    while i < size:\n        record = 128 + i * 544\n        value = 0\n        if request_literal(s, record, 2, 28783) == 1:\n            value = 4\n        if request_literal(s, record, 4, 1936159329) == 1:\n            value = 1\n        if request_literal(s, record, 5, 495841473633) == 1:\n            value = 2\n        if value == 0 or (found & value) != 0:\n            return 4294967280\n        found = found | value\n        i = i + 1\n    return found\n\ndef request_literal(s:readbuf, record:u64, n:u64, word:u64) -> u64:\n    if uint(s, record) != 1 or uint(s, record + 8) != n:\n        return 0\n    if uint(s, record + 16) < n:\n        return 0\n    i = 0\n    while i < n:\n        if request_codepoint(s, record + 24 + i * 4) != ((word >> (i * 8)) & 255):\n            return 0\n        i = i + 1\n    return 1\n\ndef request_codepoint(s:readbuf, at:u64) -> u64:\n    value = 0\n    i = 0\n    while i < 4:\n        value = value | (byte(s, at + i) << (i * 8))\n        i = i + 1\n    return value\n\ndef request_matches(s:readbuf, w:mutbuf, node:u64, record:u64) -> u64:\n    if kind(w, node) != 4 or uint(s, record) != 1:\n        return 0\n    size = count(w, node)\n    if size > 128 or uint(s, record + 8) != size or uint(s, record + 16) < size:\n        return 0\n    start = get(w, 64 + node * 56 + 24)\n    i = 0\n    while i < size:\n        if request_codepoint(s, record + 24 + i * 4) != byte(w, start + i):\n            return 0\n        i = i + 1\n    return 1\n\ndef query_select(s:readbuf, w:mutbuf) -> u64:\n    chosen = query_fields(s)\n    if chosen == 4294967280:\n        return chosen\n    qput(w, 48, chosen)\n    # All three original identity exact-type checks precede any lookup.\n    if uint(s, 1760) != 1 or uint(s, 2304) != 1 or uint(s, 2848) != 1:\n        return 4294967279\n    fn = query_named(s, w, field(w, 0, K_functions), K_name, 1760)\n    if fn == NONE:\n        return 4294967278\n    qput(w, 0, fn)\n    block = query_named(s, w, field(w, fn, K_blocks), K_id, 2304)\n    if block == NONE:\n        return 4294967277\n    qput(w, 8, block)\n    found = NONE\n    chosen_index = 0\n    index = 0\n    operation = child(w, field(w, block, K_ops))\n    while operation != NONE:\n        name = child(w, field(w, operation, K_out))\n        matched = 0\n        while name != NONE:\n            if request_matches(s, w, field(w, name, K_name), 2848) == 1:\n                matched = 1\n                qput(w, 232, field(w, name, K_name))\n            name = next_node(w, name)\n        if matched == 1:\n            if found != NONE:\n                return 4294967276\n            found = operation\n            chosen_index = index\n        operation = next_node(w, operation)\n        index = index + 1\n    if found == NONE:\n        return 4294967276\n    qput(w, 16, found)\n    qput(w, 40, chosen_index)\n    return 0\n\ndef query_named(s:readbuf, w:mutbuf, array:u64, key:u64, record:u64) -> u64:\n    selected = NONE\n    item = child(w, array)\n    while item != NONE:\n        if request_matches(s, w, field(w, item, key), record) == 1:\n            if selected != NONE:\n                return NONE\n            selected = item\n        item = next_node(w, item)\n    return selected\n"

GRAPH = "\n# Native encoding of the original 8-Q slice header and row/edge/link packet.\n# The already-verified canonical Core tree is the sole input.  Python supplies\n# no SSA dictionary, graph rows, selected index, flags or JSON context.\n\ndef graph_counts(w:mutbuf) -> u64:\n    qput(w, 160, count(w, field(w, qget(w, 0), K_blocks)))\n    qput(w, 168, 0)\n    qput(w, 176, 0)\n    qput(w, 184, 0)\n    qput(w, 192, 0)\n    block = child(w, field(w, qget(w, 0), K_blocks))\n    while block != NONE:\n        qput(w, 176, qget(w, 176) + count(w, field(w, block, K_params)))\n        qput(w, 168, qget(w, 168) + count(w, field(w, block, K_ops)))\n        operation = child(w, field(w, block, K_ops))\n        while operation != NONE:\n            qput(w, 176, qget(w, 176) + count(w, field(w, operation, K_out)))\n            qput(w, 192, qget(w, 192) + count(w, field(w, operation, K_args)))\n            operation = next_node(w, operation)\n        term = field(w, block, K_term)\n        tag = graph_term_kind(w, term)\n        if tag == 0:\n            qput(w, 192, qget(w, 192) + count(w, field(w, term, K_values)))\n        if tag == 1:\n            qput(w, 184, qget(w, 184) + 1)\n            qput(w, 192, qget(w, 192) + 2 * count(w, field(w, term, K_args)))\n        if tag == 2:\n            qput(w, 184, qget(w, 184) + 2)\n            qput(w, 192, qget(w, 192) + 1 + 2 * count(w, field(w, field(w, term, K_then), K_args)) + 2 * count(w, field(w, field(w, term, K_else), K_args)))\n        block = next_node(w, block)\n    return qw_error(w)\n\ndef graph_allocate(w:mutbuf) -> u64:\n    size = 64 + qget(w, 160) * 64 + qget(w, 168) * 40 + qget(w, 176) * 16 + qget(w, 184) * 32 + qget(w, 192) * 8\n    # These are the original fact-packet bounds, not a smaller query policy.\n    if size > 8388608 or qget(w, 160) == 0 or qget(w, 168) == 0 or qget(w, 176) == 0:\n        return qw_fail(w, 4294967268)\n    qput(w, 72, size)\n    qput(w, 64, q_reserve(w, size))\n    qput(w, 80, q_reserve(w, qget(w, 160) * 8))\n    qput(w, 88, q_reserve(w, qget(w, 168) * 8))\n    qput(w, 96, q_reserve(w, qget(w, 176) * 8))\n    slots = 1\n    while slots < 2 * (qget(w, 160) + qget(w, 176)):\n        slots = slots << 1\n    qput(w, 112, slots)\n    qput(w, 104, q_reserve(w, slots * 24))\n    qput(w, 144, 64 + 8 * (qget(w, 160) + qget(w, 168) + qget(w, 176)))\n    qput(w, 128, qget(w, 144) + qget(w, 160) * 8)\n    qput(w, 120, q_reserve(w, qget(w, 128)))\n    qput(w, 136, q_reserve(w, qget(w, 144)))\n    qput(w, 272, 4 * qget(w, 360) + 4096)\n    qput(w, 256, q_reserve(w, qget(w, 272) * 64))\n    qput(w, 264, 0)\n    qput(w, 448, q_reserve(w, 2048))\n    qput(w, 456, 0)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    i = 0\n    while i < slots:\n        put(w, qget(w, 104) + i * 24, 0)\n        i = i + 1\n    graph_put(w, 0, SLICE_MAGIC)\n    graph_put(w, 8, qget(w, 160))\n    graph_put(w, 16, qget(w, 168))\n    graph_put(w, 24, qget(w, 176))\n    graph_put(w, 32, qget(w, 184))\n    graph_put(w, 40, qget(w, 192))\n    graph_put(w, 48, NONE)\n    graph_put(w, 56, NONE)\n    return 0\n\ndef graph_term_kind(w:mutbuf, term:u64) -> u64:\n    name = field(w, term, K_op)\n    if text_is(w, name, L_ret) == 1:\n        return 0\n    if text_is(w, name, L_jump) == 1:\n        return 1\n    if text_is(w, name, L_branch) == 1:\n        return 2\n    if text_is(w, name, L_trap) == 1:\n        return 3\n    qw_fail(w, 4294967268)\n    return NONE\n\ndef graph_symbol(w:mutbuf, name:u64, namespace:u64, value:u64) -> u64:\n    if kind(w, name) != 4 or (namespace != 1 and namespace != 2):\n        qw_fail(w, 4294967268)\n        return NONE\n    start = get(w, 64 + name * 56 + 24)\n    size = count(w, name)\n    hash = 14695981039346656037\n    i = 0\n    while i < size:\n        hash = (hash ^ byte(w, start + i)) * 1099511628211\n        i = i + 1\n    slots = qget(w, 112)\n    position = hash & (slots - 1)\n    probes = 0\n    while probes < slots:\n        record = qget(w, 104) + position * 24\n        tag = get(w, record)\n        if tag == 0:\n            if value == NONE:\n                qw_fail(w, 4294967268)\n                return NONE\n            put(w, record, namespace)\n            put(w, record + 8, name)\n            put(w, record + 16, value)\n            return value\n        if tag == namespace and arena_text_equal(w, name, get(w, record + 8)) == 1:\n            if value != NONE:\n                qw_fail(w, 4294967268)\n                return NONE\n            return get(w, record + 16)\n        position = (position + 1) & (slots - 1)\n        probes = probes + 1\n    qw_fail(w, 4294967268)\n    return NONE\n\ndef graph_index_values(w:mutbuf, owner:u64, producer:u64, array:u64) -> u64:\n    node = child(w, array)\n    while node != NONE and qw_error(w) == 0:\n        value = qget(w, 216)\n        if value >= qget(w, 176):\n            return qw_fail(w, 4294967268)\n        graph_value_set(w, value, 0, owner)\n        graph_value_set(w, value, 1, producer)\n        put(w, qget(w, 96) + value * 8, field(w, node, K_name))\n        graph_symbol(w, field(w, node, K_name), 2, value)\n        qput(w, 216, value + 1)\n        node = next_node(w, node)\n    return qw_error(w)\n\ndef graph_index(w:mutbuf) -> u64:\n    qput(w, 208, 0)\n    qput(w, 216, 0)\n    qput(w, 224, 0)\n    qput(w, 240, 0)\n    node = child(w, field(w, qget(w, 0), K_blocks))\n    while node != NONE and qw_error(w) == 0:\n        block = qget(w, 240)\n        put(w, qget(w, 80) + block * 8, node)\n        graph_symbol(w, field(w, node, K_id), 1, block)\n        graph_block_set(w, block, 0, qget(w, 216))\n        graph_block_set(w, block, 1, count(w, field(w, node, K_params)))\n        graph_index_values(w, block, NONE, field(w, node, K_params))\n        graph_block_set(w, block, 2, qget(w, 224))\n        graph_block_set(w, block, 3, count(w, field(w, node, K_ops)))\n        if node == qget(w, 8):\n            qput(w, 24, block)\n            graph_put(w, 48, block)\n        operation = child(w, field(w, node, K_ops))\n        while operation != NONE and qw_error(w) == 0:\n            index = qget(w, 224)\n            put(w, qget(w, 88) + index * 8, operation)\n            graph_op_set(w, index, 0, block)\n            graph_op_set(w, index, 1, qget(w, 208))\n            graph_op_set(w, index, 2, count(w, field(w, operation, K_args)))\n            qput(w, 208, qget(w, 208) + count(w, field(w, operation, K_args)))\n            graph_op_set(w, index, 3, qget(w, 216))\n            graph_op_set(w, index, 4, count(w, field(w, operation, K_out)))\n            if operation == qget(w, 16):\n                qput(w, 32, index)\n                graph_put(w, 56, index)\n            graph_index_values(w, block, index, field(w, operation, K_out))\n            qput(w, 224, index + 1)\n            operation = next_node(w, operation)\n        qput(w, 240, block + 1)\n        node = next_node(w, node)\n    if qget(w, 240) != qget(w, 160) or qget(w, 224) != qget(w, 168) or qget(w, 216) != qget(w, 176):\n        return qw_fail(w, 4294967268)\n    return qw_error(w)\n\ndef graph_write_links(w:mutbuf, array:u64, start:u64) -> u64:\n    current = child(w, array)\n    while current != NONE and qw_error(w) == 0:\n        if start >= qget(w, 192):\n            qw_fail(w, 4294967268)\n            return start\n        graph_link_set(w, start, graph_symbol(w, current, 2, NONE))\n        start = start + 1\n        current = next_node(w, current)\n    return start\n\ndef graph_edge(w:mutbuf, origin:u64, node:u64) -> u64:\n    index = qget(w, 200)\n    if index >= qget(w, 184):\n        return qw_fail(w, 4294967268)\n    graph_edge_set(w, index, 0, origin)\n    graph_edge_set(w, index, 1, graph_symbol(w, field(w, node, K_target), 1, NONE))\n    graph_edge_set(w, index, 2, qget(w, 208))\n    graph_edge_set(w, index, 3, count(w, field(w, node, K_args)))\n    qput(w, 208, graph_write_links(w, field(w, node, K_args), qget(w, 208)))\n    qput(w, 200, index + 1)\n    return qw_error(w)\n\ndef graph_fill_terminator(w:mutbuf, block:u64) -> u64:\n    term = field(w, graph_block_node(w, block), K_term)\n    tag = graph_term_kind(w, term)\n    graph_block_set(w, block, 4, tag)\n    graph_block_set(w, block, 5, NONE)\n    graph_block_set(w, block, 6, qget(w, 208))\n    if tag == 0:\n        qput(w, 208, graph_write_links(w, field(w, term, K_values), qget(w, 208)))\n    if tag == 1:\n        qput(w, 208, graph_write_links(w, field(w, term, K_args), qget(w, 208)))\n    if tag == 2:\n        condition = graph_symbol(w, field(w, term, K_cond), 2, NONE)\n        graph_block_set(w, block, 5, condition)\n        if qget(w, 208) >= qget(w, 192):\n            return qw_fail(w, 4294967268)\n        graph_link_set(w, qget(w, 208), condition)\n        qput(w, 208, qget(w, 208) + 1)\n        qput(w, 208, graph_write_links(w, field(w, field(w, term, K_then), K_args), qget(w, 208)))\n        qput(w, 208, graph_write_links(w, field(w, field(w, term, K_else), K_args), qget(w, 208)))\n    graph_block_set(w, block, 7, qget(w, 208) - sl_block(w, block, 6))\n    if tag == 1:\n        graph_edge(w, block, term)\n    if tag == 2:\n        graph_edge(w, block, field(w, term, K_then))\n        graph_edge(w, block, field(w, term, K_else))\n    return qw_error(w)\n\ndef graph_fill(w:mutbuf) -> u64:\n    index = 0\n    while index < qget(w, 168) and qw_error(w) == 0:\n        end = graph_write_links(w, field(w, graph_operation_node(w, index), K_args), sl_op(w, index, 1))\n        if end != sl_op(w, index, 1) + sl_op(w, index, 2):\n            return qw_fail(w, 4294967268)\n        index = index + 1\n    qput(w, 200, 0)\n    block = 0\n    while block < qget(w, 160) and qw_error(w) == 0:\n        graph_fill_terminator(w, block)\n        block = block + 1\n    if qget(w, 200) != qget(w, 184) or qget(w, 208) != qget(w, 192):\n        return qw_fail(w, 4294967268)\n    return qw_error(w)\n"

TREE = "# Native HIA query-tree construction. String literals below are static\n# authoring macros, expanded to native packed-byte operations at build time.\n# qclone performs a native subtree copy into a distinct parent/sibling arena;\n# no copied JSON object or context is supplied by the host.\n\ndef build_query_tree(w:mutbuf, operation:u64) -> u64:\n    root = qcontainer(w, 6)\n    if qget(w, 56) == 1:\n        qadd(w, root, qtext(w, \"hepta.hia.edit-query.v3\"), \"schema\")\n    else:\n        qadd(w, root, qtext(w, \"hepta.hia.edit-query.v2\"), \"schema\")\n    qadd(w, root, qdigest_text(w, 0), \"base_sha256\")\n    qadd(w, root, qdigest_text(w, 1), \"input_sha256\")\n    qadd(w, root, query_selector(w), \"selector\")\n    qadd(w, root, query_field_names(w), \"fields\")\n    qadd(w, root, qdigest_text(w, 2), \"operation_sha256\")\n    qadd(w, root, query_context(w, operation), \"context\")\n    qadd(w, root, qtext(w, \"explicit SSA slice with complete displayed terminator inputs and full reachable regions of value-affected branches; precise control-dependence, aliases and behavioral equivalence are NOT proved; whole module is reverified\"), \"scope\")\n    return root\n\ndef query_selector(w:mutbuf) -> u64:\n    result = qcontainer(w, 6)\n    qadd(w, result, qclone(w, field(w, qget(w, 0), K_name)), \"function\")\n    qadd(w, result, qclone(w, field(w, qget(w, 8), K_id)), \"block\")\n    qadd(w, result, qclone(w, qget(w, 232)), \"output\")\n    return result\n\ndef query_field_names(w:mutbuf) -> u64:\n    result = qcontainer(w, 5)\n    fields = qget(w, 48)\n    if (fields & 1) != 0:\n        qappend(w, result, qtext(w, \"args\"))\n    if (fields & 2) != 0:\n        qappend(w, result, qtext(w, \"attrs\"))\n    if (fields & 4) != 0:\n        qappend(w, result, qtext(w, \"op\"))\n    return result\n\ndef query_context(w:mutbuf, operation:u64) -> u64:\n    result = qcontainer(w, 6)\n    block = qget(w, 8)\n    selected = qget(w, 24)\n    qadd(w, result, query_signature(w, qget(w, 0)), \"function\")\n    qadd(w, result, qclone(w, field(w, block, K_params)), \"block_params\")\n    qadd(w, result, query_entries(w, selected, 2), \"dependencies\")\n    qadd(w, result, qinteger(w, qget(w, 40)), \"operation_index\")\n    qadd(w, result, operation, \"operation\")\n    qadd(w, result, query_entries(w, selected, 1), \"consumers\")\n    qadd(w, result, query_downstream(w), \"downstream\")\n    qadd(w, result, qclone(w, field(w, block, K_term)), \"terminator\")\n    qadd(w, result, query_callees(w), \"callees\")\n    return result\n\ndef query_signature(w:mutbuf, function:u64) -> u64:\n    result = qcontainer(w, 6)\n    qadd(w, result, qclone(w, field(w, function, K_name)), \"name\")\n    qadd(w, result, qclone(w, field(w, function, K_params)), \"params\")\n    qadd(w, result, qclone(w, field(w, function, K_returns)), \"returns\")\n    qadd(w, result, qclone(w, field(w, function, K_effects)), \"effects\")\n    if qget(w, 56) == 1:\n        loans = field(w, function, K_return_loans)\n        if loans == NONE:\n            defaults = qcontainer(w, 5)\n            i = 0\n            while i < count(w, field(w, function, K_returns)):\n                qappend(w, defaults, qnull(w))\n                i = i + 1\n            qadd(w, result, defaults, \"return_loans\")\n        else:\n            qadd(w, result, qclone(w, loans), \"return_loans\")\n    return result\n\ndef query_entries(w:mutbuf, block:u64, wanted:u64) -> u64:\n    result = qcontainer(w, 5)\n    start = sl_block(w, block, 2)\n    stop = start + sl_block(w, block, 3)\n    i = start\n    while i < stop:\n        if result_op_flag(w, i) == wanted:\n            item = qcontainer(w, 6)\n            qadd(w, item, qinteger(w, i - start), \"index\")\n            qadd(w, item, qclone(w, graph_operation_node(w, i)), \"operation\")\n            qappend(w, result, item)\n        i = i + 1\n    return result\n\ndef query_callees(w:mutbuf) -> u64:\n    result = qcontainer(w, 5)\n    function = child(w, field(w, 0, K_functions))\n    while function != NONE:\n        if query_called(w, field(w, function, K_name)) == 1:\n            qappend(w, result, query_signature(w, function))\n        function = next_node(w, function)\n    return result\n\ndef query_collect_calls(w:mutbuf) -> u64:\n    qput(w, 456, 0)\n    i = 0\n    while i < graph_get(w, 16):\n        if result_op_flag(w, i) != 0:\n            operation = graph_operation_node(w, i)\n            if text_is(w, field(w, operation, K_op), L_call) == 1:\n                if qget(w, 456) >= 256:\n                    return qw_fail(w, 4294967268)\n                put(w, qget(w, 448) + qget(w, 456) * 8, field(w, field(w, operation, K_attrs), K_function))\n                qput(w, 456, qget(w, 456) + 1)\n        i = i + 1\n    return 0\n\ndef query_called(w:mutbuf, name:u64) -> u64:\n    i = 0\n    while i < qget(w, 456):\n        if arena_text_equal(w, get(w, qget(w, 448) + i * 8), name) == 1:\n            return 1\n        i = i + 1\n    return 0\n\ndef query_downstream(w:mutbuf) -> u64:\n    result = qcontainer(w, 5)\n    block = 0\n    while block < graph_get(w, 8):\n        if result_block_flag(w, block) != 0:\n            qappend(w, result, query_downstream_block(w, block))\n        block = block + 1\n    return result\n\ndef query_downstream_block(w:mutbuf, block:u64) -> u64:\n    result = qcontainer(w, 6)\n    source = graph_block_node(w, block)\n    flag = result_block_flag(w, block)\n    qadd(w, result, qclone(w, field(w, source, K_id)), \"id\")\n    qadd(w, result, qclone(w, field(w, source, K_params)), \"params\")\n    qadd(w, result, query_affected_params(w, block), \"affected_params\")\n    qadd(w, result, qboolean(w, (flag & 2) != 0), \"control_reachable\")\n    qadd(w, result, query_entries(w, block, 2), \"dependencies\")\n    qadd(w, result, query_entries(w, block, 1), \"consumers\")\n    qadd(w, result, qclone(w, field(w, source, K_term)), \"terminator\")\n    qadd(w, result, qboolean(w, (flag & 4) != 0), \"branch_condition_affected\")\n    return result\n\ndef query_affected_params(w:mutbuf, block:u64) -> u64:\n    result = qcontainer(w, 5)\n    value = sl_block(w, block, 0)\n    stop = value + sl_block(w, block, 1)\n    while value < stop:\n        if (result_value_flag(w, value) & 2) != 0:\n            qappend(w, result, qclone(w, graph_value_name(w, value)))\n        value = value + 1\n    qsort_strings(w, result)\n    return result\n"

ARENA = "\ndef q_new(w:mutbuf, tag:u64, payload:u64, size:u64) -> u64:\n    if qw_error(w) != 0:\n        return 0\n    node = qget(w, 264)\n    if node >= qget(w, 272):\n        qw_fail(w, 4294967268)\n        return 0\n    record = qget(w, 256) + (node << 6)\n    if record > length(w) or length(w) - record < 64:\n        qw_fail(w, 4294967268)\n        return 0\n    put(w, record, tag)\n    put(w, record + 8, NONE)\n    put(w, record + 16, NONE)\n    put(w, record + 24, payload)\n    put(w, record + 32, size)\n    put(w, record + 40, 0)\n    put(w, record + 48, 0)\n    put(w, record + 56, NONE)\n    qput(w, 264, node + 1)\n    return node\n\ndef q_attach(w:mutbuf, parent:u64, node:u64, key:u64, size:u64) -> u64:\n    if qw_error(w) != 0:\n        return 0\n    if parent >= qget(w, 264) or node >= qget(w, 264) or parent == node:\n        return qw_fail(w, 4294967268)\n    destination = qw_record(w, parent)\n    record = qw_record(w, node)\n    tag = get(w, destination)\n    if tag != 5 and tag != 6:\n        return qw_fail(w, 4294967268)\n    if get(w, record + 8) != NONE or get(w, record + 16) != NONE:\n        return qw_fail(w, 4294967268)\n    if key > length(w) or size > length(w) - key:\n        return qw_fail(w, 4294967268)\n    last = get(w, destination + 56)\n    if last == NONE:\n        if get(w, destination + 32) != 0 or get(w, destination + 24) != NONE:\n            return qw_fail(w, 4294967268)\n        put(w, destination + 24, node)\n    else:\n        if last >= qget(w, 264) or get(w, qw_record(w, last) + 8) != parent:\n            return qw_fail(w, 4294967268)\n        put(w, qw_record(w, last) + 16, node)\n    put(w, record + 8, parent)\n    put(w, record + 40, choose(tag == 6, key, 0))\n    put(w, record + 48, choose(tag == 6, size, 0))\n    put(w, destination + 56, node)\n    put(w, destination + 32, get(w, destination + 32) + 1)\n    return 0\n\ndef q_clone_node(w:mutbuf, source:u64) -> u64:\n    if source >= qget(w, 360):\n        qw_fail(w, 4294967268)\n        return 0\n    tag = kind(w, source)\n    if tag > 6:\n        qw_fail(w, 4294967268)\n        return 0\n    if tag == 5 or tag == 6:\n        return q_new(w, tag, NONE, 0)\n    return q_new(w, tag, get(w, 64 + source * 56 + 24), count(w, source))\n\ndef qclone(w:mutbuf, source:u64) -> u64:\n    root = q_clone_node(w, source)\n    current = source\n    clone = root\n    walking = True\n    while walking and qw_error(w) == 0:\n        nested = child(w, current)\n        if nested != NONE:\n            copied = q_clone_node(w, nested)\n            q_attach(w, clone, copied, get(w, 64 + nested * 56 + 40), get(w, 64 + nested * 56 + 48))\n            current = nested\n            clone = copied\n        else:\n            climbing = True\n            while climbing and qw_error(w) == 0:\n                if current == source:\n                    walking = False\n                    climbing = False\n                else:\n                    following = next_node(w, current)\n                    if following != NONE:\n                        copied = q_clone_node(w, following)\n                        q_attach(w, get(w, qw_record(w, clone) + 8), copied,\n                                 get(w, 64 + following * 56 + 40), get(w, 64 + following * 56 + 48))\n                        current = following\n                        clone = copied\n                        climbing = False\n                    else:\n                        current = get(w, 64 + current * 56 + 8)\n                        clone = get(w, qw_record(w, clone) + 8)\n    return root\n\ndef qsort_strings(w:mutbuf, node:u64) -> u64:\n    if qw_error(w) != 0:\n        return 0\n    if node >= qget(w, 264) or get(w, qw_record(w, node)) != 5:\n        return qw_fail(w, 4294967268)\n    current = get(w, qw_record(w, node) + 24)\n    while current != NONE and qw_error(w) == 0:\n        record = qw_record(w, current)\n        if get(w, record) != 4:\n            return qw_fail(w, 4294967268)\n        put(w, record + 40, get(w, record + 24))\n        put(w, record + 48, get(w, record + 32))\n        current = get(w, record + 16)\n    qw_sort_object(w, node)\n    current = get(w, qw_record(w, node) + 24)\n    while current != NONE:\n        record = qw_record(w, current)\n        put(w, record + 40, 0)\n        put(w, record + 48, 0)\n        current = get(w, record + 16)\n    return qw_error(w)\n\ndef q_reserve(w:mutbuf, size:u64) -> u64:\n    cursor = qget(w, 352)\n    if cursor > length(w) or size > length(w) - cursor:\n        qw_fail(w, 4294967268)\n        return 0\n    qput(w, 352, cursor + size)\n    return cursor\n\ndef arena_text_equal(w:mutbuf, left:u64, right:u64) -> u64:\n    if kind(w, left) != 4 or kind(w, right) != 4:\n        return 0\n    size = count(w, left)\n    if size != count(w, right):\n        return 0\n    a = get(w, 64 + left * 56 + 24)\n    b = get(w, 64 + right * 56 + 24)\n    i = 0\n    while i < size:\n        if byte(w, a + i) != byte(w, b + i):\n            return 0\n        i = i + 1\n    return 1\n"

ASCII_WRITER = "\ndef query_wire(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u64:\n    if length(w) < 48 or length(o) < 1048640:\n        return 4294967268\n    state = get(w, 40)\n    if state > length(w) or length(w) - state < 352:\n        return 4294967268\n    base = get(w, state + 256)\n    count = get(w, state + 264)\n    capacity = get(w, state + 272)\n    if count > capacity or root >= count:\n        return 4294967268\n    if base > length(w) or capacity > ((length(w) - base) >> 6):\n        return 4294967268\n    record = base + (root << 6)\n    if get(w, record + 8) != 18446744073709551615 or get(w, record + 16) != 18446744073709551615:\n        return 4294967268\n    put(w, state + 280, 64)\n    put(w, state + 288, 0)\n    put(w, state + 296, 0)\n    put(w, state + 304, 0)\n    put(w, state + 312, 1)\n    put(w, state + 320, root)\n    put(w, state + 328, 0)\n    put(w, state + 336, 1048576)\n    put(w, state + 344, 64)\n    qw_preflight(s, w, root)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    put(w, state + 328, 1)\n    qw_emit_tree(s, o, w, root)\n    if qw_error(w) != 0:\n        return qw_error(w)\n    return get(w, state + 280) - 64\n\ndef qw_error(w:mutbuf) -> u64:\n    return get(w, get(w, 40) + 288)\n\ndef qw_fail(w:mutbuf, code:u64) -> u64:\n    state = get(w, 40)\n    if get(w, state + 288) == 0:\n        put(w, state + 288, code)\n    return 0\n\ndef qw_record(w:mutbuf, node:u64) -> u64:\n    return get(w, get(w, 40) + 256) + (node << 6)\n\ndef qw_valid_node(w:mutbuf, node:u64) -> u64:\n    if node >= get(w, get(w, 40) + 264):\n        qw_fail(w, 4294967268)\n        return 0\n    return 1\n\ndef qw_utf8_unit(w:mutbuf, at:u64, end:u64) -> u64:\n    if at >= end or end > length(w):\n        return 0\n    first = byte(w, at)\n    if first < 128:\n        return 4294967296 | first\n    remaining = end - at\n    if first < 194 or first > 244 or remaining < 2:\n        return 0\n    second = byte(w, at + 1)\n    if second < 128 or second > 191:\n        return 0\n    if first < 224:\n        return 8589934592 | ((first & 31) << 6) | (second & 63)\n    if remaining < 3:\n        return 0\n    third = byte(w, at + 2)\n    if third < 128 or third > 191:\n        return 0\n    if first == 224 and second < 160:\n        return 0\n    if first == 237 and second > 159:\n        return 0\n    if first < 240:\n        return 12884901888 | ((first & 15) << 12) | ((second & 63) << 6) | (third & 63)\n    if remaining < 4:\n        return 0\n    fourth = byte(w, at + 3)\n    if fourth < 128 or fourth > 191:\n        return 0\n    if first == 240 and second < 144:\n        return 0\n    if first == 244 and second > 143:\n        return 0\n    return 17179869184 | ((first & 7) << 18) | ((second & 63) << 12) | ((third & 63) << 6) | (fourth & 63)\n\ndef qw_ascii_width(point:u64) -> u64:\n    if point == 34 or point == 92:\n        return 2\n    if point < 32:\n        if point == 8 or point == 9 or point == 10 or point == 12 or point == 13:\n            return 2\n        return 6\n    if point < 127:\n        return 1\n    if point <= 65535:\n        return 6\n    return 12\n\ndef qw_string_size(w:mutbuf, start:u64, size:u64) -> u64:\n    if start > length(w) or size > length(w) - start:\n        return qw_fail(w, 4294967268)\n    at = start\n    end = start + size\n    total = 2\n    while at < end:\n        unit = qw_utf8_unit(w, at, end)\n        if unit == 0:\n            return qw_fail(w, 4294967270)\n        width = qw_ascii_width(unit & 4294967295)\n        if width > 1048576 - total:\n            return qw_fail(w, 4294967271)\n        total = total + width\n        at = at + (unit >> 32)\n    return total\n\ndef qw_integer_span(s:readbuf, w:mutbuf, start:u64, size:u64) -> u64:\n    # Kind 3 is an original canonical Core integer lexeme, never float bits.\n    # Preserve its decimal span instead of narrowing it to u64.\n    if start > length(s) or size > length(s) - start or size == 0:\n        return qw_fail(w, 4294967268)\n    at = start\n    end = start + size\n    if byte(s, at) == 45:\n        at = at + 1\n    if at >= end:\n        return qw_fail(w, 4294967268)\n    if byte(s, at) == 48 and end - at != 1:\n        return qw_fail(w, 4294967268)\n    while at < end:\n        value = byte(s, at)\n        if value < 48 or value > 57:\n            return qw_fail(w, 4294967268)\n        at = at + 1\n    return size\n\ndef qw_check_children(w:mutbuf, parent:u64, object:u64) -> u64:\n    record = qw_record(w, parent)\n    wanted = get(w, record + 32)\n    child = get(w, record + 24)\n    previous = 18446744073709551615\n    seen = 0\n    while child != 18446744073709551615 and seen < wanted:\n        if qw_valid_node(w, child) == 0:\n            return 0\n        current = qw_record(w, child)\n        if get(w, current + 8) != parent:\n            return qw_fail(w, 4294967268)\n        if object == 1:\n            qw_string_size(w, get(w, current + 40), get(w, current + 48))\n            if qw_error(w) != 0:\n                return 0\n        previous = child\n        child = get(w, current + 16)\n        seen = seen + 1\n    if child != 18446744073709551615 or seen != wanted or previous != get(w, record + 56):\n        return qw_fail(w, 4294967268)\n    return 1\n\ndef qw_reverse_children(w:mutbuf, parent:u64) -> u64:\n    # Private query nodes only. Preflight reverses on entry and restores on exit.\n    record = qw_record(w, parent)\n    original = get(w, record + 24)\n    current = original\n    previous = 18446744073709551615\n    while current != 18446744073709551615:\n        child = qw_record(w, current)\n        following = get(w, child + 16)\n        put(w, child + 16, previous)\n        previous = current\n        current = following\n    put(w, record + 24, previous)\n    put(w, record + 56, original)\n    return 0\n\ndef qw_enter(s:readbuf, w:mutbuf, node:u64) -> u64:\n    state = get(w, 40)\n    if get(w, state + 296) > 128:\n        qw_fail(w, 4294967274)\n        return 18446744073709551615\n    if qw_valid_node(w, node) == 0:\n        return 18446744073709551615\n    queued = get(w, state + 312)\n    if queued == 0:\n        qw_fail(w, 4294967268)\n        return 18446744073709551615\n    queued = queued - 1\n    visited = get(w, state + 304) + 1\n    put(w, state + 312, queued)\n    put(w, state + 304, visited)\n    if visited > 262144:\n        qw_fail(w, 4294967272)\n        return 18446744073709551615\n    record = qw_record(w, node)\n    kind = get(w, record)\n    if kind > 7:\n        qw_fail(w, 4294967268)\n        return 18446744073709551615\n    if kind == 5 or kind == 6:\n        children = get(w, record + 32)\n        if queued > 262144 - visited or children > 262144 - visited - queued:\n            qw_fail(w, 4294967275)\n            return 18446744073709551615\n        put(w, state + 312, queued + children)\n        if qw_check_children(w, node, choose(kind == 6, 1, 0)) == 0:\n            return 18446744073709551615\n        qw_reverse_children(w, node)\n        if children != 0:\n            put(w, state + 296, get(w, state + 296) + 1)\n            return get(w, record + 24)\n    else:\n        if kind == 4:\n            qw_string_size(w, get(w, record + 24), get(w, record + 32))\n        if kind == 3:\n            relative = get(w, record + 24)\n            if relative > length(s) or length(s) - relative < 3392:\n                qw_fail(w, 4294967268)\n            else:\n                qw_integer_span(s, w, relative + 3392, get(w, record + 32))\n    return 18446744073709551615\n\ndef qw_preflight(s:readbuf, w:mutbuf, root:u64) -> u64:\n    node = root\n    walking = True\n    while walking and qw_error(w) == 0:\n        child = qw_enter(s, w, node)\n        if child != 18446744073709551615 and qw_error(w) == 0:\n            node = child\n        else:\n            climbing = True\n            while climbing and qw_error(w) == 0:\n                if node == root:\n                    walking = False\n                    climbing = False\n                else:\n                    record = qw_record(w, node)\n                    sibling = get(w, record + 16)\n                    if sibling != 18446744073709551615:\n                        node = sibling\n                        climbing = False\n                    else:\n                        parent = get(w, record + 8)\n                        if qw_valid_node(w, parent) == 0:\n                            return 0\n                        qw_reverse_children(w, parent)\n                        node = parent\n                        state = get(w, 40)\n                        depth = get(w, state + 296)\n                        if depth == 0:\n                            return qw_fail(w, 4294967268)\n                        put(w, state + 296, depth - 1)\n    return qw_error(w)\n\ndef qw_emit(o:mutbuf, w:mutbuf, value:u64) -> u64:\n    if qw_error(w) != 0:\n        return 0\n    state = get(w, 40)\n    cursor = get(w, state + 280)\n    if cursor < 64:\n        return qw_fail(w, 4294967268)\n    if cursor - 64 >= 1048576:\n        return qw_fail(w, 4294967273)\n    if cursor >= length(o):\n        return qw_fail(w, 4294967268)\n    store(o, cursor, value)\n    put(w, state + 280, cursor + 1)\n    return 0\n\ndef qw_hex(value:u64) -> u64:\n    if value < 10:\n        return value + 48\n    return value + 87\n\ndef qw_u16_escape(o:mutbuf, w:mutbuf, point:u64) -> u64:\n    qw_emit(o, w, 92)\n    qw_emit(o, w, 117)\n    qw_emit(o, w, qw_hex((point >> 12) & 15))\n    qw_emit(o, w, qw_hex((point >> 8) & 15))\n    qw_emit(o, w, qw_hex((point >> 4) & 15))\n    qw_emit(o, w, qw_hex(point & 15))\n    return 0\n\ndef qw_string(o:mutbuf, w:mutbuf, start:u64, size:u64) -> u64:\n    qw_emit(o, w, 34)\n    at = start\n    end = start + size\n    while at < end and qw_error(w) == 0:\n        unit = qw_utf8_unit(w, at, end)\n        if unit == 0:\n            return qw_fail(w, 4294967270)\n        point = unit & 4294967295\n        if point == 34 or point == 92:\n            qw_emit(o, w, 92)\n            qw_emit(o, w, point)\n        else:\n            if point < 32:\n                escaped = 0\n                if point == 8:\n                    escaped = 98\n                if point == 9:\n                    escaped = 116\n                if point == 10:\n                    escaped = 110\n                if point == 12:\n                    escaped = 102\n                if point == 13:\n                    escaped = 114\n                if escaped != 0:\n                    qw_emit(o, w, 92)\n                    qw_emit(o, w, escaped)\n                else:\n                    qw_u16_escape(o, w, point)\n            else:\n                if point < 127:\n                    qw_emit(o, w, point)\n                else:\n                    if point <= 65535:\n                        qw_u16_escape(o, w, point)\n                    else:\n                        remaining = point - 65536\n                        qw_u16_escape(o, w, 55296 + (remaining >> 10))\n                        qw_u16_escape(o, w, 56320 + (remaining & 1023))\n        at = at + (unit >> 32)\n    qw_emit(o, w, 34)\n    return qw_error(w)\n\ndef qw_key_order(w:mutbuf, left:u64, right:u64) -> u64:\n    # 0 equal, 1 less, 2 greater; compare decoded UTF-8, not JSON escape spelling.\n    a = qw_record(w, left)\n    b = qw_record(w, right)\n    start_a = get(w, a + 40)\n    start_b = get(w, b + 40)\n    size_a = get(w, a + 48)\n    size_b = get(w, b + 48)\n    i = 0\n    while i < size_a and i < size_b:\n        x = byte(w, start_a + i)\n        y = byte(w, start_b + i)\n        if x < y:\n            return 1\n        if x > y:\n            return 2\n        i = i + 1\n    if size_a < size_b:\n        return 1\n    if size_a > size_b:\n        return 2\n    return 0\n\ndef qw_sort_object(w:mutbuf, node:u64) -> u64:\n    record = qw_record(w, node)\n    size = get(w, record + 32)\n    if size < 2:\n        return 0\n    head = get(w, record + 24)\n    width = 1\n    tail = 18446744073709551615\n    while width < size:\n        p = head\n        head = 18446744073709551615\n        tail = 18446744073709551615\n        while p != 18446744073709551615:\n            q = p\n            left = 0\n            while left < width and q != 18446744073709551615:\n                q = get(w, qw_record(w, q) + 16)\n                left = left + 1\n            right = width\n            element = 0\n            while left > 0 or (right > 0 and q != 18446744073709551615):\n                take_left = False\n                if left > 0:\n                    if right == 0 or q == 18446744073709551615:\n                        take_left = True\n                    else:\n                        if qw_key_order(w, p, q) != 2:\n                            take_left = True\n                if take_left:\n                    element = p\n                    p = get(w, qw_record(w, p) + 16)\n                    left = left - 1\n                else:\n                    element = q\n                    q = get(w, qw_record(w, q) + 16)\n                    right = right - 1\n                if tail == 18446744073709551615:\n                    head = element\n                else:\n                    put(w, qw_record(w, tail) + 16, element)\n                tail = element\n            p = q\n        put(w, qw_record(w, tail) + 16, 18446744073709551615)\n        width = width * 2\n    put(w, record + 24, head)\n    put(w, record + 56, tail)\n    p = head\n    while p != 18446744073709551615:\n        q = get(w, qw_record(w, p) + 16)\n        if q != 18446744073709551615:\n            if qw_key_order(w, p, q) == 0:\n                return qw_fail(w, 4294967268)\n        p = q\n    return 0\n\ndef qw_decimal(o:mutbuf, w:mutbuf, value:u64) -> u64:\n    index = 0\n    started = False\n    while index < 20:\n        power = qw_decimal_power(index)\n        digit = 0\n        while value >= power:\n            value = value - power\n            digit = digit + 1\n        if digit != 0 or started or index == 19:\n            qw_emit(o, w, 48 + digit)\n            started = True\n        index = index + 1\n    return 0\n\ndef qw_atom(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:\n    record = qw_record(w, node)\n    kind = get(w, record)\n    if kind == 0:\n        qw_emit(o, w, 110)\n        qw_emit(o, w, 117)\n        qw_emit(o, w, 108)\n        qw_emit(o, w, 108)\n    if kind == 1:\n        qw_emit(o, w, 102)\n        qw_emit(o, w, 97)\n        qw_emit(o, w, 108)\n        qw_emit(o, w, 115)\n        qw_emit(o, w, 101)\n    if kind == 2:\n        qw_emit(o, w, 116)\n        qw_emit(o, w, 114)\n        qw_emit(o, w, 117)\n        qw_emit(o, w, 101)\n    if kind == 3:\n        start = get(w, record + 24) + 3392\n        size = get(w, record + 32)\n        i = 0\n        if size == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:\n            qw_emit(o, w, 48)\n        else:\n            while i < size and qw_error(w) == 0:\n                qw_emit(o, w, byte(s, start + i))\n                i = i + 1\n    if kind == 4:\n        qw_string(o, w, get(w, record + 24), get(w, record + 32))\n    if kind == 7:\n        qw_decimal(o, w, get(w, record + 24))\n    return qw_error(w)\n\ndef qw_emit_tree(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u64:\n    node = root\n    walking = True\n    while walking and qw_error(w) == 0:\n        record = qw_record(w, node)\n        kind = get(w, record)\n        parent = get(w, record + 8)\n        if node != root:\n            if get(w, qw_record(w, parent)) == 6:\n                qw_string(o, w, get(w, record + 40), get(w, record + 48))\n                qw_emit(o, w, 58)\n                if qw_error(w) != 0:\n                    return qw_error(w)\n        complete = True\n        if kind == 5 or kind == 6:\n            if kind == 6:\n                qw_sort_object(w, node)\n                if qw_error(w) != 0:\n                    return qw_error(w)\n            qw_emit(o, w, choose(kind == 5, 91, 123))\n            if get(w, record + 32) == 0:\n                qw_emit(o, w, choose(kind == 5, 93, 125))\n            else:\n                node = get(w, record + 24)\n                complete = False\n        else:\n            qw_atom(s, o, w, node)\n        if complete:\n            moving = True\n            while moving and qw_error(w) == 0:\n                if node == root:\n                    walking = False\n                    moving = False\n                else:\n                    record = qw_record(w, node)\n                    sibling = get(w, record + 16)\n                    if sibling != 18446744073709551615:\n                        qw_emit(o, w, 44)\n                        node = sibling\n                        moving = False\n                    else:\n                        node = get(w, record + 8)\n                        qw_emit(o, w, choose(get(w, qw_record(w, node)) == 5, 93, 125))\n    return qw_error(w)\n\ndef qw_decimal_power(index:u64) -> u64:\n    if index == 0:\n        return 10000000000000000000\n    if index == 1:\n        return 1000000000000000000\n    if index == 2:\n        return 100000000000000000\n    if index == 3:\n        return 10000000000000000\n    if index == 4:\n        return 1000000000000000\n    if index == 5:\n        return 100000000000000\n    if index == 6:\n        return 10000000000000\n    if index == 7:\n        return 1000000000000\n    if index == 8:\n        return 100000000000\n    if index == 9:\n        return 10000000000\n    if index == 10:\n        return 1000000000\n    if index == 11:\n        return 100000000\n    if index == 12:\n        return 10000000\n    if index == 13:\n        return 1000000\n    if index == 14:\n        return 100000\n    if index == 15:\n        return 10000\n    if index == 16:\n        return 1000\n    if index == 17:\n        return 100\n    if index == 18:\n        return 10\n    return 1\n"


def _name(value):
    return ast.Name(id=value, ctx=ast.Load())


def _constant(value):
    return ast.Constant(value=value)


def _call(name, *args):
    return ast.Call(func=_name(name), args=list(args), keywords=[])


def _add(left, right):
    return ast.BinOp(left=left, op=ast.Add(), right=right)


def _multiply(left, right):
    return ast.BinOp(left=left, op=ast.Mult(), right=right)


def _qstate():
    return _call('get', _name('w'), _constant(40))


def _qget(offset):
    return _call('qget', _name('w'), _constant(offset))


def _address(offset, index, stride):
    return _add(_qget(offset), _multiply(index, _constant(stride)))


def _packed(text):
    raw = text.encode('ascii')
    if len(raw) > 24:
        raise ValueError('packed comparison literal exceeds existing helper')
    return [len(raw), *(int.from_bytes(raw[i:i+8], 'little') for i in (0, 8, 16))]


class _CoreInput(ast.NodeTransformer):
    """Only JSON parser input accesses move to the exact canonical span."""
    def visit_Call(self, node):
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Name):
            if (node.func.id == 'length' and len(node.args) == 1
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == 's'):
                return _call('uint', _name('s'), _constant(CORE_LENGTH_FIELD))
            if (node.func.id == 'byte' and len(node.args) == 2
                    and isinstance(node.args[0], ast.Name) and node.args[0].id == 's'):
                return _call('byte', _name('s'), _add(_constant(INPUT_OFFSET), node.args[1]))
        return node


def _decoder_nodes():
    # source_program itself contains the original single count-export guard.
    # Use its actual supported HIA source, never a host JSON parser.
    return _CoreInput().visit(ast.parse(decoder_source())).body


class _SliceWorkspace(ast.NodeTransformer):
    """Rebase source/result/private scratch into three disjoint regions.

    No branch, operation, ordering, refusal constant or loop is rewritten.
    A private packet produced by the new native encoder still passes valid().
    """
    def __init__(self, signatures):
        self.signatures = signatures

    def visit_Name(self, node):
        if node.id in {'s', 'o'}:
            return ast.copy_location(_name('w'), node)
        return node

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Name):
            raise ValueError('slice source contains an unsupported call expression')
        name = node.func.id
        original = node.args
        if name == 'uint':
            if len(original) != 2 or not isinstance(original[0], ast.Name) or original[0].id != 's':
                raise ValueError('slice input reader role changed')
            return _call('get', _name('w'), _add(_qget(64), self.visit(original[1])))
        if name in {'get', 'put', 'store', 'byte'}:
            if not original or not isinstance(original[0], ast.Name):
                raise ValueError('slice memory role changed')
            role = original[0].id
            expected = {'get': {'w'}, 'put': {'w', 'o'},
                        'store': {'w'}, 'byte': set()}
            if role not in expected[name]:
                raise ValueError(('unexpected slice memory role', name, role))
            base = 120 if role == 'w' else 136
            args = [_name('w'), _add(_qget(base), self.visit(original[1]))]
            args.extend(self.visit(value) for value in original[2:])
            return _call(name, *args)
        if name == 'length':
            if len(original) != 1 or not isinstance(original[0], ast.Name):
                raise ValueError('slice length role changed')
            offset = {'s': 72, 'o': 144, 'w': 128}.get(original[0].id)
            if offset is None:
                raise ValueError('unknown slice length role')
            return _qget(offset)
        if name in self.signatures:
            signature = self.signatures[name]
            if len(original) != len(signature):
                raise ValueError('slice call arity changed')
            kept = [self.visit(value) for value, typ in zip(original, signature, strict=True)
                    if typ not in {'readbuf', 'mutbuf'}]
            return _call('sl_' + name, _name('w'), *kept)
        return self.generic_visit(node)


def _slice_nodes():
    original = ast.parse(slice_source()).body
    signatures = {node.name: [arg.annotation.id for arg in node.args.args]
                  for node in original}
    result = []
    for node in original:
        if node.name in {'uint', 'get', 'put'}:
            continue
        source_name = node.name
        node = _SliceWorkspace(signatures).visit(node)
        node.name = 'sl_' + source_name
        kept = [arg for arg in node.args.args
                if arg.annotation.id not in {'readbuf', 'mutbuf'}]
        node.args.args = [ast.arg(arg='w', annotation=_name('mutbuf')), *kept]
        result.append(node)
    return result


class _QueryHash(ast.NodeTransformer):
    """Reuse SHA rounds/padding; select an immutable span from native state."""
    def visit_Call(self, node):
        if not isinstance(node.func, ast.Name):
            raise ValueError('SHA source contains an unsupported call')
        name = node.func.id
        original = node.args
        node = self.generic_visit(node)
        if name == 'length' and isinstance(original[0], ast.Name):
            if original[0].id == 's':
                return _qget(416)
            if original[0].id == 'w':
                return ast.BinOp(left=_call('length', _name('w')), op=ast.Sub(),
                                 right=_add(_qstate(), _constant(2048)))
        if name in {'get', 'put'}:
            if not isinstance(original[0], ast.Name) or original[0].id != 'w':
                raise ValueError('SHA workspace role changed')
            return _call(name, _name('w'),
                         _add(_add(_qstate(), _constant(2048)), node.args[1]),
                         *node.args[2:])
        if name == 'padded_byte':
            return _call('query_padded_byte', _name('s'), _name('o'), _name('w'),
                         *node.args[1:])
        if name == 'byte':
            if not isinstance(original[0], ast.Name) or original[0].id != 's':
                raise ValueError('SHA byte-source role changed')
            return _call('query_hash_byte', _name('s'), _name('o'), _name('w'), node.args[1])
        if name == 'store':
            if not isinstance(original[0], ast.Name) or original[0].id != 'o':
                raise ValueError('SHA output role changed')
            return _call('query_hash_emit', _name('w'), *node.args[1:])
        if name == 'rotate':
            node.func.id = 'query_rotate'
        return node


def _sha_nodes():
    result = []
    for node in ast.parse(sha_source()).body:
        if node.name in {'get', 'put'}:
            continue
        original_name = node.name
        node = _QueryHash().visit(node)
        if original_name == 'sha256':
            node.name = 'query_sha256'
        elif original_name == 'padded_byte':
            node.name = 'query_padded_byte'
            node.args.args[1:1] = [ast.arg(arg='o', annotation=_name('mutbuf')),
                                  ast.arg(arg='w', annotation=_name('mutbuf'))]
        elif original_name == 'rotate':
            node.name = 'query_rotate'
        else:
            raise ValueError('unexpected SHA helper')
        result.append(node)
    return result


def _arena_helpers():
    wanted = {'kind', 'count', 'child', 'field', 'same', 'text_is'}
    nodes = [node for node in ast.parse(FRONTEND).body if node.name in wanted]
    if {node.name for node in nodes} != wanted:
        raise ValueError('Core arena helper definitions changed')
    # The frontend's sibling helper is supplied by its canonical renderer;
    # here the exact 56-byte arena next pointer is sufficient.
    nodes += ast.parse('''
def next_node(w:mutbuf, node:u64) -> u64:
    if node == 18446744073709551615:
        return 18446744073709551615
    return get(w, 64 + node * 56 + 16)

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value
''').body
    key = ['def key_id(w:mutbuf, node:u64) -> u64:',
           '    start = get(w, 64 + node * 56 + 40)',
           '    size = get(w, 64 + node * 56 + 48)']
    for index, name in enumerate(KEYS):
        key += ['    if same(w, start, size, ' + ', '.join(map(str, _packed(name))) + ') == 1:',
                '        return ' + str(1 << index)]
    key += ['    return 0']
    nodes += ast.parse('\n'.join(key)).body
    return nodes


def _static_pool(nodes):
    values = []
    for node in nodes:
        for item in ast.walk(node):
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name):
                if item.func.id == 'qtext':
                    value = item.args[1]
                elif item.func.id == 'qadd':
                    value = item.args[3]
                else:
                    continue
                if not isinstance(value, ast.Constant) or type(value.value) is not str:
                    raise ValueError('query literal is not authoring-time text')
                if value.value not in values:
                    values.append(value.value)
    position = 768
    result = {}
    for text in values:
        raw = text.encode('ascii')
        result[text] = (position, len(raw))
        position += len(raw)
    if position > 2048:
        raise ValueError('static query text overlaps the unchanged SHA scratch')
    return result


def _constant_initializer(pool):
    end = max((at + size for at, size in pool.values()), default=768)
    raw = bytearray(end - 768)
    for text, (at, size) in pool.items():
        raw[at - 768:at - 768 + size] = text.encode('ascii')
    lines = ['def initialize_query_constants(w:mutbuf) -> u64:']
    for index in range(0, len(raw) // 8 * 8, 8):
        lines.append('    put(w, get(w, 40) + ' + str(768 + index) + ', ' +
                     str(int.from_bytes(raw[index:index + 8], 'little')) + ')')
    for index in range(len(raw) // 8 * 8, len(raw)):
        lines.append('    store(w, get(w, 40) + ' + str(768 + index) + ', ' + str(raw[index]) + ')')
    lines.append('    return 0')
    return ast.parse('\n'.join(lines)).body


class _Expand(ast.NodeTransformer):
    def __init__(self, pool):
        self.pool = pool
        self.constants = {'K_' + value: 1 << index for index, value in enumerate(KEYS)}
        self.constants.update(NONE=(1 << 64) - 1,
                              QUERY_MAGIC=int.from_bytes(b'HIAPQ001', 'little'),
                              QUERY_RESULT_MAGIC=int.from_bytes(b'HIAPQR01', 'little'),
                              SLICE_MAGIC=int.from_bytes(b'HIASLC01', 'little'),
                              SLICE_RESULT_MAGIC=int.from_bytes(b'HIASLR01', 'little'))
        self.literals = {'L_' + name: _packed(value) for name, value in LITERALS.items()}

    def visit_Name(self, node):
        if node.id in self.constants:
            return ast.copy_location(_constant(self.constants[node.id]), node)
        return node

    def visit_Call(self, node):
        node = self.generic_visit(node)
        if not isinstance(node.func, ast.Name):
            raise ValueError('query authoring call must name a function')
        name, args = node.func.id, node.args
        expanded = []
        for arg in args:
            if isinstance(arg, ast.Name) and arg.id in self.literals:
                expanded.extend(_constant(value) for value in self.literals[arg.id])
            else:
                expanded.append(arg)
        node.args = args = expanded
        if name == 'qget':
            return node
        if name == 'qput':
            # Preserve address-before-value evaluation at the original put.
            return _call('put', args[0], _call('qaddress', args[0], args[1]), args[2])
        if name == 'qcontainer':
            return _call('q_new', args[0], args[1], _constant((1 << 64) - 1), _constant(0))
        if name in {'qinteger', 'qnull', 'qboolean'}:
            value = args[1] if name == 'qinteger' else _constant(0)
            tag = (_constant(7) if name == 'qinteger' else _constant(0) if name == 'qnull'
                   else _call('choose', args[1], _constant(2), _constant(1)))
            return _call('q_new', args[0], tag, value, _constant(0))
        if name == 'qdigest_text':
            at = _add(_add(_qstate(), _constant(512)), _multiply(args[1], _constant(64)))
            return _call('q_new', args[0], _constant(4), at, _constant(64))
        if name in {'qtext', 'qadd'}:
            literal = args[1] if name == 'qtext' else args[3]
            if not isinstance(literal, ast.Constant) or type(literal.value) is not str:
                raise ValueError('dynamic host text cannot enter native query literals')
            at, size = self.pool[literal.value]
            pointer = _add(_qstate(), _constant(at))
            if name == 'qtext':
                return _call('q_new', args[0], _constant(4), pointer, _constant(size))
            return _call('q_attach', *args[:3], pointer, _constant(size))
        if name == 'qappend':
            return _call('q_attach', *args, _constant(0), _constant(0))
        if name in {'graph_get', 'graph_put'}:
            return _call('get' if name == 'graph_get' else 'put',
                         args[0], _add(_qget(64), args[1]), *args[2:])
        if name in {'graph_block_node', 'graph_operation_node', 'graph_value_name'}:
            offset = {'graph_block_node': 80, 'graph_operation_node': 88, 'graph_value_name': 96}[name]
            return _call('get', args[0], _address(offset, args[1], 8))
        if name in {'result_block_flag', 'result_value_flag', 'result_op_flag'}:
            base = _add(_qget(136), _constant(64))
            if name != 'result_block_flag':
                count = _qget(160) if name == 'result_value_flag' else _add(_qget(160), _qget(176))
                base = _add(base, _multiply(count, _constant(8)))
            return _call('get', args[0], _add(base, _multiply(args[1], _constant(8))))
        if name in {'graph_block_set', 'graph_op_set', 'graph_value_set', 'graph_edge_set', 'graph_link_set'}:
            base = _add(_qget(64), _constant(64))
            widths = {'graph_block_set': 64, 'graph_op_set': 40, 'graph_value_set': 16,
                      'graph_edge_set': 32, 'graph_link_set': 8}
            preceding = {'graph_block_set': (), 'graph_op_set': ((160, 64),),
                         'graph_value_set': ((160, 64), (168, 40)),
                         'graph_edge_set': ((160, 64), (168, 40), (176, 16)),
                         'graph_link_set': ((160, 64), (168, 40), (176, 16), (184, 32))}
            for count, width in preceding[name]:
                base = _add(base, _multiply(_qget(count), _constant(width)))
            at = _add(base, _multiply(args[1], _constant(widths[name])))
            if name == 'graph_link_set':
                return _call('put', args[0], at, args[2])
            return _call('put', args[0], _add(at, _multiply(args[2], _constant(8))), args[3])
        return node


def _state_helpers():
    # Shared reads keep every original state load.  qaddress is evaluated
    # before the put value at the original call site; no value is hoisted.
    return ast.parse("""
def qget(w:mutbuf, offset:u64) -> u64:
    return get(w, get(w, 40) + offset)

def qaddress(w:mutbuf, offset:u64) -> u64:
    return get(w, 40) + offset
""").body


def _unroll_word_access(nodes):
    """Specialize only three exact eight-byte loops, preserving access order.

    Function boundaries and each byte access remain.  Counter arithmetic is
    private, ranges only over 0..8, and cannot wrap; each shift is still 8*i.
    No load/store is widened and no later byte is evaluated before an earlier
    byte has completed, including its original bounds refusal or partial write.
    """
    expected = ast.parse("""
def get(w:mutbuf, index:u64) -> u64:
    value = 0
    count = 0
    while count < 8:
        value = value | (byte(w, index + count) << (count * 8))
        count = count + 1
    return value

def put(w:mutbuf, index:u64, value:u64) -> u64:
    count = 0
    while count < 8:
        store(w, index + count, value >> (count * 8))
        count = count + 1
    return value

def uint(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value
""").body
    originals = {node.name: node for node in expected}
    counters = {'get': 'count', 'put': 'count', 'uint': 'index'}

    class ConstantIndex(ast.NodeTransformer):
        def __init__(self, counter, index):
            self.counter, self.index = counter, index

        def visit_Name(self, node):
            if node.id == self.counter:
                return ast.copy_location(ast.Constant(value=self.index), node)
            return node

        def visit_BinOp(self, node):
            if (isinstance(node.op, ast.Mult)
                    and isinstance(node.left, ast.Name)
                    and node.left.id == self.counter
                    and isinstance(node.right, ast.Constant)
                    and type(node.right.value) is int and node.right.value == 8):
                return ast.copy_location(ast.Constant(value=8 * self.index), node)
            return self.generic_visit(node)

    found = set()
    result = []
    for node in nodes:
        if node.name not in originals:
            result.append(node)
            continue
        if node.name in found or ast.dump(node) != ast.dump(originals[node.name]):
            raise ValueError(('eight-byte helper definition changed', node.name))
        found.add(node.name)
        counter = counters[node.name]
        loop = next(item for item in node.body if isinstance(item, ast.While))
        rewritten = copy.deepcopy(node)
        initial = [copy.deepcopy(item) for item in node.body[:node.body.index(loop)]
                   if not (isinstance(item, ast.Assign)
                           and len(item.targets) == 1
                           and isinstance(item.targets[0], ast.Name)
                           and item.targets[0].id == counter)]
        accesses = [ConstantIndex(counter, index).visit(copy.deepcopy(loop.body[0]))
                    for index in range(8)]
        rewritten.body = [*initial, *accesses, copy.deepcopy(node.body[-1])]
        result.append(rewritten)
    if found != set(originals):
        raise ValueError(('eight-byte helper missing', sorted(set(originals) - found)))
    return result


def source_program():
    original = ast.parse(ENTRY + SELECTION + GRAPH + TREE + ARENA + ASCII_WRITER).body
    pool = _static_pool(original)
    original += _constant_initializer(pool)
    original += _arena_helpers()
    original += _decoder_nodes()
    original += _slice_nodes()
    original += _sha_nodes()
    original += _state_helpers()
    names = [node.name for node in original]
    if len(names) != len(set(names)) or names[0] != 'prepare_query':
        raise ValueError('duplicate helper or wrong flat entry')
    original = _unroll_word_access(original)
    expanded = _Expand(pool).visit(ast.Module(body=original, type_ignores=[]))
    text = ast.unparse(ast.fix_missing_locations(expanded)) + '\n'
    parsed = ast.parse(text)
    for node in ast.walk(parsed):
        if isinstance(node, ast.Constant) and type(node.value) is str:
            raise ValueError('unlowered host string in native authoring source')
        if isinstance(node, ast.Name) and (
                node.id.startswith(('K_', 'L_')) or node.id == 'NONE'):
            raise ValueError('unlowered native static constant')
    declared = {node.name for node in parsed.body}
    builtins = {'length', 'byte', 'store', 'fill_range', 'choose'}
    for call in (node for node in ast.walk(parsed) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Name) or call.func.id not in declared | builtins:
            raise ValueError(('unresolved native call', ast.dump(call)))
    return text


def profile_inventory(document, assembly):
    """Inspect every logical argument position in the actual lowered CFG.

    This deliberately does not report a native image/relocation result.
    Those require the original real compiler and captured native receipt.
    """
    functions = document['functions']
    evidence = {'functions': len(functions), 'blocks': 0, 'operations': 0,
                'assembly_bytes': len(assembly.encode('utf-8')), 'per_function': [],
                'max_logical_call_arguments': 0, 'max_logical_edge_arguments': 0,
                'max_logical_block_parameters': 0, 'max_function_parameters': 0,
                'max_function_values': 0,
                'native_image_bytes': None, 'native_relocations': None,
                'native_compile_executed': False,
                'required_native_image_limit_bytes': 1048576,
                'required_native_relocation_limit': 12000}
    if not functions or functions[0]['name'] != 'f0':
        raise ValueError('wrong native entry identity')
    if [param['type'] for param in functions[0]['params']] != ['readbuf', 'mutbuf', 'mutbuf']:
        raise ValueError('entry escaped the existing flat 3-buffer ABI')
    if functions[0]['returns'] != ['u32']:
        raise ValueError('entry result ABI changed')
    for function in functions:
        values = {param['name'] for param in function['params']}
        blocks = function['blocks']
        item = {'name': function['name'], 'blocks': len(blocks), 'operations': 0,
                'parameters': len(function['params']), 'values': None,
                'max_block_parameters': 0, 'max_edge_arguments': 0,
                'max_call_arguments': 0}
        for block in blocks:
            values.update(param['name'] for param in block['params'])
            item['max_block_parameters'] = max(item['max_block_parameters'], len(block['params']))
            item['operations'] += len(block['ops'])
            for operation in block['ops']:
                values.update(out['name'] for out in operation['out'])
                if operation['op'] == 'call':
                    item['max_call_arguments'] = max(item['max_call_arguments'], len(operation['args']))
            term = block['term']
            edges = ([term] if term['op'] == 'jump' else
                     [term['then'], term['else']] if term['op'] == 'branch' else [])
            for edge in edges:
                item['max_edge_arguments'] = max(item['max_edge_arguments'], len(edge['args']))
            if term['op'] == 'ret' and len(term['values']) > 16:
                raise ValueError(('native return arity exceeded', function['name'], block['id']))
        item['values'] = len(values)
        evidence['per_function'].append(item)
        evidence['blocks'] += item['blocks']
        evidence['operations'] += item['operations']
        evidence['max_function_parameters'] = max(evidence['max_function_parameters'], item['parameters'])
        evidence['max_logical_block_parameters'] = max(evidence['max_logical_block_parameters'], item['max_block_parameters'])
        evidence['max_logical_edge_arguments'] = max(evidence['max_logical_edge_arguments'], item['max_edge_arguments'])
        evidence['max_logical_call_arguments'] = max(evidence['max_logical_call_arguments'], item['max_call_arguments'])
        evidence['max_function_values'] = max(evidence['max_function_values'], item['values'])
        if item['blocks'] > 256 or item['values'] > 2048:
            raise ValueError(('native function profile exceeded', item))
        if max(item['parameters'], item['max_block_parameters'],
               item['max_edge_arguments'], item['max_call_arguments']) > 16:
            raise ValueError(('native logical argument profile exceeded', item))
    if (evidence['functions'] > 128 or evidence['blocks'] > 1536
            or evidence['operations'] > 8192 or evidence['assembly_bytes'] > 1048576):
        raise ValueError(('native module profile exceeded', evidence))
    evidence['static_generated_profile_within_existing_limits'] = True
    evidence['status'] = 'GENERATED_STRUCTURE_ONLY_NOT_NATIVE_OR_COLD_QUALIFIED'
    return evidence


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name],
                          'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    result = compact_authoring_cfg(
        {'schema': 'hepta.hia.program.v8', 'module': 'agent_query', 'functions': functions})
    assembly = render_assembly(result)
    profile_inventory(result, assembly)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--authoring-source', type=Path)
    args = parser.parse_args()
    # This draft never chooses a repository destination or overwrites a file.
    targets = [args.output, args.inventory, *([args.authoring_source] if args.authoring_source else [])]
    if len({str(path.absolute()) for path in targets}) != len(targets) or any(path.exists() for path in targets):
        raise ValueError('draft generation requires distinct absent output paths')
    result = document()
    assembly = render_assembly(result)
    inventory = profile_inventory(result, assembly)
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(assembly)
    with args.inventory.open('x', encoding='utf-8') as stream:
        json.dump(inventory, stream, sort_keys=True, indent=2)
        stream.write('\n')
    if args.authoring_source:
        with args.authoring_source.open('x', encoding='utf-8') as stream:
            stream.write(source_program())


if __name__ == '__main__':
    main()
