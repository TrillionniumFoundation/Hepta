"""Pure HIA prefix for syntax objects issued by the complete assembly owner.

This consumes the owner's complete insertion-preserving integer JSON view.
It is not the public raw-JSON entry and grants no Core admission authority.
It performs the original object snapshot and structure gates before emitting
canonical bytes for the independently invoked complete primitive admission.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hashlib import sha256
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import DECODER_SOURCE
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE
from tools.generate_hia_json_canonical import SOURCE as CANONICAL_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

BAD = 0xfffffffd
NEED = 0xfffffffe
MAGIC = int.from_bytes(b"HIAOPE01", "little")
LIMIT = 8 << 20
MESSAGES = {
    1: "E_HIA_LIMIT: caller-owned tree exceeds snapshot budget",
    2: "E_HIA_LIMIT: caller-owned tree exceeds queued-node budget",
    3: "E_HIA_LIMIT: program exceeds structural budget",
    4: "E_HIA_LIMIT: program exceeds queued-node budget",
    5: "E_HIA_LIMIT: program exceeds byte budget before encoding",
}
BODY = r'''
def object_prefix(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128 or length(w) < 128:
        return BAD
    # The retained strict decoder packs an index into 32 bits. Complete
    # assembly is byte bounded before construction; this is private ABI.
    if length(s) == 0 or length(s) > 4294967295:
        return prefix_event(o, 3, 1, 0, 0, 0, 0, 0)
    if measure_transport(s, w) == 0:
        return prefix_event(o, 3, 2, 0, 0, 0, 0, 0)
    nodes = get(w, 64)
    depth = get(w, 72)
    required_work = 64 + nodes * 56 + length(s)
    if required_work < 128 + (depth + 1) * 32:
        required_work = 128 + (depth + 1) * 32
    required_output = length(s) + 128
    stack = 128 + (depth + 1) * 48
    if required_output < stack:
        required_output = stack
    bound = nodes
    if bound > (length(s) >> 2) + 1:
        bound = (length(s) >> 2) + 1
    slots = 2
    while slots < bound * 2:
        slots = slots * 2
    if required_output < slots * 8:
        required_output = slots * 8
    if length(w) < required_work or length(o) < required_output:
        return prefix_event(o, 1, 0, required_output, required_work, 0, nodes, depth)
    put(o, 48, nodes)
    put(o, 56, depth)
    decoded_result = widen(decode_json(s, w, o))
    if decoded_result >= 4294967292:
        return prefix_event(o, 3, 3, required_output, required_work, 0, decoded_result, 0)
    actual_nodes = get(w, 8)
    reason = object_snapshot_budget(w)
    if reason != 0:
        return prefix_event(o, 2, reason, required_output, required_work, 0, actual_nodes, depth)
    reason = object_structure_budget(s, w)
    if reason != 0:
        return prefix_event(o, 2, reason, required_output, required_work, 0, actual_nodes, depth)
    expected = get(w, 48)
    put(w, 56, 128)
    emitted = render_object(s, o, w)
    if emitted != 128 + expected or expected > LIMIT:
        return prefix_event(o, 3, 4, required_output, required_work, 0, actual_nodes, depth)
    return prefix_event(o, 0, 0, required_output, required_work, expected, actual_nodes, depth)

def prefix_event(o:mutbuf, action:u64, reason:u64, need_o:u64, need_w:u64, size:u64, nodes:u64, depth:u64) -> u32:
    put(o, 0, MAGIC)
    put(o, 8, 1)
    put(o, 16, action)
    put(o, 24, reason)
    put(o, 32, need_o)
    put(o, 40, need_w)
    put(o, 48, 128)
    put(o, 56, size)
    put(o, 64, nodes)
    put(o, 72, depth)
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

def measure_transport(s:readbuf, w:mutbuf) -> u64:
    index = 0
    nodes = 0
    depth = 0
    peak = 0
    while index < length(s):
        ch = byte(s, index)
        if ch == 34:
            nodes = nodes + 1
            index = index + 1
            done = False
            while index < length(s) and done == False:
                ch = byte(s, index)
                index = index + 1
                if ch == 92:
                    if index == length(s):
                        return 0
                    index = index + 1
                elif ch == 34:
                    done = True
            if done == False:
                return 0
        elif ch == 91 or ch == 123:
            nodes = nodes + 1
            depth = depth + 1
            if depth > peak:
                peak = depth
            index = index + 1
        elif ch == 93 or ch == 125:
            if depth == 0:
                return 0
            depth = depth - 1
            index = index + 1
        elif ch == 32 or ch == 9 or ch == 10 or ch == 13 or ch == 44 or ch == 58:
            index = index + 1
        else:
            nodes = nodes + 1
            moving = True
            while index < length(s) and moving:
                ch = byte(s, index)
                if ch == 32 or ch == 9 or ch == 10 or ch == 13 or ch == 44 or ch == 58 or ch == 91 or ch == 123 or ch == 93 or ch == 125 or ch == 34:
                    moving = False
                else:
                    index = index + 1
    if nodes == 0 or depth != 0:
        return 0
    put(w, 64, nodes)
    put(w, 72, peak)
    return 1

def object_snapshot_budget(w:mutbuf) -> u64:
    node = 0
    depth = 0
    count = 0
    queued = 1
    going = True
    while going:
        queued = queued - 1
        count = count + 1
        if count > 262144 or depth > 64:
            return 1
        record = 64 + node * 56
        kind = get(w, record)
        children = 0
        if kind == 5 or kind == 6:
            children = get(w, record + 32)
            if children > 262144 - count - queued:
                return 2
            queued = queued + children
        if children != 0:
            node = get(w, record + 24)
            depth = depth + 1
        else:
            moving = True
            while moving:
                if node == 0:
                    moving = False
                    going = False
                else:
                    record = 64 + node * 56
                    next = get(w, record + 16)
                    if next != 18446744073709551615:
                        node = next
                        moving = False
                    else:
                        node = get(w, record + 8)
                        depth = depth - 1
    return 0

def object_structure_budget(s:readbuf, w:mutbuf) -> u64:
    node = 0
    depth = 0
    count = 0
    queued = 1
    size = 0
    going = True
    while going:
        queued = queued - 1
        count = count + 1
        if count > 262144 or depth > 64:
            return 3
        record = 64 + node * 56
        kind = get(w, record)
        children = 0
        if kind == 5 or kind == 6:
            children = get(w, record + 32)
            if children > 262144 - count - queued:
                return 4
            queued = queued + children
            size = size + 2
            if children != 0:
                size = size + children - 1
            if kind == 6:
                size = size + children
                child = get(w, record + 24)
                while child != 18446744073709551615:
                    if size > LIMIT:
                        return 5
                    r = 64 + child * 56
                    width = object_string_size(w, get(w, r + 40), get(w, r + 48), LIMIT - size)
                    if width == 18446744073709551615:
                        return 5
                    size = size + width
                    child = get(w, r + 16)
        elif kind == 4:
            if size > LIMIT:
                return 5
            width = object_string_size(w, get(w, record + 24), get(w, record + 32), LIMIT - size)
            if width == 18446744073709551615:
                return 5
            size = size + width
        elif kind == 3:
            start = get(w, record + 24)
            width = get(w, record + 32)
            if width == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:
                width = 1
            size = size + width
        elif kind == 1:
            size = size + 5
        else:
            size = size + 4
        if size > LIMIT:
            return 5
        if children != 0:
            reverse_children(w, node)
            node = get(w, record + 24)
            depth = depth + 1
        else:
            moving = True
            while moving:
                if node == 0:
                    moving = False
                    going = False
                else:
                    next = get(w, 64 + node * 56 + 16)
                    if next != 18446744073709551615:
                        node = next
                        moving = False
                    else:
                        node = get(w, 64 + node * 56 + 8)
                        reverse_children(w, node)
                        depth = depth - 1
    put(w, 48, size)
    return 0

def object_string_size(w:mutbuf, start:u64, bytes:u64, remaining:u64) -> u64:
    index = 0
    characters = 0
    while index < bytes:
        if (byte(w, start + index) & 192) != 128:
            characters = characters + 1
        index = index + 1
    if characters + 2 > remaining:
        return 18446744073709551615
    size = 2
    index = 0
    while index < bytes:
        ch = byte(w, start + index)
        width = 1
        if ch < 32:
            width = 6
            if ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
                width = 2
        elif ch == 34 or ch == 92:
            width = 2
        size = size + width
        if size > remaining:
            return 18446744073709551615
        index = index + 1
    return size

def reverse_children(w:mutbuf, node:u64) -> u64:
    record = 64 + node * 56
    previous = 18446744073709551615
    child = get(w, record + 24)
    while child != 18446744073709551615:
        at = 64 + child * 56 + 16
        following = get(w, at)
        put(w, at, previous)
        previous = child
        child = following
    put(w, record + 24, previous)
    return 0
'''

def replace_once(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)

def source_program():
    # These changes concern only this private issued-object transport. Original
    # raw/program/strict JSON sources and their public limits stay byte exact.
    preflight = replace_once(PREFLIGHT_SOURCE,
        "if length(s) > 8388608 or length(w) < 128:",
        "if length(s) > 4294967295 or length(w) < 128:")
    preflight = replace_once(preflight,
        "if maximum < 1 or maximum > 1048576 or maximum_depth > 128:",
        "if maximum < 1 or maximum > length(s) or maximum_depth > length(s):")
    preflight = replace_once(preflight,
        "            if index == length(s):\n                return 0",
        "            if index == length(s):\n                put(w, 64, nodes)\n                return 0")
    decoder = replace_once(DECODER_SOURCE,
        "if length(s) > 8388608 or length(w) < 128 or length(o) < 128:",
        "if length(s) > 4294967295 or length(w) < 128 or length(o) < 128:")
    decoder = replace_once(decoder,
        "if maximum < 1 or maximum > 1048576 or maximum_depth > 128:",
        "if maximum < 1 or maximum > length(s) or maximum_depth > length(s):")
    canonical = ast.parse(CANONICAL_SOURCE)
    render = canonical.body[0]
    render.name = "render_object"
    render.returns.id = "u64"
    start = next(i for i, n in enumerate(render.body)
                 if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                 and n.targets[0].id == "node")
    render.body = render.body[start:]
    canonical_source = ast.unparse(ast.fix_missing_locations(canonical)) + "\n"
    constants = {"BAD":BAD, "NEED":NEED, "MAGIC":MAGIC, "LIMIT":LIMIT}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node
    tree = ast.fix_missing_locations(Expand().visit(ast.parse(
        BODY + "\n" + canonical_source + "\n" + decoder + "\n" + preflight)))
    # Exact word accesses unrolled to retain the proven byte order without
    # eight-iteration loops at every protocol/arena word.
    for fn in tree.body:
        if fn.name == "get":
            fn.body = ast.parse("return " + " | ".join(
                "(byte(w, index + %d) << %d)" % (i,8*i) for i in range(8))).body
        elif fn.name == "put":
            fn.body = ast.parse("\n".join(
                "store(w, index + %d, (value >> %d) & 255)" % (i,8*i)
                for i in range(8)) + "\nreturn 0").body
    names = [n.name for n in tree.body]
    assert len(names) == len(set(names))
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"

def document():
    nodes = ast.parse(source_program()).body
    names = {n.name:"f"+str(i) for i,n in enumerate(nodes)}
    signatures = {n.name:([a.annotation.id for a in n.args.args],n.returns.id)
                  for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name":names[node.name],
            "params":[builder.param(v) for v in builder.params],
            "returns":[builder.returns], "effects":["read","write","trap"],
            "entry":"b0", "blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"assembly_object_prefix", "functions":functions})

if __name__ == "__main__":
    destination = Path(__file__).resolve().parents[1]/"assembly_object_prefix.hiaasm"
    destination.write_text(render_assembly(document()))
    print(destination)
