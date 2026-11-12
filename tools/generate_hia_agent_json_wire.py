"""HIA Agent JSON arena-to-wire owner with native binary64 conversion/printing.

The entry consumes the actual private HIADATA1 arena and original raw spans.
No foreign JSON parser, float conversion, string encoder or wire reconstruction
runs in this image. The original Agent-data admission/UTF8/preflight/int-parse
boundary remains separate. Python object graphs and numeric object keys are
outside this private decoded-JSON arena ABI.
"""
from __future__ import annotations
import argparse
import ast
import copy
from hashlib import sha256
import json
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_binary64 import source_program as decimal_source
from tools.generate_hia_agent_binary64_format import source_program as format_source
from tools.generate_hia_json_canonical import SOURCE as canonical_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

ARENA_MAGIC = int.from_bytes(b"HIADATA1", "little")
REQUEST_MAGIC = int.from_bytes(b"HIAJWRQ1", "little")
PRIVATE_BYTES = 16384
MAX_BYTES = 8388608
MAX_NODES = 262144
NUMERIC_AUDIT = {}

SOURCE = r'''
def agent_json_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 8388608 or length(o) < 8388608 or length(w) < 16504:
        return 4294967293
    private = length(w) - 16384
    if get(w, private + 16000) != @REQUEST_MAGIC@ or get(w, private + 16008) != 1:
        return 4294967293
    if get(w, private + 16016) != 8388608 or get(w, private + 16032) != 0 or get(w, private + 16040) != 0:
        return 4294967293
    put(w, private + 16048, 0)
    put(w, private + 16056, 18446744073709551615)
    status = arena(s, w)
    if status != 0:
        put(w, private + 16048, status)
        return status
    count = get(w, 8)
    bits = get(w, 24)
    index = 0
    while index < count:
        record = 64 + index * 56
        put(w, bits + index * 8, 0)
        if get(w, record) == 7:
            put(w, private + 12304, get(w, record + 24))
            put(w, private + 12312, get(w, record + 32))
            result = widen(num_convert(s, o, w))
            if result != 8:
                status = choose(result == 4294967292, 4294967291, 4294967292)
                put(w, private + 16048, status)
                put(w, private + 16056, index)
                return status
            put(w, bits + index * 8, get(w, private + 12288))
        index = index + 1
    # Structural admission and numeric conversion finish before sorted output.
    index = 0
    while index < count:
        record = 64 + index * 56
        if get(w, record) == 6:
            sort_object(w, index)
            current = get(w, record + 24)
            previous = 18446744073709551615
            while current != 18446744073709551615:
                if previous != 18446744073709551615:
                    if same_key(w, previous, current) != 0:
                        put(w, private + 16048, 4294967292)
                        return 4294967292
                previous = current
                current = next_node(w, current)
        index = index + 1
    put(w, 56, 0)
    node = 0
    going = True
    visits = 0
    while going:
        visits = visits + 1
        if visits > count:
            return 4294967292
        record = 64 + node * 56
        kind = get(w, record)
        parent = get(w, record + 8)
        if parent != 18446744073709551615:
            if get(w, 64 + parent * 56) == 6:
                append_string(o, w, get(w, record + 40), get(w, record + 48))
                append_byte(o, w, 58)
        complete = True
        if kind == 5 or kind == 6:
            append_byte(o, w, choose(kind == 5, 91, 123))
            if get(w, record + 32) == 0:
                append_byte(o, w, choose(kind == 5, 93, 125))
            else:
                node = get(w, record + 24)
                complete = False
        elif kind == 4:
            append_string(o, w, get(w, record + 24), get(w, record + 32))
        elif kind == 7:
            put(w, private + 12288, get(w, bits + node * 8))
            result = widen(num_render_binary64(s, o, w))
            if result == 0 or result > 32:
                put(w, private + 16048, 4294967292)
                put(w, private + 16056, node)
                return 4294967292
            index = 0
            while index < result:
                append_byte(o, w, byte(w, private + 12320 + index))
                index = index + 1
        elif kind == 3:
            start = get(w, record + 24)
            size = get(w, record + 32)
            digits = size
            if byte(s, start) == 45:
                digits = digits - 1
            limit = get(w, private + 16024)
            if limit != 0 and digits > limit:
                put(w, private + 16048, 4294967290)
                put(w, private + 16056, node)
                return 4294967290
            if size == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:
                append_byte(o, w, 48)
            else:
                index = 0
                while index < size:
                    append_byte(o, w, byte(s, start + index))
                    index = index + 1
        else:
            literal = 1819047278
            size = 4
            if kind == 1:
                literal = 435728179558
                size = 5
            if kind == 2:
                literal = 1702195828
            index = 0
            while index < size:
                append_byte(o, w, literal & 255)
                literal = literal >> 8
                index = index + 1
        if get(w, private + 16048) != 0:
            return get(w, private + 16048)
        if complete:
            moving = True
            while moving:
                record = 64 + node * 56
                sibling = get(w, record + 16)
                if sibling != 18446744073709551615:
                    append_byte(o, w, 44)
                    node = sibling
                    moving = False
                else:
                    parent = get(w, record + 8)
                    if parent == 18446744073709551615:
                        going = False
                        moving = False
                    else:
                        node = parent
                        append_byte(o, w, choose(get(w, 64 + node * 56) == 5, 93, 125))
        if get(w, private + 16048) != 0:
            return get(w, private + 16048)
    if visits != count:
        return 4294967292
    return get(w, 56)

def arena(s:readbuf, w:mutbuf) -> u64:
    count = get(w, 8)
    used = get(w, 24)
    private = length(w) - 16384
    if get(w, 0) != @ARENA_MAGIC@ or count == 0 or count > 262144:
        return 4294967292
    strings = 64 + count * 56
    if get(w, 16) != strings or used < strings or used > private:
        return 4294967292
    if used - strings > length(s) or count * 8 > private - used:
        return 4294967292
    if get(w, 32) != used or get(w, 40) != length(s) or get(w, 48) != 1 or get(w, 56) != 0:
        return 4294967292
    index = 0
    children = 0
    while index < count:
        record = 64 + index * 56
        kind = get(w, record)
        parent = get(w, record + 8)
        sibling = get(w, record + 16)
        start = get(w, record + 24)
        size = get(w, record + 32)
        key = get(w, record + 40)
        key_size = get(w, record + 48)
        if kind > 7:
            return 4294967292
        if index == 0:
            if parent != 18446744073709551615 or sibling != 18446744073709551615 or key != 0 or key_size != 0:
                return 4294967292
        else:
            if parent >= index:
                return 4294967292
            parent_kind = get(w, 64 + parent * 56)
            if parent_kind != 5 and parent_kind != 6:
                return 4294967292
            if sibling != 18446744073709551615:
                if sibling <= index or sibling >= count:
                    return 4294967292
                if get(w, 64 + sibling * 56 + 8) != parent:
                    return 4294967292
            if parent_kind == 6:
                if string_span(w, key, key_size, strings, used) == 0:
                    return 4294967292
            else:
                if key != 0 or key_size != 0:
                    return 4294967292
        depth = 0
        ancestor = parent
        while ancestor != 18446744073709551615:
            depth = depth + 1
            if depth > 128:
                return 4294967288
            ancestor = get(w, 64 + ancestor * 56 + 8)
        if kind == 5 or kind == 6:
            if size > count:
                return 4294967292
            if size == 0:
                if start != 18446744073709551615:
                    return 4294967292
            else:
                current = start
                previous = index
                observed = 0
                while current != 18446744073709551615:
                    if current <= previous or current >= count:
                        return 4294967292
                    child_record = 64 + current * 56
                    if get(w, child_record + 8) != index:
                        return 4294967292
                    previous = current
                    current = get(w, child_record + 16)
                    observed = observed + 1
                    if observed > size:
                        return 4294967292
                if observed != size:
                    return 4294967292
                children = children + observed
        elif kind == 4:
            if string_span(w, start, size, strings, used) == 0:
                return 4294967292
        else:
            if start > length(s) or size == 0 or size > length(s) - start:
                return 4294967292
            if kind == 3:
                if integer_span(s, start, size) == 0:
                    return 4294967292
            elif kind == 7:
                marker = False
                cursor = 0
                while cursor < size:
                    value = byte(s, start + cursor)
                    if value == 46 or value == 69 or value == 101:
                        marker = True
                    cursor = cursor + 1
                if marker == False:
                    return 4294967292
            else:
                literal = 1819047278
                wanted = 4
                if kind == 1:
                    literal = 435728179558
                    wanted = 5
                if kind == 2:
                    literal = 1702195828
                if size != wanted:
                    return 4294967292
                cursor = 0
                while cursor < wanted:
                    if byte(s, start + cursor) != (literal & 255):
                        return 4294967292
                    literal = literal >> 8
                    cursor = cursor + 1
        index = index + 1
    if children != count - 1:
        return 4294967292
    return 0

def integer_span(s:readbuf, start:u64, size:u64) -> u64:
    index = 0
    if byte(s, start) == 45:
        index = 1
    if index >= size:
        return 0
    value = byte(s, start + index)
    if value == 48:
        return choose(index + 1 == size, 1, 0)
    if value < 49 or value > 57:
        return 0
    index = index + 1
    while index < size:
        value = byte(s, start + index)
        if value < 48 or value > 57:
            return 0
        index = index + 1
    return 1

def string_span(w:mutbuf, start:u64, size:u64, strings:u64, used:u64) -> u64:
    if start < strings or start > used or size > used - start:
        return 0
    index = 0
    encoded = 2
    while index < size:
        value = byte(w, start + index)
        width = 1
        if value < 128:
            if value < 32:
                width = 6
                if value == 8 or value == 9 or value == 10 or value == 12 or value == 13:
                    width = 2
            elif value == 34 or value == 92:
                width = 2
            index = index + 1
        else:
            count = 0
            point = 0
            minimum = 0
            if value >= 194 and value <= 223:
                count = 2
                point = value & 31
                minimum = 128
            elif value >= 224 and value <= 239:
                count = 3
                point = value & 15
                minimum = 2048
            elif value >= 240 and value <= 244:
                count = 4
                point = value & 7
                minimum = 65536
            else:
                return 0
            if count > size - index:
                return 0
            offset = 1
            while offset < count:
                next = byte(w, start + index + offset)
                if next < 128 or next > 191:
                    return 0
                point = (point << 6) | (next & 63)
                offset = offset + 1
            if point < minimum or point > 1114111 or (point >= 55296 and point <= 57343):
                return 0
            width = count
            index = index + count
        encoded = encoded + width
        if encoded > 8388608:
            return 0
    return 1

def same_key(w:mutbuf, a:u64, b:u64) -> u64:
    ra = 64 + a * 56
    rb = 64 + b * 56
    size = get(w, ra + 48)
    if size != get(w, rb + 48):
        return 0
    aa = get(w, ra + 40)
    bb = get(w, rb + 40)
    index = 0
    while index < size:
        if byte(w, aa + index) != byte(w, bb + index):
            return 0
        index = index + 1
    return 1

def append_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    index = get(w, 56)
    if index >= 8388608:
        put(w, length(w) - 16384 + 16048, 4294967289)
        return 1
    store(o, index, value)
    put(w, 56, index + 1)
    return 0

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value & 255)
        value = value >> 8
        index = index + 1
    return 0

def widen(value:u64) -> u64:
    return value
'''

def _dump(node):
    return ast.dump(node, include_attributes=False)

def _call(name, *args):
    return ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=list(args), keywords=[])

def _name(value):
    return ast.Name(id=value, ctx=ast.Load())

def _constant(value):
    return ast.Constant(value=value)

def _add(a, b):
    return ast.BinOp(left=a, op=ast.Add(), right=b)

def numeric_nodes():
    """Rebase only numeric buffer IO and entry transport; arithmetic is retained."""
    decimal = ast.parse(decimal_source()).body
    formatting = ast.parse(format_source()).body
    original = {}
    shared = []
    for node in decimal + formatting:
        if not isinstance(node, ast.FunctionDef):
            raise ValueError("numeric source must contain only functions")
        if node.name in original:
            if _dump(original[node.name]) != _dump(node):
                raise ValueError("shared numeric helper differs: " + node.name)
            shared.append(node.name)
        else:
            original[node.name] = node
    names = set(original)
    rows = []
    class Rebase(ast.NodeTransformer):
        owner = None
        def visit_FunctionDef(self, node):
            old = self.owner
            self.owner = node.name
            node = self.generic_visit(node)
            node.name = "num_" + node.name
            self.owner = old
            return node
        def visit_Call(self, node):
            before = copy.deepcopy(node)
            node = self.generic_visit(node)
            name = node.func.id if isinstance(node.func, ast.Name) else None
            first = node.args[0].id if node.args and isinstance(node.args[0], ast.Name) else None
            reason = None
            if name == "length" and first == "w":
                node = _constant(PRIVATE_BYTES)
                reason = "original numeric workspace extent"
            elif name == "length" and first == "s" and self.owner == "convert":
                node = _call("num_get", _name("w"), _constant(12312))
                reason = "actual raw numeric span length"
            elif name == "length" and first == "s" and self.owner == "render_binary64":
                node = _constant(8)
                reason = "native produced binary64 input width"
            elif name == "length" and first == "o" and self.owner in {"convert", "render_binary64"}:
                node = _constant(8 if self.owner == "convert" else 32)
                reason = "private output window exact capacity"
            elif name == "read64" and first == "s" and self.owner == "render_binary64":
                if len(node.args) != 2 or _dump(node.args[1]) != _dump(_constant(0)):
                    raise ValueError("formatter bits read changed")
                node = _call("num_get", _name("w"), _constant(12288))
                reason = "native produced binary64 bits"
            elif name in {"byte", "store"} and first == "w":
                node.args[1] = _add(ast.BinOp(left=_call("length", _name("w")),
                                              op=ast.Sub(), right=_constant(PRIVATE_BYTES)), node.args[1])
                reason = "private workspace byte address"
            elif name == "byte" and first == "s" and self.owner == "convert":
                node.args[1] = _add(_call("num_get", _name("w"), _constant(12304)), node.args[1])
                reason = "actual original raw numeric span address"
            elif name == "put" and first == "o" and self.owner == "convert":
                if len(node.args) != 3 or _dump(node.args[1]) != _dump(_constant(0)):
                    raise ValueError("converter bits publication changed")
                node.args[0] = _name("w")
                node.args[1] = _constant(12288)
                reason = "private native bits output"
            elif name == "store" and first == "o" and self.owner == "render_binary64":
                node.args[0] = _name("w")
                node.args[1] = _add(ast.BinOp(left=_call("length", _name("w")),
                                              op=ast.Sub(), right=_constant(PRIVATE_BYTES)),
                                    _add(_constant(12320), node.args[1]))
                reason = "private native formatted byte output"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in names:
                node.func.id = "num_" + node.func.id
            if reason:
                node._numeric_original_call = before
                rows.append({"function": self.owner, "reason": reason,
                             "before": ast.unparse(before), "after": ast.unparse(ast.fix_missing_locations(copy.deepcopy(node)))})
            return node
    changed = Rebase().visit(copy.deepcopy(ast.Module(body=list(original.values()), type_ignores=[])))
    class Inverse(ast.NodeTransformer):
        def visit(self, node):
            if hasattr(node, "_numeric_original_call"):
                return copy.deepcopy(node._numeric_original_call)
            return super().visit(node)
        def visit_FunctionDef(self, node):
            node = self.generic_visit(node)
            if not node.name.startswith("num_"):
                raise ValueError("numeric function namespace differs")
            node.name = node.name[4:]
            return node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id.startswith("num_"):
                node.func.id = node.func.id[4:]
            return node
    restored = Inverse().visit(copy.deepcopy(changed))
    if _dump(restored) != _dump(ast.Module(body=list(original.values()), type_ignores=[])):
        raise ValueError("numeric arithmetic/control AST changed outside mechanical IO rebasing")
    if not rows or set(shared) != {"multiply", "bits", "copy_big", "normalize", "shift", "compare_big", "subtract", "get", "put"}:
        raise ValueError("numeric source inventory differs")
    global NUMERIC_AUDIT
    NUMERIC_AUDIT = {
        "decimal_source_sha256": sha256(decimal_source().encode()).hexdigest(),
        "format_source_sha256": sha256(format_source().encode()).hexdigest(),
        "numeric_functions": len(original), "shared_functions": sorted(shared),
        "inverse_AST_equal": True, "rebasing": rows,
        "native_execution": False,
        "proof_scope": "mechanical source custody only; native composition qualification remains separate",
    }
    return changed.body

def source_nodes():
    text = SOURCE.replace("@REQUEST_MAGIC@", str(REQUEST_MAGIC)).replace("@ARENA_MAGIC@", str(ARENA_MAGIC))
    nodes = ast.parse(text).body
    canonical = ast.parse(canonical_source).body
    wanted = {"hex_digit", "append_string", "next_node", "key_less", "sort_object"}
    helpers = [copy.deepcopy(node) for node in canonical if node.name in wanted]
    if {node.name for node in helpers} != wanted:
        raise ValueError("canonical helper inventory differs")
    nodes.extend(helpers)
    nodes.extend(numeric_nodes())
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError("function namespace collision")
    return ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])).body

def source_program():
    return ast.unparse(ast.Module(body=source_nodes(), type_ignores=[])) + "\n"

def document():
    nodes = source_nodes()
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([argument.annotation.id for argument in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(value) for value in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "agent_json_wire",
                                  "functions": functions})

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inventory", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output or root / "examples/hia_bootstrap/agent_json_wire.hepta"
    model = document()
    raw = render_assembly(model).encode("utf-8")
    output.write_bytes(raw)
    if args.inventory:
        inventory = {"schema": "hepta.hia.agent-json-wire-source.v1",
            "status": "GENERATED_SOURCE_NOT_NATIVE_OR_COLD_QUALIFIED",
            "assembly_bytes": len(raw), "assembly_sha256": sha256(raw).hexdigest(),
            "functions": len(model["functions"]),
            "blocks": sum(len(fn["blocks"]) for fn in model["functions"]),
            "instructions": sum(len(block["ops"]) for fn in model["functions"] for block in fn["blocks"]),
            "numeric_algorithm_rebasing": NUMERIC_AUDIT,
            "native_compile_executed": False, "ordinary_provider_selected": False,
            "whole_stack_rewritten_in_hia": False}
        args.inventory.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    print(output.name, len(raw))

if __name__ == "__main__":
    main()
