"""Native ordinary patch preparation after actual base and request admission.

This pure kernel owns the complete _prepare_program_patch transformation and
its ordered edit diagnostics. It returns an insertion-preserving unadmitted
candidate. The caller must subsequently perform the original object snapshot,
whole Core verification and interface policy, then issue its actual receipt.
This development author never runs in a production patch request.
"""
from __future__ import annotations
import ast
import copy
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed, source_program as frontend_source
from tools.generate_hia_core_patch import BODY as PATCH_BODY, KEYS, LITERALS
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

BAD=0xfffffffd
NEED=0xfffffffe
NIL=0xffffffffffffffff
MAGIC=int.from_bytes(b"HIAPPE01","little")
SCRATCH=8192
MESSAGES={
 1:"E_HIA_EDIT: patch must be a structured request",
 2:"E_HIA_EDIT: patch requires exactly its declared fields; unknown or missing fields",
 3:"E_HIA_EDIT: v2 interface_policy must be preserve or migrate",
 4:"E_HIA_EDIT: unsupported patch schema",
 5:"E_HIA_EDIT: invalid expected snapshot digest",
 6:"E_HIA_EDIT: stale base snapshot",
 7:"E_HIA_EDIT: patch needs 1..64 edits",
 8:"E_HIA_EDIT: edit needs an action",
 9:"E_HIA_EDIT: function edit requires exactly its declared fields; unknown or missing fields",
 10:"E_HIA_EDIT: operation edit requires exactly its declared fields; unknown or missing fields",
 11:"E_HIA_EDIT: terminator edit requires exactly its declared fields; unknown or missing fields",
 12:"E_HIA_EDIT: unknown edit action",
 13:"E_HIA_EDIT: function identity must be a string",
 14:"E_HIA_EDIT: added function already exists",
 15:"E_HIA_EDIT: function not found",
 16:"E_HIA_EDIT: function edit must retain its declared identity",
 17:"E_HIA_EDIT: overlapping whole-function and local edits",
 18:"E_HIA_EDIT: block identity must be a string",
 19:"E_HIA_EDIT: block not found",
 20:"E_HIA_EDIT: invalid operation index",
 21:"E_HIA_EDIT: duplicate operation edit",
 22:"E_HIA_EDIT: duplicate terminator edit",
}
BODY=r'''
def prepare_patch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128 or length(w) < 128:
        return BAD
    if length(s) < 5 or length(s) > 16777219:
        return prepare_event(o, 3, 1, 0, 0, 0, 0, 0, 0, 0)
    if measure_transport(s, w) == 0:
        return prepare_event(o, 3, 2, 0, 0, 0, 0, 0, 0, 0)
    nodes = get(w, 64)
    depth = get(w, 72)
    need_w = 64 + nodes * 56 + length(s) + SCRATCH + 8
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
        return prepare_event(o, 1, 0, need_o, need_w, 0, 0, 0, 0, 0)
    put(o, 48, nodes)
    put(o, 56, depth)
    decoded = widen(decode_json(s, w, o))
    if decoded >= 4294967292:
        return prepare_event(o, 3, 3, need_o, need_w, 0, 0, 0, 0, 0)
    if kind(w, 0) != 5 or count(w, 0) != 2:
        return prepare_event(o, 3, 4, need_o, need_w, 0, 0, 0, 0, 0)
    base = child(w, 0)
    request = next_node(w, base)
    functions = field(w, base, K_functions)
    if kind(w, base) != 6 or kind(w, functions) != 5:
        return prepare_event(o, 3, 5, need_o, need_w, 0, 0, 0, 0, 0)
    scratch = (get(w, 32) + 7) & 18446744073709551608
    if scratch > length(w) or length(w) - scratch < SCRATCH:
        return prepare_event(o, 3, 6, need_o, need_w, 0, 0, 0, 0, 0)
    put(w, 40, scratch)
    put(w, scratch + 1200, base)
    put(w, scratch + 1208, request)
    put(w, scratch + 1216, 0)
    put(w, scratch + 1224, 0)
    put(w, scratch + 1232, NIL)
    put(w, scratch + 1240, 0)
    put(w, scratch + 1248, functions)
    reason = request_prefix(s, o, w, request, base)
    if get(w, 48) != 0:
        return prepare_event(o, 3, 7, need_o, need_w, 0, 0, 0, 0, 0)
    schema = get(w, scratch + 1216)
    policy = get(w, scratch + 1224)
    edits = get(w, scratch + 1232)
    total = count(w, edits)
    if reason != 0:
        return prepare_event(o, 2, reason, need_o, need_w, 0, schema, policy, total, 0)
    edit = child(w, edits)
    applied = 0
    while edit != NIL:
        reason = prepare_one(s, w, functions, edit, applied)
        if reason != 0:
            return prepare_event(o, 2, reason, need_o, need_w, 0, schema, policy, total, applied)
        remember_edit(w, applied)
        applied = applied + 1
        edit = next_node(w, edit)
    put(w, 48, 0)
    put(w, 56, 128)
    render_insertion_fragment(s, o, w, base)
    size = get(w, 56)
    if size > 4294967295:
        return prepare_event(o, 3, 8, need_o, need_w, 0, schema, policy, total, applied)
    if size > length(o):
        return prepare_event(o, 1, 0, size, need_w, 0, schema, policy, total, applied)
    if get(w, 48) != 0 or applied != total:
        return prepare_event(o, 3, 9, need_o, need_w, 0, schema, policy, total, applied)
    return prepare_event(o, 0, 0, need_o, need_w, size - 128, schema, policy, total, applied)

def prepare_event(o:mutbuf, action:u64, reason:u64, need_o:u64, need_w:u64, size:u64, schema:u64, policy:u64, total:u64, applied:u64) -> u32:
    if action == 2:
        message_size = diagnostic_size(reason)
        if message_size == 0:
            return BAD
        if length(o) < 128 + message_size:
            if need_o < 128 + message_size:
                need_o = 128 + message_size
            action = 1
            reason = 0
            size = 0
        else:
            size = diagnostic_bytes(o, reason)
            if size != message_size:
                return BAD
    put(o, 0, MAGIC)
    put(o, 8, 1)
    put(o, 16, action)
    put(o, 24, reason)
    put(o, 32, need_o)
    put(o, 40, need_w)
    put(o, 48, 128)
    put(o, 56, size)
    put(o, 64, schema)
    put(o, 72, policy)
    put(o, 80, total)
    put(o, 88, applied)
    put(o, 96, 0)
    put(o, 104, 0)
    put(o, 112, 0)
    put(o, 120, 0)
    if action == 1:
        return NEED
    if action == 3:
        return BAD
    return 128

def request_prefix(s:readbuf, o:mutbuf, w:mutbuf, request:u64, base:u64) -> u64:
    put(w, 48, 0)
    scratch = get(w, 40)
    if kind(w, request) != 6:
        return 1
    schema = field(w, request, K_schema)
    if text_is(w, schema, L_patch_v1) != 0:
        put(w, scratch + 1216, 1)
        if shape(w, request, K_schema | K_expected_sha256 | K_edits) == 0:
            return 2
    elif text_is(w, schema, L_patch_v2) != 0:
        put(w, scratch + 1216, 2)
        if shape(w, request, K_schema | K_expected_sha256 | K_interface_policy | K_edits) == 0:
            return 2
        selected = field(w, request, K_interface_policy)
        if text_is(w, selected, L_migrate) != 0:
            put(w, scratch + 1224, 1)
        elif text_is(w, selected, L_preserve) == 0:
            return 3
    else:
        return 4
    expected = field(w, request, K_expected_sha256)
    if kind(w, expected) != 4 or count(w, expected) != 64:
        return 5
    # Validate the entire spelling before any stale digest comparison.
    offset = get(w, 64 + expected * 56 + 24)
    i = 0
    while i < 64:
        if lower_nibble(byte(w, offset + i)) > 15:
            return 5
        i = i + 1
    put(w, 56, 32)
    render_fragment(s, o, w, base)
    if get(w, 48) != 0:
        return 0
    if digest_fragment(o, w, get(w, 56) - 32) != 32:
        put(w, 48, BAD)
        return 0
    i = 0
    while i < 32:
        a = lower_nibble(byte(w, offset + i * 2))
        b = lower_nibble(byte(w, offset + i * 2 + 1))
        if byte(w, scratch + 1088 + i) != ((a << 4) | b):
            return 6
        i = i + 1
    edits = field(w, request, K_edits)
    put(w, scratch + 1232, edits)
    if kind(w, edits) != 5 or count(w, edits) < 1 or count(w, edits) > 64:
        return 7
    return 0

def prepare_one(s:readbuf, w:mutbuf, functions:u64, edit:u64, applied:u64) -> u64:
    tag = field(w, edit, K_action)
    if kind(w, edit) != 6 or kind(w, tag) != 4:
        return 8
    action = 0
    if text_is(w, tag, L_replace_function) != 0:
        action = 1
    elif text_is(w, tag, L_add_function) != 0:
        action = 2
    elif text_is(w, tag, L_replace_operation) != 0:
        action = 3
    elif text_is(w, tag, L_replace_terminator) != 0:
        action = 4
    else:
        return 12
    fields = K_action | K_function
    if action <= 2:
        if shape(w, edit, fields | K_definition) == 0:
            return 9
    elif action == 3:
        if shape(w, edit, fields | K_block | K_index | K_operation) == 0:
            return 10
    else:
        if shape(w, edit, fields | K_block | K_term) == 0:
            return 11
    name = field(w, edit, K_function)
    if kind(w, name) != 4:
        return 13
    fn = named(w, functions, K_name, name)
    if action == 2:
        if fn != NIL:
            return 14
    elif fn == NIL:
        return 15
    scratch = get(w, 40)
    put(w, scratch + 1280, action)
    put(w, scratch + 1288, fn)
    put(w, scratch + 1296, name)
    put(w, scratch + 1304, NIL)
    put(w, scratch + 1312, NIL)
    put(w, scratch + 1320, NIL)
    if action <= 2:
        definition = field(w, edit, K_definition)
        if kind(w, definition) != 6 or same_text(w, field(w, definition, K_name), name) == 0:
            return 16
        if whole_overlap(w, applied, name, 1) != 0:
            return 17
        if action == 2:
            append_node(w, functions, definition)
        else:
            replace_node(w, functions, fn, definition)
        return 0
    # The original replaced set is checked before even reading the block name.
    if whole_overlap(w, applied, name, 0) != 0:
        return 17
    block_name = field(w, edit, K_block)
    if kind(w, block_name) != 4:
        return 18
    block = named(w, field(w, fn, K_blocks), K_id, block_name)
    if block == NIL:
        return 19
    put(w, scratch + 1304, block)
    put(w, scratch + 1312, block_name)
    if action == 3:
        index = exact_index(s, w, field(w, edit, K_index))
        operations = field(w, block, K_ops)
        if kind(w, operations) != 5 or index >= count(w, operations):
            return 20
        put(w, scratch + 1320, index)
        if duplicate_local(w, applied, name, block_name, index, action) != 0:
            return 21
        target = child(w, operations)
        position = 0
        while position < index:
            target = next_node(w, target)
            position = position + 1
        replace_node(w, operations, target, field(w, edit, K_operation))
    else:
        if duplicate_local(w, applied, name, block_name, NIL, action) != 0:
            return 22
        replace_node(w, block, field(w, block, K_term), field(w, edit, K_term))
    return 0

def whole_overlap(w:mutbuf, applied:u64, name:u64, whole:u64) -> u64:
    scratch = get(w, 40)
    previous = 0
    while previous < applied:
        entry = scratch + 2048 + previous * 32
        if same_text(w, name, get(w, entry)) != 0:
            if whole != 0 or get(w, entry + 24) <= 2:
                return 1
        previous = previous + 1
    return 0

def duplicate_local(w:mutbuf, applied:u64, name:u64, block:u64, index:u64, action:u64) -> u64:
    scratch = get(w, 40)
    previous = 0
    while previous < applied:
        entry = scratch + 2048 + previous * 32
        if get(w, entry + 24) == action and get(w, entry + 16) == index:
            if same_text(w, name, get(w, entry)) != 0 and same_text(w, block, get(w, entry + 8)) != 0:
                return 1
        previous = previous + 1
    return 0

def remember_edit(w:mutbuf, applied:u64) -> u64:
    scratch = get(w, 40)
    entry = scratch + 2048 + applied * 32
    put(w, entry, get(w, scratch + 1296))
    put(w, entry + 8, get(w, scratch + 1312))
    put(w, entry + 16, get(w, scratch + 1320))
    put(w, entry + 24, get(w, scratch + 1280))
    return 0

def append_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    index = get(w, 56)
    if index < length(o):
        store(o, index, value)
    else:
        put(w, 48, NEED)
    put(w, 56, index + 1)
    return 0

def hash_get(w:mutbuf, index:u64) -> u64:
    return get(w, get(w, 40) + index)

def hash_put(w:mutbuf, index:u64, value:u64) -> u64:
    return put(w, get(w, 40) + index, value)
'''

def replace_once(source, old, new):
    assert source.count(old)==1, old
    return source.replace(old,new)

def diagnostic_functions():
    size=["def diagnostic_size(reason:u64) -> u64:"]
    emit=["def diagnostic_bytes(o:mutbuf, reason:u64) -> u64:"]
    for reason,message in sorted(MESSAGES.items()):
        data=message.encode("utf-8")
        size+=["    if reason == "+str(reason)+":","        return "+str(len(data))]
        emit+=["    if reason == "+str(reason)+":"]
        for offset in range(0,len(data),8):
            part=data[offset:offset+8]
            emit+=["        diagnostic_chunk(o, "+str(128+offset)+", "+
                   str(int.from_bytes(part,"little"))+", "+str(len(part))+")"]
        emit+=["        return "+str(len(data))]
    size+=["    return 0"];emit+=["    return 0"]
    helper="""def diagnostic_chunk(o:mutbuf, start:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, start + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
"""
    return ast.parse("\n".join(size+emit)+"\n"+helper).body

def source_program():
    constants={"K_"+key:1<<i for i,key in enumerate(KEYS)}
    constants.update(BAD=BAD,NEED=NEED,NIL=NIL,MAGIC=MAGIC,SCRATCH=SCRATCH)
    literals={"L_"+key:packed(value) for key,value in LITERALS.items()}
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in constants:return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
        def visit_Call(self,node):
            node=self.generic_visit(node);args=[]
            for value in node.args:
                if isinstance(value,ast.Name) and value.id in literals:
                    args.extend(ast.Constant(x) for x in literals[value.id])
                else:args.append(value)
            node.args=args
            return node
    own=Expand().visit(ast.parse(BODY)).body
    front_keep={"kind","count","child","field","shape","same","text_is",
                "render_fragment","hex_digit","append_string","next_node","key_less","sort_object","emit"}
    front=[node for node in ast.parse(frontend_source()).body if node.name in front_keep]
    assert {node.name for node in front}==front_keep
    fragment=copy.deepcopy(next(node for node in front if node.name=="render_fragment"))
    fragment.name="render_insertion_fragment"
    raw=ast.unparse(ast.fix_missing_locations(fragment))
    raw=replace_once(raw,"            if kind == 6:\n                sort_object(w, node)\n","")
    insertion=ast.parse(raw).body
    patch_keep={"same_text","named","exact_index","replace_node","append_node","lower_nibble"}
    patch=[node for node in ast.parse(PATCH_BODY).body if node.name in patch_keep]
    assert {node.name for node in patch}==patch_keep
    patch=Expand().visit(ast.Module(body=patch,type_ignores=[])).body
    key=["def key_id(w:mutbuf, node:u64) -> u64:",
         "    start = get(w, 64 + node * 56 + 40)",
         "    size = get(w, 64 + node * 56 + 48)"]
    for i,name in enumerate(KEYS):
        key+=["    if same(w, start, size, "+", ".join(map(str,packed(name)))+") == 1:",
              "        return "+str(1<<i)]
    key+=["    return 0"]
    decoder=decoder_source().replace("length(s) > 8388608","length(s) > 16777219")
    decoder=decoder.replace("maximum > 1048576 or maximum_depth > 128",
                            "maximum > length(s) or maximum_depth > length(s)")
    hash_nodes=[node for node in ast.parse(sha_source()).body if node.name not in {"get","put"}]
    digest=ast.unparse(ast.fix_missing_locations(ast.Module(body=hash_nodes,type_ignores=[])))
    digest=replace_once(digest,"def sha256(s: readbuf, o: mutbuf, w: mutbuf) -> u32:",
                               "def digest_fragment(s: mutbuf, w: mutbuf, size: u64) -> u64:")
    digest=replace_once(digest,"def padded_byte(s: readbuf, index: u64, total: u64) -> u64:",
                               "def padded_byte(s: mutbuf, index: u64, total: u64, size: u64) -> u64:")
    digest=digest.replace("length(s)","size")
    digest=replace_once(digest,"size > 8388608 or length(o) < 32 or length(w) < 1088","size > 8388608")
    digest=replace_once(digest,"padded_byte(s, block + i * 4 + j, padded)",
                               "padded_byte(s, block + i * 4 + j, padded, size)")
    digest=replace_once(digest,"byte(s, index)","byte(s, 32 + index)")
    digest=digest.replace("get(w,","hash_get(w,").replace("put(w,","hash_put(w,")
    digest=replace_once(digest,"store(o, i * 4 + j,","store(w, get(w, 40) + 1088 + i * 4 + j,")
    from importlib import util
    path=Path(__file__).with_name("issued_object_prefix_reference.py")
    spec=util.spec_from_file_location("ordinary_patch_transport_measure",path)
    module=util.module_from_spec(spec);spec.loader.exec_module(module)
    measure=[node for node in ast.parse(module.BODY).body if node.name=="measure_transport"]
    assert len(measure)==1
    nodes=own+diagnostic_functions()+front+insertion+patch+measure+ast.parse("\n".join(key)+"\n"+decoder+"\n"+digest).body
    names=[node.name for node in nodes];assert len(names)==len(set(names)),names
    for node in nodes:
        if node.name=="get":
            node.body=ast.parse("return "+" | ".join("(byte(w, index + %d) << %d)"%(i,8*i) for i in range(8))).body
        elif node.name=="put":
            node.body=ast.parse("\n".join("store(w, index + %d, (value >> %d) & 255)"%(i,8*i) for i in range(8))+"\nreturn 0").body
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])))+"\n"

def document():
    nodes=ast.parse(source_program()).body
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({"name":names[node.name],"params":[builder.param(value) for value in builder.params],
                          "returns":[builder.returns],"effects":["read","write","trap"],
                          "entry":"b0","blocks":builder.blocks})
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"ordinary_patch_prepare","functions":functions})

if __name__=="__main__":
    destination=Path(__file__).resolve().with_suffix(".hiaasm")
    destination.write_text(render_assembly(document()))
    print(destination)
