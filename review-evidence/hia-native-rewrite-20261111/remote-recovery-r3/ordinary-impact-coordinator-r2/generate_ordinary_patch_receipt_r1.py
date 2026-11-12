"""Native ordinary patch interface policy and ordered receipt value kernel.

Private inputs are the two actual admitted canonical Core snapshots plus the
issued original-input identity and exact preparation metadata. This pure kernel
owns sorted union interface comparison, the complete original diagnostic,
native SHA-256 and ordered receipt bytes. It does not grant Core authority or
waive the ordinary coordinator\'s base and fresh candidate admission steps.
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
MAGIC=int.from_bytes(b"HIAPRC01","little")
SCRATCH_BYTES=40960
KEYS=("functions","name","params","returns","effects","return_loans")
LITERALS={}
MESSAGES={1:"E_HIA_EDIT: interface change needs explicit v2 migrate policy: "}
BODY = r'''
def receipt(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128 or length(w) < 128:
        return BAD
    if length(s) == 0 or length(s) > 16777472:
        return receipt_event(o, 3, 1, 0, 0, 0)
    if measure_transport(s, w) == 0:
        return receipt_event(o, 3, 2, 0, 0, 0)
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
        return receipt_event(o, 1, 0, need_o, need_w, 0)
    put(o, 48, nodes)
    put(o, 56, depth)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return receipt_event(o, 3, 3, need_o, need_w, 0)
    if kind(w, 0) != 5 or count(w, 0) != 6:
        return receipt_event(o, 3, 4, need_o, need_w, 0)
    old = child(w, 0)
    new = next_node(w, old)
    identity = next_node(w, new)
    version_node = next_node(w, identity)
    policy_node = next_node(w, version_node)
    edits_node = next_node(w, policy_node)
    version = exact_index(s, w, version_node)
    policy = exact_index(s, w, policy_node)
    edits = exact_index(s, w, edits_node)
    if kind(w, old) != 6 or kind(w, new) != 6 or valid_identity(w, identity) == 0:
        return receipt_event(o, 3, 5, need_o, need_w, 0)
    if version != 1 and version != 2:
        return receipt_event(o, 3, 6, need_o, need_w, 0)
    if policy > 1 or (version == 1 and policy != 0) or edits == 0 or edits > 64:
        return receipt_event(o, 3, 7, need_o, need_w, 0)
    scratch = (get(w, 32) + 7) & 18446744073709551608
    if scratch > length(w) or length(w) - scratch < SCRATCH_BYTES:
        return receipt_event(o, 3, 8, need_o, need_w, 0)
    put(w, 40, scratch)
    put(w, scratch + 2048, old)
    put(w, scratch + 2056, new)
    put(w, scratch + 2064, identity)
    put(w, scratch + 2072, version)
    put(w, scratch + 2080, 0)
    put(w, scratch + 2088, 0)
    put(w, scratch + 2096, policy)
    put(w, scratch + 2104, edits)
    put(w, scratch + 2112, 0)
    if inventory(w, old, scratch + 4096, 2080) != 0:
        return receipt_event(o, 3, 9, need_o, need_w, 0)
    if inventory(w, new, scratch + 12288, 2088) != 0:
        return receipt_event(o, 3, 10, need_o, need_w, 0)
    put(w, 48, 0)
    changed_interfaces(s, o, w)
    if get(w, 48) != 0:
        return receipt_event(o, 3, 11, need_o, need_w, 0)
    action = 0
    reason = 0
    if get(w, scratch + 2112) != 0 and policy == 0:
        action = 2
        reason = 1
    if action == 0:
        if digest_node(s, o, w, old, scratch + 1200) == 0:
            return receipt_event(o, 3, 12, need_o, need_w, 0)
        if digest_node(s, o, w, new, scratch + 1232) == 0:
            return receipt_event(o, 3, 13, need_o, need_w, 0)
    put(w, 48, 0)
    put(w, 56, 128)
    if action == 2:
        emit_interface_error(o, w)
    else:
        emit_receipt(o, w)
    size = get(w, 56)
    if size > length(o):
        return receipt_event(o, 1, 0, size, need_w, 0)
    if get(w, 48) != 0:
        return receipt_event(o, 3, 14, need_o, need_w, 0)
    receipt_event(o, action, reason, need_o, need_w, size - 128)
    put(o, 64, version)
    put(o, 72, policy)
    put(o, 80, edits)
    put(o, 88, get(w, scratch + 2112))
    return 128

def receipt_event(o:mutbuf, action:u64, reason:u64, need_o:u64, need_w:u64, size:u64) -> u32:
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

def valid_identity(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 4 or count(w, node) != 64:
        return 0
    start = get(w, 64 + node * 56 + 24)
    i = 0
    while i < 64:
        value = byte(w, start + i)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return 0
        i = i + 1
    return 1

def changed_interfaces(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    scratch = get(w, 40)
    left = 0
    right = 0
    changed = 0
    left_size = get(w, scratch + 2080)
    right_size = get(w, scratch + 2088)
    while left < left_size or right < right_size:
        old = NIL
        new = NIL
        if left < left_size:
            old = get(w, scratch + 4096 + left * 8)
        if right < right_size:
            new = get(w, scratch + 12288 + right * 8)
        different = 1
        name = NIL
        if old == NIL:
            name = field(w, new, K_name)
            right = right + 1
        elif new == NIL:
            name = field(w, old, K_name)
            left = left + 1
        else:
            old_name = field(w, old, K_name)
            new_name = field(w, new, K_name)
            if same_text(w, old_name, new_name) != 0:
                name = old_name
                different = choose(same_interface(s, o, w, old, new) == 0, 1, 0)
                left = left + 1
                right = right + 1
            elif text_less(w, old_name, new_name) != 0:
                name = old_name
                left = left + 1
            else:
                name = new_name
                right = right + 1
        if different != 0:
            put(w, scratch + 20480 + changed * 8, name)
            changed = changed + 1
    put(w, scratch + 2112, changed)
    return 0

def emit_interface_error(o:mutbuf, w:mutbuf) -> u64:
    emit_text(o, w, 'E_HIA_EDIT: interface change needs explicit v2 migrate policy: ')
    scratch = get(w, 40)
    i = 0
    while i < get(w, scratch + 2112) and i < 8:
        if i != 0:
            emit_text(o, w, ', ')
        name = get(w, scratch + 20480 + i * 8)
        start = get(w, 64 + name * 56 + 24)
        j = 0
        while j < count(w, name):
            append_byte(o, w, byte(w, start + j))
            j = j + 1
        i = i + 1
    return 0

def emit_changes(o:mutbuf, w:mutbuf) -> u64:
    scratch = get(w, 40)
    append_byte(o, w, 91)
    i = 0
    while i < get(w, scratch + 2112):
        if i != 0:
            append_byte(o, w, 44)
        emit_name(o, w, get(w, scratch + 20480 + i * 8))
        i = i + 1
    append_byte(o, w, 93)
    return 0

def emit_receipt(o:mutbuf, w:mutbuf) -> u64:
    scratch = get(w, 40)
    version = get(w, scratch + 2072)
    emit_text(o, w, '{"schema":"hepta.hia.patch-result.v')
    append_byte(o, w, version + 48)
    emit_text(o, w, '","ok":true,"status":"verified_unpublished","before_sha256":"')
    emit_digest(o, w, scratch + 1200)
    emit_text(o, w, '","after_sha256":"')
    emit_digest(o, w, scratch + 1232)
    emit_text(o, w, '","edits":')
    receipt_count(o, w, get(w, scratch + 2104))
    emit_text(o, w, ',"edit_domain":"independently_verified_normalized_core","original_input_sha256":')
    emit_name(o, w, get(w, scratch + 2064))
    emit_text(o, w, ',"interface_changes":')
    emit_changes(o, w)
    emit_text(o, w, ',"claims":{"whole_module_rechecked":true,"behavior_equivalence_proved":false,"native_executed":false')
    if version == 2:
        emit_text(o, w, ',"interface_preserved":')
        if get(w, scratch + 2112) == 0:
            emit_text(o, w, 'true')
        else:
            emit_text(o, w, 'false')
        emit_text(o, w, ',"external_callers_revalidated":false')
    append_byte(o, w, 125)
    if version == 2:
        emit_text(o, w, ',"interface_policy":"')
        if get(w, scratch + 2096) == 0:
            emit_text(o, w, 'preserve')
        else:
            emit_text(o, w, 'migrate')
        append_byte(o, w, 34)
    append_byte(o, w, 125)
    return 0

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
    return get(w, get(w, 40) + index)

def hash_put(w:mutbuf, index:u64, value:u64) -> u64:
    return put(w, get(w, 40) + index, value)

def receipt_count(o:mutbuf, w:mutbuf, value:u64) -> u64:
    tens = 0
    while value >= 10:
        value = value - 10
        tens = tens + 1
    if tens != 0:
        append_byte(o, w, tens + 48)
    append_byte(o, w, value + 48)
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
    patch_keep={"same_text","equal_json","default_loans","same_interface","text_less","exact_index"}
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
    decoder=decoder.replace("length(s) > 8388608","length(s) > 16777472")
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
    spec=util.spec_from_file_location("ordinary_receipt_issued_measure",measure_path)
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
    return compact_authoring_cfg({"schema":"hepta.hia.program.v8","module":"ordinary_patch_receipt","functions":functions})

if __name__=="__main__":
    destination=Path(__file__).resolve().with_suffix(".hiaasm")
    destination.write_text(render_assembly(document()))
    print(destination)

