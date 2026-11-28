"""HIA ownership and foreign-call policy for real CPython cells and frames.

The mechanical adapter exposes only the enumerated operations below. HIA owns
validation, duplicate/search loops, owned-result masks, foreign call ordering,
cleanup, and completion. CPython GC slots remain an explicit compatibility ABI.
"""
from __future__ import annotations
import ast
import json
from hashlib import sha256
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = "examples/hia_bootstrap/carrier_cell_policy.hepta"
ABI_PATH = "hepta/hia_carrier_cell_abi.json"
MAGIC = int.from_bytes(b"HIACCP01", "little")
REFUSAL = 0xfffffffd
OPERATIONS = {
 1:"retain_receiver",
 11:"parse_bindings_constructor",12:"observe_bindings_argument_types",
 13:"observe_name_tuple_length",14:"observe_cell_tuple_length",
 15:"observe_one_binding_types",16:"compare_two_exact_names",
 17:"allocate_bindings_storage",18:"retain_empty_reader",19:"retain_one_binding",
 21:"observe_live_binding_count",22:"observe_lookup_name_type",
 23:"compare_one_live_name",24:"observe_cell_and_reader_state",
 25:"retain_current_cell_value",26:"call_actual_empty_cell_reader",
 27:"observe_subset_length",28:"observe_empty_reader_liveness",
 29:"allocate_selected_cells_tuple",30:"retain_selected_cell",
 31:"parse_callback_constructor",32:"observe_callback_argument_types",
 33:"allocate_callback",34:"retain_one_callback_field",
 35:"call_real_bindings_constructor",
 41:"parse_callback_argument",42:"observe_factory_liveness",
 43:"construct_bound_dictionary",44:"construct_factory_arguments",
 45:"construct_factory_keywords",46:"call_actual_factory",
 47:"call_actual_frame_finish",80:"release_one_owned_slot",90:"raise_fixed_exception",
}
SOURCE = r'''
def carrier_cell(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or length(o) != 32 or length(w) != 512:
        return REFUSAL
    if word(s, 0) != MAGIC or word(s, 56) != 0:
        return REFUSAL
    mode = word(s, 8)
    if mode < 1 or mode > 5:
        return REFUSAL
    if get(w, 0) == 0:
        if zero(w, 0, 512) != 1:
            return REFUSAL
        if word(s, 16) != 0 or word(s, 24) != 0 or word(s, 32) != 0 or word(s, 40) != 0 or word(s, 48) != 0:
            return REFUSAL
        put(w, 0, MAGIC)
        put(w, 8, mode)
        if mode == 1:
            return ask(o, w, 11, 0, 0)
        if mode == 2 or mode == 3:
            return ask(o, w, 21, 0, 0)
        if mode == 4:
            return ask(o, w, 31, 0, 0)
        return ask(o, w, 41, 0, 0)
    if get(w, 0) != MAGIC or get(w, 8) != mode or get(w, 104) != 0:
        return REFUSAL
    if word(s, 16) != get(w, 16) or word(s, 24) != get(w, 24):
        return REFUSAL
    if word(s, 32) > 1 or word(s, 48) > 255 or get(w, 72) > 255 or get(w, 56) > 1:
        return REFUSAL
    if get(w, 40) > 64 or get(w, 48) > 64 or get(w, 64) > 64 or get(w, 128) > 64:
        return REFUSAL
    action = get(w, 24)
    if admitted_action(mode, action) == 0:
        return REFUSAL
    before = get(w, 72)
    after = word(s, 48)
    bit = acquired_bit(action)
    if action == 80:
        release = get(w, 32)
        if release == 0 or release > 128 or release & (release - 1) != 0 or before & release == 0:
            return REFUSAL
        if word(s, 32) != 0 or after != (before ^ release):
            return REFUSAL
    elif bit != 0:
        if before & bit != 0:
            return REFUSAL
        if word(s, 32) == 0:
            if after != (before | bit):
                return REFUSAL
        elif after != before and after != (before | bit):
            return REFUSAL
    elif after != before:
        return REFUSAL
    put(w, 72, after)
    if word(s, 32) == 1:
        put(w, 56, 1)
        if action == 46:
            put(w, 96, 1)
        return cleanup(o, w)
    if action == 90:
        return REFUSAL
    if action == 80:
        return cleanup(o, w)
    if mode == 1:
        return bindings_new(s, o, w)
    if mode == 2 or mode == 3:
        return bindings_read(s, o, w)
    if mode == 4:
        return callback_new(s, o, w)
    return callback_call(s, o, w)

def admitted_action(mode:u64, action:u64) -> u64:
    if action == 80 or action == 90:
        return 1
    if mode == 1:
        return choose(action >= 11 and action <= 19, 1, 0)
    if mode == 2:
        return choose(action == 1 or (action >= 21 and action <= 26), 1, 0)
    if mode == 3:
        return choose((action >= 21 and action <= 23) or (action >= 27 and action <= 30) or action == 35, 1, 0)
    if mode == 4:
        return choose(action >= 31 and action <= 34, 1, 0)
    return choose(action == 1 or (action >= 41 and action <= 47), 1, 0)

def acquired_bit(action:u64) -> u64:
    if action == 1:
        return 128
    if action == 17 or action == 33:
        return 1
    if action == 29:
        return 2
    if action == 43:
        return 4
    if action == 44:
        return 8
    if action == 45:
        return 16
    if action == 46:
        return 32
    if action == 25 or action == 26 or action == 35 or action == 47:
        return 64
    return 0

def bindings_new(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 24)
    x = word(s, 40)
    if action == 11:
        return ask(o, w, 12, 0, 0)
    if action == 12:
        if x != 7:
            return ask(o, w, 90, 1, 0)
        return ask(o, w, 13, 0, 0)
    if action == 13:
        if x < 1 or x > 64:
            return ask(o, w, 90, 2, 0)
        put(w, 64, x)
        return ask(o, w, 14, 0, 0)
    if action == 14:
        if x != get(w, 64):
            return ask(o, w, 90, 2, 0)
        return ask(o, w, 15, 0, 0)
    if action == 15:
        if x != 3:
            return ask(o, w, 90, 3, 0)
        put(w, 48, 0)
        if get(w, 40) != 0:
            return ask(o, w, 16, get(w, 40), 0)
        return next_binding(o, w)
    if action == 16:
        if x > 1:
            return REFUSAL
        if x == 1:
            return ask(o, w, 90, 4, 0)
        put(w, 48, get(w, 48) + 1)
        if get(w, 48) < get(w, 40):
            return ask(o, w, 16, get(w, 40), get(w, 48))
        return next_binding(o, w)
    if action == 17:
        return ask(o, w, 18, 0, 0)
    if action == 18:
        put(w, 40, 0)
        return ask(o, w, 19, 0, 0)
    if action == 19:
        put(w, 40, get(w, 40) + 1)
        if get(w, 40) < get(w, 64):
            return ask(o, w, 19, get(w, 40), 0)
        return cleanup(o, w)
    return REFUSAL

def next_binding(o:mutbuf, w:mutbuf) -> u32:
    put(w, 40, get(w, 40) + 1)
    if get(w, 40) < get(w, 64):
        return ask(o, w, 15, get(w, 40), 0)
    return ask(o, w, 17, get(w, 64), 0)

def bindings_read(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    mode = get(w, 8)
    action = get(w, 24)
    x = word(s, 40)
    if action == 21:
        if x > 64:
            return REFUSAL
        put(w, 128, x)
        if mode == 3:
            return ask(o, w, 27, 0, 0)
        return ask(o, w, 22, 0, 0)
    if action == 27:
        if x < 1 or x > 64:
            return ask(o, w, 90, 7, 0)
        put(w, 64, x)
        return ask(o, w, 28, 0, 0)
    if action == 28:
        if x != 1:
            return ask(o, w, 90, 7, 0)
        return ask(o, w, 29, get(w, 64), 0)
    if action == 29:
        return ask(o, w, 22, 0, 0)
    if action == 22:
        if x != 1:
            return ask(o, w, 90, 5, 0)
        put(w, 48, 0)
        if get(w, 128) == 0:
            return ask(o, w, 90, 5, 0)
        return ask(o, w, 23, 0, 0)
    if action == 23:
        if x > 1:
            return REFUSAL
        if x == 0:
            put(w, 48, get(w, 48) + 1)
            if get(w, 48) == get(w, 128):
                return ask(o, w, 90, 5, 0)
            return ask(o, w, 23, get(w, 48), 0)
        if mode == 3:
            return ask(o, w, 30, get(w, 48), get(w, 40))
        return ask(o, w, 24, get(w, 48), 0)
    if action == 24:
        if x == 0:
            return ask(o, w, 90, 6, 0)
        if x == 1:
            return ask(o, w, 25, get(w, 48), 0)
        if x != 2:
            return REFUSAL
        return ask(o, w, 1, 0, 0)
    if action == 1:
        return ask(o, w, 26, get(w, 48), 0)
    if action == 25 or action == 26 or action == 35:
        return cleanup(o, w)
    if action == 30:
        put(w, 40, get(w, 40) + 1)
        if get(w, 40) < get(w, 64):
            return ask(o, w, 22, get(w, 40), 0)
        return ask(o, w, 35, 0, 0)
    return REFUSAL

def callback_new(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 24)
    x = word(s, 40)
    if action == 31:
        return ask(o, w, 32, 0, 0)
    if action == 32:
        if x != 63:
            return ask(o, w, 90, 8, 0)
        return ask(o, w, 33, 0, 0)
    if action == 33:
        return ask(o, w, 34, 0, 0)
    if action == 34:
        put(w, 40, get(w, 40) + 1)
        if get(w, 40) < 7:
            return ask(o, w, 34, get(w, 40), 0)
        return cleanup(o, w)
    return REFUSAL

def callback_call(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    action = get(w, 24)
    x = word(s, 40)
    if action == 41:
        return ask(o, w, 42, 0, 0)
    if action == 42:
        if x != 1:
            return ask(o, w, 90, 9, 0)
        return ask(o, w, 1, 0, 0)
    if action == 1:
        return ask(o, w, 43, 0, 0)
    if action == 43:
        return ask(o, w, 44, 0, 0)
    if action == 44:
        return ask(o, w, 45, 0, 0)
    if action == 45:
        return ask(o, w, 46, 0, 0)
    if action == 46:
        put(w, 96, 1)
        return cleanup(o, w)
    if action == 47:
        return cleanup(o, w)
    return REFUSAL

def cleanup(o:mutbuf, w:mutbuf) -> u32:
    mask = get(w, 72)
    if get(w, 96) == 1:
        if mask & 8 != 0:
            return ask(o, w, 80, 8, 0)
        if mask & 16 != 0:
            return ask(o, w, 80, 16, 0)
        if mask & 4 != 0:
            return ask(o, w, 80, 4, 0)
        put(w, 96, 0)
        if get(w, 56) == 0:
            if mask & 32 == 0:
                return REFUSAL
            return ask(o, w, 47, 0, 0)
    if mask & 32 != 0:
        return ask(o, w, 80, 32, 0)
    if mask & 16 != 0:
        return ask(o, w, 80, 16, 0)
    if mask & 8 != 0:
        return ask(o, w, 80, 8, 0)
    if mask & 4 != 0:
        return ask(o, w, 80, 4, 0)
    if mask & 2 != 0:
        return ask(o, w, 80, 2, 0)
    if get(w, 56) == 1:
        if mask & 64 != 0:
            return ask(o, w, 80, 64, 0)
        if mask & 1 != 0:
            return ask(o, w, 80, 1, 0)
    if mask & 128 != 0:
        return ask(o, w, 80, 128, 0)
    target = choose(get(w, 8) == 1 or get(w, 8) == 4, 1, 64)
    if get(w, 56) == 1:
        target = 0
    if get(w, 72) != target:
        return REFUSAL
    put(w, 104, 1)
    put(w, 24, 0)
    put(o, 0, 0)
    put(o, 8, get(w, 56))
    put(o, 16, target)
    put(o, 24, 0)
    return 0

def ask(o:mutbuf, w:mutbuf, action:u64, a:u64, b:u64) -> u32:
    put(w, 16, get(w, 16) + 1)
    put(w, 24, action)
    put(w, 32, a)
    put(o, 0, action)
    put(o, 8, a)
    put(o, 16, b)
    put(o, 24, 0)
    return 1

def choose(condition:bool, yes:u64, no:u64) -> u64:
    if condition:
        return yes
    return no

def word(s:readbuf, at:u64) -> u64:
    n = 0
    i = 0
    while i < 8:
        n = n | (byte(s, at + i) << (i * 8))
        i = i + 1
    return n

def get(w:mutbuf, at:u64) -> u64:
    n = 0
    i = 0
    while i < 8:
        n = n | (byte(w, at + i) << (i * 8))
        i = i + 1
    return n

def put(w:mutbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (n >> (i * 8)) & 255)
        i = i + 1
    return 0

def zero(w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        if byte(w, at + i) != 0:
            return 0
        i = i + 1
    return 1
'''
def document():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            values = {"MAGIC": MAGIC, "REFUSAL": REFUSAL}
            return ast.copy_location(ast.Constant(values[node.id]), node) if node.id in values else node
    nodes = ast.fix_missing_locations(Constants().visit(ast.parse(SOURCE))).body
    names = {node.name: "f"+str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"],
                              entry="b0", blocks=builder.blocks))
    return compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module="carrier_cell_policy", functions=functions))
def generated_files():
    raw = render_assembly(document()).encode()
    abi = dict(schema="hepta.hia.cpython-cell-foreign-abi.v1", source=SOURCE_PATH,
               source_sha256=sha256(raw).hexdigest(), magic="HIACCP01", request_bytes=64,
               response_bytes=32, state_bytes=512, refusal=REFUSAL,
               modes={"bindings_new":1,"bindings_getitem":2,"bindings_subset":3,"callback_new":4,"callback_call":5},
               operations=OPERATIONS, maximum_bindings=64, maximum_effects=10000,
               extension_domain="CPYTHON_GIL_LINUX_X86_64_LP64_COMPATIBILITY",
               standalone_cpython_dependency=False, arbitrary_c_api_calls=False,
               default_worker_qualification_claimed=False)
    return {SOURCE_PATH:raw, ABI_PATH:(json.dumps(abi,sort_keys=True,indent=2)+"\n").encode()}
if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument("--check",action="store_true");args=parser.parse_args()
    for name,raw in generated_files().items():
        path=ROOT/name
        if args.check:
            if path.read_bytes()!=raw:raise SystemExit("generated cell policy differs: "+name)
        else:path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        print(name,len(raw),sha256(raw).hexdigest())
