"""Unified P16 type diagnostics, late Core errors and actual Core Graph issuance.

This isolated extension starts from the complete actual FOLLOW53 group6 root.
Every original mode=1..4/tree input guard and non-Graph result path remains.
Only a successful mode=1/tree=0 raw admission continues through service58 kind2
and actual decoder roles31/32/33. All other accepted modes/tree combinations
return the original HIAWPE01 format. No host constructs Graph nodes.

Before extension, the complete current generator must reproduce the actual
293304-byte worker_program_root HIA source byte-for-byte. Existing fixed,
actual-type-context and late-Core diagnostics remain exact method ASTs.
This is development authoring. Private issued bytes and correlated leases are
required at runtime; a matching header alone grants no authority.

NEW INACTIVE SOURCE ONLY. No AST, generation, B3 or native result is claimed.
"""
from __future__ import annotations
import ast,copy
from hashlib import sha256

P16_OWNER_SHA="c7575f39085d09c05df5999087657f2825d9219e6d1512beba21d77c3551a3e4"
P16_GENERATOR_SHA="f73573a25b040920ff2f9b006a0fbc92e5e63616e64b550db92b4574b375a7b9"
LATE_OWNER_SHA="2c7ae73cf067397e7245cd52713e4c13ede0a108376a1697d40b2c6f1e580906"
PRIOR_ROOT_BYTES=293304
PRIOR_ROOT_SHA="42c09f173d185133de7c9a661c7798aa24c66a01583f0d36a777942ccdde0902"
PRIOR_ROOT_IMAGE_BYTES=381135
PRIOR_ROOT_IMAGE_SHA="0f3745a833a17bae7c42c9017f6b8f944f7069200db876119ba434f93cc06d9d"
ENTRY="unified_program_graph_service"
CONSTANTS={
 "BG_STATE":int.from_bytes(b"HIABGS01","little"),
 "BG_RESULT":int.from_bytes(b"HIAWGE01","little"),
 "BG_GRAPH_MAGIC":int.from_bytes(b"HIAGRF01","little"),
 "BG_DECODE_COMMAND":int.from_bytes(b"HIADJC01","little"),
 "BG_DECODE_EVENT":int.from_bytes(b"HIAJDE01","little"),
 "BG_LEASE":41,
 "BG_MAGIC":81000,"BG_GRAPH_AT":81008,"BG_GRAPH_BYTES":81016,
 "BG_GRAPH_ROOT":81024,"BG_GRAPH_NODES":81032,"BG_RELEASE":81040,
 "BG_OUTPUT_AT":81048,"BG_SAVED_EVENT":81104,
}
BODY=r'''
def backend_graph_begin(w:mutbuf)->u64:
    if get(w,WP_MODE) != 1 or get(w,WP_TREE) != 0 or get(w,WP_HAS_RECEIPT) != 1:
        return refuse(w,12510)
    if get(w,WP_CORE_SLOT) != B_CORE or get(w,WP_CORE_BYTES) != get(w,E_CORE_BYTES):
        return refuse(w,12511)
    if cap(w,B_CORE) != get(w,E_CORE_BYTES) or cap(w,B_GRAPH) != 0:
        return refuse(w,12512)
    if get(w,BG_MAGIC) != 0 or get(w,WP_RESULT_KIND) != 0:
        return refuse(w,12513)
    if get(w,WD_ACTIVE) != 0 or get(w,WC_ACTIVE) != 0:
        return refuse(w,12514)
    put(w,BG_MAGIC,BG_STATE)
    put(w,C_PHASE,91000)
    return 0

def backend_graph_frame(w:mutbuf)->u64:
    if get(w,BG_MAGIC) != BG_STATE or get(w,S_STATE) != 2 or get(w,S_KIND) != 2:
        return 0
    if get(w,S_RESULT_CODE) != 128 or get(w,S_RESULT_EVENT_BYTES) != 128:
        return 0
    if get(w,S_RESULT_EVENT) != BG_DECODE_EVENT or get(w,S_RESULT_EVENT+8) != 0:
        return 0
    if get(w,S_RESULT_EVENT+16) != BG_LEASE or get(w,S_RESULT_EVENT+24) != get(w,E_REQUEST):
        return 0
    if get(w,S_RESULT_EVENT+104) != 0 or cap(w,get(w,S_RESULT_SLOT)) != get(w,S_RESULT_BYTES):
        return 0
    at = get(w,S_RESULT_EVENT+112)
    size = get(w,S_RESULT_EVENT+120)
    if size < 128 or inside(w,get(w,S_RESULT_SLOT),at,size) == 0:
        return 0
    copy_local(w,BG_SAVED_EVENT,S_RESULT_EVENT,128)
    put(w,BG_GRAPH_AT,at)
    put(w,BG_GRAPH_BYTES,size)
    return 1

def backend_graph_header(w:mutbuf)->u64:
    if get(w,OBS) != BG_GRAPH_MAGIC or get(w,OBS+8) != BG_LEASE or get(w,OBS+56) != 0:
        return 0
    nodes = get(w,OBS+16)
    root = get(w,OBS+24)
    edges = get(w,OBS+32)
    size = get(w,BG_GRAPH_BYTES)
    if nodes == 0 or root == 0 or root > nodes or get(w,OBS+48) != size:
        return 0
    if nodes > (MAX-64) >> 6:
        return 0
    data = 64+nodes*64
    if edges > (MAX-data) >> 3:
        return 0
    data = data+edges*8
    if data > size or get(w,OBS+40) != size-data:
        return 0
    put(w,BG_GRAPH_ROOT,root)
    put(w,BG_GRAPH_NODES,nodes)
    return 1

def backend_graph_step(o:mutbuf,w:mutbuf,phase:u64)->u64:
    if get(w,BG_MAGIC) != BG_STATE or get(w,WP_HAS_RECEIPT) != 1:
        return refuse(w,12520)
    if phase == 91000:
        wire8(w,BG_DECODE_COMMAND,BG_LEASE,get(w,E_REQUEST),9,get(w,E_DIGITS),0,0,0)
        result = edit_service_start(w,2,B_CORE,0,get(w,E_CORE_BYTES),B_CONTROLLER,WIRE,64,512,MAIN,91001)
        if result != 0:
            return result
        return switch(o,w,SERVICE,50000)
    if phase == 91001:
        if backend_graph_frame(w) == 0:
            return refuse(w,12521)
        return grow(o,w,B_GRAPH,get(w,BG_GRAPH_BYTES),91002)
    if phase == 91002:
        return copy(o,w,get(w,S_RESULT_SLOT),get(w,BG_GRAPH_AT),B_GRAPH,0,get(w,BG_GRAPH_BYTES),91003)
    if phase == 91003:
        return protect(o,w,B_GRAPH,1,91004)
    if phase == 91004:
        return view(o,w,B_GRAPH,0,64,91005)
    if phase == 91005:
        if backend_graph_header(w) == 0:
            return refuse(w,12522)
        put(w,BG_RELEASE,32)
        put(w,C_PHASE,91006)
        return 0
    if phase == 91006:
        slot = get(w,BG_RELEASE)
        if slot == 50:
            put(w,C_PHASE,91007)
            return 0
        if slot < 32 or slot >= 50:
            return refuse(w,12523)
        put(w,BG_RELEASE,slot+1)
        return release(o,w,slot,91006)
    if phase == 91007:
        if cap(w,B_GRAPH) != get(w,BG_GRAPH_BYTES) or get(w,BG_GRAPH_ROOT) == 0:
            return refuse(w,12524)
        return worker_result_begin(w,1,0,0,0,B_CORE,0,get(w,WP_CORE_BYTES))
    return refuse(w,12525)

def worker_result_layout(w:mutbuf)->u64:
    if backend_original_result_layout(w) == 0:
        return 0
    if get(w,WP_RESULT_KIND) == 4:
        return 1
    if get(w,WP_MODE) != 1 or get(w,WP_TREE) != 0:
        return 1
    if get(w,WP_RESULT_KIND) != 1:
        return 0
    if get(w,BG_MAGIC) != BG_STATE or get(w,BG_GRAPH_BYTES) < 128 or get(w,BG_GRAPH_ROOT) == 0:
        return 0
    if cap(w,B_GRAPH) != get(w,BG_GRAPH_BYTES) or get(w,WP_HAS_RECEIPT) != 1:
        return 0
    end = get(w,WP_FRAME_BYTES)
    if get(w,BG_GRAPH_BYTES) > MAX-end:
        return 0
    put(w,BG_OUTPUT_AT,end)
    end = end+get(w,BG_GRAPH_BYTES)
    put(w,WP_FRAME_BYTES,end)
    put(w,WP_HEADER,BG_RESULT)
    put(w,WP_HEADER+72,end)
    put(w,WP_HEADER+144,get(w,BG_OUTPUT_AT))
    put(w,WP_HEADER+152,get(w,BG_GRAPH_BYTES))
    put(w,WP_HEADER+160,BG_LEASE)
    put(w,WP_HEADER+168,get(w,BG_GRAPH_ROOT))
    put(w,WP_HEADER+176,get(w,BG_GRAPH_NODES))
    return 1
'''

ADMISSION_OLD='''        if get(w, WP_MODE) == 1:
            return worker_result_begin(w, 1, 0, 0, 0, B_CORE, 0, get(w, WP_CORE_BYTES))
'''
ADMISSION_NEW='''        if get(w, WP_MODE) == 1:
            if get(w, WP_TREE) == 0:
                return backend_graph_begin(w)
            return worker_result_begin(w, 1, 0, 0, 0, B_CORE, 0, get(w, WP_CORE_BYTES))
'''
RESULT_OLD='''        if get(w, WP_RESULT_KIND) == 1:
            put(w, C_PHASE, 88007)
            return 0
'''
RESULT_NEW='''        if get(w, WP_RESULT_KIND) == 1:
            if get(w, WP_MODE) == 1 and get(w, WP_TREE) == 0:
                return copy(o, w, B_GRAPH, 0, B_RESULT, get(w, BG_OUTPUT_AT), get(w, BG_GRAPH_BYTES), 88007)
            put(w, C_PHASE, 88007)
            return 0
'''

def unique_replace(source,old,new):
    assert source.count(old)==1
    result=source.replace(old,new,1)
    assert result.count(new)==1 and result.replace(new,old,1)==source
    return result

def extend(generator,owner_raw,generator_raw,late_owner_raw,actual_predecessor_source):
    """Regenerate the exact predecessor, then produce an isolated AST map.

    actual_predecessor_source must be the complete source extracted by the
    independently checked FOLLOW53 archive reader. Source equality is a
    development custody gate, not runtime external-frame authentication.
    """
    assert sha256(owner_raw).hexdigest()==P16_OWNER_SHA
    assert sha256(generator_raw).hexdigest()==P16_GENERATOR_SHA
    assert sha256(late_owner_raw).hexdigest()==LATE_OWNER_SHA
    assert isinstance(actual_predecessor_source,bytes)
    assert (len(actual_predecessor_source),sha256(actual_predecessor_source).hexdigest())==(
        PRIOR_ROOT_BYTES,PRIOR_ROOT_SHA)
    assert {"worker_late_core_start","worker_late_core_text",
        "worker_type_context_start","worker_type_context_step",
        "worker_fixed_diagnostic_start","worker_fixed_diagnostic_step"}<=set(generator.working)
    from hepta.hia_program import verify_program
    predecessor_body,predecessor_live=generator.expanded("worker_program_service")
    predecessor_document=generator.base.document(predecessor_body)
    predecessor_document["module"]="worker_program_root"
    reproduced=generator.base.render_assembly(predecessor_document).encode("utf-8")
    assert reproduced==actual_predecessor_source
    assert generator.base.assemble_program(reproduced).canonical_bytes==verify_program(
        predecessor_document).canonical_bytes
    predecessor_profile=generator.measured(predecessor_document)
    predecessor_ast={name:ast.dump(node,include_attributes=False)
        for name,node in generator.working.items()}
    predecessor_constants=dict(generator.CONSTANTS)
    constants=dict(generator.CONSTANTS)
    assert not(set(constants)&set(CONSTANTS))
    constants.update(CONSTANTS)
    assert constants["BG_SAVED_EVENT"]+128<=constants["MIN_WORK"]
    regions=[
        ("late-Core-text",constants["PREFIX_TEXT"],constants["PREFIX_TEXT"]+128),
        ("saved-code",constants["WP_SAVED_CODE"],constants["WP_SAVED_CODE"]+64),
        ("fixed-diagnostic",constants["WD_SEQUENCE"],constants["WD_HEADER"]+128),
        ("actual-type-context",constants["WC_ACTIVE"],constants["WC_HEADER"]+128),
        ("Core-Graph",constants["BG_MAGIC"],constants["BG_SAVED_EVENT"]+128),
    ]
    assert all(0<=lo<hi<=constants["MIN_WORK"] for _,lo,hi in regions)
    assert all(a[2]<=b[1] or b[2]<=a[1]
               for i,a in enumerate(regions) for b in regions[i+1:])
    assert not [(n,v) for n,v in generator.CONSTANTS.items()
                if type(v) is int and constants["BG_MAGIC"]<=v<constants["BG_SAVED_EVENT"]+128]
    assert constants["B_GRAPH"] not in (constants["B_CORE"],constants["B_PROGRAM"],
        constants["B_PROGRAM_FRAME"],constants["B_CONTROLLER"],constants["B_RESULT"])
    assert constants["B_GRAPH"] not in range(32,59)
    assert constants["MAIN"]==56 and constants["SERVICE"]==58
    original=generator.working
    working={name:copy.deepcopy(node) for name,node in original.items()}
    def changed(name,old,new):
        before=ast.unparse(original[name])+"\n"
        source=unique_replace(before,old,new)
        node=ast.parse(source).body[0]
        assert node.name==name
        working[name]=node
        return dict(function=name,before_sha256=sha256(before.encode()).hexdigest(),
            after_sha256=sha256(source.encode()).hexdigest(),unique_inverse_exact=True)
    edits=[]
    edits.append(changed("worker_admission_step",ADMISSION_OLD,ADMISSION_NEW))
    edits.append(changed("worker_result_step",RESULT_OLD,RESULT_NEW))
    saved=copy.deepcopy(original["worker_result_layout"])
    saved.name="backend_original_result_layout"
    assert saved.name not in working
    working[saved.name]=saved
    # Preserve the full original input contract and complete current dispatch.
    # The f0 name, new success continuation and its private in-flight mode
    # invariant are added. Original input modes, private tree input, assembly
    # and 87500/87600 error routes remain.
    original_top=ast.unparse(original["worker_program_service"])+"\n"
    top=unique_replace(original_top,"def worker_program_service(","def "+ENTRY+"(")
    top=unique_replace(top,
        "    while get(w, L_STATUS) == 1:\n",
        "    if get(w, BG_MAGIC) != 0:\n"
        "        if get(w, BG_MAGIC) != BG_STATE or get(w, WP_MODE) != 1 or get(w, WP_TREE) != 0:\n"
        "            return refuse(w, 12526)\n"
        "    while get(w, L_STATUS) == 1:\n")
    top=unique_replace(top,
        "        elif phase >= 88000 and phase < 88100:\n",
        "        elif phase >= 91000 and phase < 91100:\n"
        "            result = backend_graph_step(o, w, phase)\n"
        "        elif phase >= 88000 and phase < 88100:\n")
    restored=top.replace("def "+ENTRY+"(","def worker_program_service(",1)
    restored=restored.replace(
        "    if get(w, BG_MAGIC) != 0:\n"
        "        if get(w, BG_MAGIC) != BG_STATE or get(w, WP_MODE) != 1 or get(w, WP_TREE) != 0:\n"
        "            return refuse(w, 12526)\n", "",1)
    restored=restored.replace(
        "        elif phase >= 91000 and phase < 91100:\n"
        "            result = backend_graph_step(o, w, phase)\n", "",1)
    assert restored==original_top
    assert ENTRY not in working
    working[ENTRY]=ast.parse(top).body[0]
    edits.append(dict(function=ENTRY,derived_from="worker_program_service",
        before_sha256=sha256(original_top.encode()).hexdigest(),
        after_sha256=sha256(top.encode()).hexdigest(),unique_inverse_exact=True))
    additions=ast.parse(BODY).body
    assert all(isinstance(node,ast.FunctionDef) for node in additions)
    assert len({node.name for node in additions})==len(additions)
    assert set(node.name for node in additions)&set(working)=={"worker_result_layout"}
    for node in additions:working[node.name]=node
    untouched=set(original)-{"worker_admission_step","worker_result_step","worker_result_layout"}
    assert all(ast.dump(working[n],include_attributes=False)==ast.dump(original[n],include_attributes=False) for n in untouched)
    live={ENTRY};pending=[ENTRY]
    while pending:
        for node in ast.walk(working[pending.pop()]):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                name=node.func.id
                if name in working and name not in live:
                    live.add(name);pending.append(name)
    assert {"worker_type_context_child_frame","program_receipt_header","worker_program_child",
        "worker_save_receipt","edit_service_start","backend_graph_header",
        "import_hash_step","worker_result_begin","worker_fixed_diagnostic_step",
        "worker_type_context_step","worker_fixed_diagnostic_start","worker_type_context_start",
        "worker_late_core_start","worker_late_core_text"}<=live
    assert set(predecessor_live)-{"worker_program_service"}<=live
    assert not(live&{"projection_step","wire_step","publication_step","assembly_service"})
    for name in ("prefix_failure","worker_fixed_diagnostic_step","worker_type_context_step",
                 "worker_fixed_diagnostic_start","worker_type_context_start",
                 "worker_type_context_child_frame","worker_late_core_start","worker_late_core_text",
                 "worker_program_service","worker_program_begin","worker_program_child",
                 "worker_object_step","worker_object_failure","worker_assembly_finish"):
        assert ast.dump(working[name],include_attributes=False)==ast.dump(original[name],include_attributes=False)

    order=[ENTRY]+[n for n in working if n in live and n!=ENTRY]
    tree=ast.Module(body=[copy.deepcopy(working[n]) for n in order],type_ignores=[])
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    for node in tree.body:
        if node.name!=ENTRY:
            assert isinstance(node.returns,ast.Name) and node.returns.id in ("u32","u64")
            node.returns.id="u64"
    assert generator.CONSTANTS==predecessor_constants
    assert set(generator.working)==set(predecessor_ast)
    assert all(ast.dump(generator.working[n],include_attributes=False)==raw
        for n,raw in predecessor_ast.items())
    proof=dict(schema="hia-unified-P16-late-Core-Graph-extension-v1",status="GENERATED_AUTHORING_NOT_NATIVE",
        edits=edits,unchanged_functions=sorted(untouched),live=sorted(live),
        original_result_layout_preserved_with_name_only=True,
        actual_predecessor_source=dict(bytes=PRIOR_ROOT_BYTES,sha256=PRIOR_ROOT_SHA,
            module="worker_program_root",profile=predecessor_profile),
        prior_current_P16_root_regenerated_byte_exact=True,
        current_generator_ast_and_constants_unchanged=True,
        original_input_modes_and_private_tree_contract_unchanged=True,
        original_non_target_result_frames_unchanged=True,
        Graph_extension_only_on_actual_mode1_tree0_success=True,
        full_original_mode_dispatch_reachable=True,
        fixed_diagnostic_actual_type_context_and_late_Core_methods_preserved=True,
        complete_current_dispatch_inverse_exact=True,workspace_regions=regions,
        actual_raw_program_to_Core_admission_required=True,
        actual_service58_decoder31_32_33_required=True,
        successful_Graph_bytes_copied_before_peer_release=True,
        actual_Core_receipt_and_Core_payload_retained=True,
        complete_public_backend=False,installed=False,native_execution_claimed=False)
    return ast.unparse(tree)+"\n",proof
