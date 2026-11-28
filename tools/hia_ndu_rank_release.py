"""Native ordinary-release and installed-DAG construction of complete NDU ranking.

All policies and final images are HIA source products. This module declares the
graph and the ordinary host's mechanical calls to the same native packers.
The current whole contract is independent of the frozen historical Rust/leaf
qualification. Both construction paths reject any different complete product.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import struct

PROGRAMS="examples/hia_bootstrap/"
POLICY="source_ndu_rank_pack.hepta"
KIT_PACKER="ndu_rank_source_kit_packer.hepta"
KIT_POLICY="source_ndu_rank_release_kit.hepta"
SOURCE_KIT_INPUTS=tuple(PROGRAMS+name for name in (KIT_PACKER,KIT_POLICY,"source_release_kit.hepta","source_build_packer.hepta","selfhost.hepta"))
CONTRACT="docs/HIA_NATIVE_NDU_RANK_BUILD.json"
PROFILE="hepta.hia.ndu-rank-native-construction-records.v4"
CONTRACT_PRODUCT="_hia_ndu_rank_build.json"
NORMALIZER_PRODUCT="hia-nominal-constructor"
THRESHOLD_SHA256="735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706"
THRESHOLD_BYTES=10100891
PRODUCTS={
 "engine":"_hia_ndu_rank_engine.bin","context":"_hia_ndu_rank_context.bin",
 "normalizer":"_hia_ndu_normalizer.elf","proof":"_hia_ndu_public_proof.elf",
 "threshold":"_hia_ndu_threshold.hiadat",
}
ROLES=("main","tasks","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","r11","r12","r13","r14","r15","r16","r17","r19","r20")
ROLE_SOURCES={
 "main":"ndu_rank_main","tasks":"ndu_rank_tasks_current","r1":"ndu_rank_json",
 "r2":"ndu_rank_canonical","r3":"ndu_rank_snapshot","r4":"background_optimizer_structure",
 "r5":"background_optimizer_freeze","r6":"ndu_rank_admission","r7":"agent_binary64",
 "r8":"agent_binary64_format","r9":"ndu_rank_cost","r10":"ndu_rank_clock_budget",
 "r11":"ndu_rank_unchanged","r12":"ndu_rank_binding","r13":"ndu_rank_selection",
 "r14":"ndu_rank_report","r15":"sha256_stream","r16":"ndu_rank_process_current",
 "r20":"background_optimizer_json_capture",
}
OWNER=("ndu_rank_native_owner","sha256_stream","ndu_rank_native_owner_identity",
       "native_path_resolve","ndu_rank_native_owner_pump","ndu_rank_native_owner_json")
SCALAR=("native_scalar_proof_policy","native_scalar_proof_hash","core_admission",
        "json_canonical","multiversion_proof_graph","cnf","evaluate_reference_wire",
        "scalar_reference","general_cnf")
CALL=("native_call_proof_policy","native_scalar_proof_hash","core_admission",
      "json_canonical","multiversion_proof_graph","native_call_closure_graph",
      "evaluate_reference_wire","scalar_reference","general_call_cnf","native_call_graph_linker")
FACADE=("ndu_rank_proof_facade","ndu_rank_sha_stream_private","multiversion_prepare_process",
        "native_public_proof_receipt","native_public_proof_json","native_public_call_proof_receipt",
        "public_proof_typed","public_proof_values","bounded_unroll_transform",
        "bounded_unroll_interface","bounded_unroll_solver","bounded_unroll_workflow",
        "normalizer_record","scalar_image","call_image","bounded_unroll_receipt")
PACKERS=("ndu_rank_native_owner_packer","ndu_rank_native_owner_error_packer",
         "ndu_rank_engine_packer","native_scalar_proof_packer","native_call_proof_packer",
         "ndu_rank_proof_facade_packer","ndu_rank_context_payload_packer",
         "ndu_rank_context_records_packer")
EXTRA=("ndu_rank_native_owner_error","ndu_rank_context_records","multiversion_background_payload")
NATIVE_NAMES=tuple(sorted(set(ROLE_SOURCES.values())|set(OWNER)|set(SCALAR)|set(CALL)|
                          (set(FACADE)-{"normalizer_record","scalar_image","call_image"})|
                          set(PACKERS)|set(EXTRA)))
THRESHOLD_SOURCES=tuple(PROGRAMS+f"ndu_rank_threshold_{i:02d}.hiadat" for i in range(11))


def checked_contract(raw):
    value=json.loads(raw)
    if type(value)is not dict or value.get("schema")!=PROFILE:
        raise ValueError("current complete NDU construction contract differs")
    rows=value.get("products")
    if type(rows)is not dict or set(rows)!=set(PRODUCTS):
        raise ValueError("complete NDU product inventory differs")
    for role,name in PRODUCTS.items():
        row=rows[role]
        if (type(row)is not dict or row.get("resource")!=name or type(row.get("bytes"))is not int
                or not 0<row["bytes"]<=16<<20 or type(row.get("sha256"))is not str
                or len(row["sha256"])!=64 or any(x not in "0123456789abcdef"for x in row["sha256"])):
            raise ValueError("complete NDU product identity differs: "+role)
    if rows["threshold"]["bytes"]!=THRESHOLD_BYTES or rows["threshold"]["sha256"]!=THRESHOLD_SHA256:
        raise ValueError("original exact NDU threshold differs")
    if tuple(row.get("role")for row in value.get("rank_roles",[]))!=ROLES:
        raise ValueError("complete NDU role inventory differs")
    return value


def identity_record(kind,raw):
    return struct.pack("<8sQQ32sQ",b"HIANKI01",kind,len(raw),sha256(raw).digest(),0)


def frame(magic,parts,*,engine=False,owner=False,payload=False,records=b""):
    sizes=struct.pack("<"+str(len(parts))+"Q",*map(len,parts))
    if engine:header=magic+struct.pack("<Q",21)+sizes+struct.pack("<Q",1)
    elif owner:header=magic+sizes+struct.pack("<Q",1)
    elif payload:header=magic+sizes+bytes(16)
    elif records:header=magic+sizes+struct.pack("<4Q",192,0,0,0)
    else:header=magic+sizes
    return header+b"".join(parts)+records


def stage_ndu_rank(work,seed,compile_sources,call,compiler,normalizer,publish):
    from tools.build_hia_native_store_release import release_sources
    builds=release_sources(seed,compile_sources,call)
    named={name+".hepta":PROGRAMS+name+".hepta"for name in NATIVE_NAMES}
    _,flats,source_raw=builds(named)
    raws={name:flats[name+".hepta"]for name in NATIVE_NAMES}
    contract_raw=builds.capture_sources({"contract":CONTRACT})["contract"]
    contract=checked_contract(contract_raw)
    chunk_named={str(i):name for i,name in enumerate(THRESHOLD_SOURCES)}
    chunks=builds.capture_sources(chunk_named)
    threshold=b"".join(chunks[str(i)]for i in range(11))
    if len(threshold)!=THRESHOLD_BYTES or sha256(threshold).hexdigest()!=THRESHOLD_SHA256:
        raise ValueError("complete original NDU threshold differs")
    initial=builds.capture_sources({str(i):name for i,name in enumerate(contract["source_files"])})
    for (_,pin),raw in zip(contract["source_files"].items(),initial.values(),strict=True):
        if sha256(raw).hexdigest()!=pin:raise ValueError("current native NDU source differs")
    from tools.build_hia_source_build import _named_source_request
    from tools.build_hia_native_store_release import _kit_with_objects
    composer,composer_images,_=builds.kit_objects(KIT_POLICY,KIT_PACKER)
    if composer_images["selfhost.hepta"]!=compiler:
        raise ValueError("NDU source-kit composer uses another compiler")
    kits={}
    def pack(name,magic,parts,**options):
        if name not in kits:
            sources=builds.capture_sources({"source_build_policy.hepta":PROGRAMS+POLICY,
                                            "selfhost.hepta":PROGRAMS+"selfhost.hepta",
                                            "source_build_packer.hepta":PROGRAMS+name+".hepta"})
            kit,images=_kit_with_objects(call(composer,"build",_named_source_request(sources,tag=b"HIAKOBJ1")))
            if images["selfhost.hepta"]!=compiler:raise ValueError("NDU rank kit uses another compiler")
            kits[name]=kit
        wire=frame(magic,parts,**options)
        first=call(kits[name],"build",wire);second=call(kits[name],"build",wire)
        if first!=second:raise ValueError("two complete NDU native constructions differ")
        return first
    roles={role:raws[name]for role,name in ROLE_SOURCES.items()}
    roles["r17"]=pack("ndu_rank_native_owner_packer",b"HIANOP02",[raws[n]for n in OWNER],owner=True)
    roles["r19"]=pack("ndu_rank_native_owner_error_packer",b"HIAERR01",[raws["ndu_rank_native_owner_error"]])
    engine=pack("ndu_rank_engine_packer",b"HIANEP02",[roles[n]for n in ROLES],engine=True)
    scalar=pack("native_scalar_proof_packer",b"HIAMVK02",[raws[n]for n in SCALAR])
    calls=pack("native_call_proof_packer",b"HIAMCK01",[raws[n]for n in CALL])
    normal_record=struct.pack("<8sQQ32sQ",b"HIANRM01",len(normalizer),0o500,sha256(normalizer).digest(),0)
    extra={"normalizer_record":normal_record,"scalar_image":scalar,"call_image":calls}
    proof=pack("ndu_rank_proof_facade_packer",b"HIANFP01",[extra[n]if n in extra else raws[n]for n in FACADE])
    payload=pack("ndu_rank_context_payload_packer",b"HIANKPL1",[raws["multiversion_background_payload"]],payload=True)
    records=b"".join(identity_record(k,v)for k,v in ((0,normalizer),(1,proof),(3,threshold)))
    context=pack("ndu_rank_context_records_packer",b"HIANKP02",
                 [raws["ndu_rank_context_records"],raws["ndu_rank_sha_stream_private"],payload],records=records)
    products={"engine":engine,"context":context,"normalizer":normalizer,"proof":proof,"threshold":threshold}
    for role,raw in products.items():
        pin=contract["products"][role]
        if len(raw)!=pin["bytes"]or sha256(raw).hexdigest()!=pin["sha256"]:
            raise ValueError("complete current native NDU product differs: "+role)
    for role,row in zip(ROLES,contract["rank_roles"],strict=True):
        if len(roles[role])!=row["bytes"]or sha256(roles[role]).hexdigest()!=row["sha256"]:
            raise ValueError("complete current native NDU role differs: "+role)
    # End captures include every source and threshold chunk, not a historical
    # projected view; the native recipe performs the same final captures.
    if builds.capture_sources(named)!=source_raw or builds.capture_sources(chunk_named)!=chunks:
        raise ValueError("NDU construction inputs changed")
    if (builds.capture_sources({"contract":CONTRACT})["contract"]!=contract_raw or
            builds.capture_sources({str(i):name for i,name in enumerate(contract["source_files"])})!=initial):
        raise ValueError("NDU current contract or bound source changed")
    work=Path(work)
    for role,raw in products.items():
        path=work/PRODUCTS[role]
        with path.open("xb")as stream:stream.write(raw)
        publish(path,expected=contract["products"][role]["sha256"])
    path=work/CONTRACT_PRODUCT
    with path.open("xb")as stream:stream.write(contract_raw)
    publish(path,expected=sha256(contract_raw).hexdigest())
    return products

def append_rank_recipe(r,*,root):
    """Append the same complete construction to the existing leaf DAG."""
    root=Path(root)
    raw=(root/CONTRACT).read_bytes()
    contract=checked_contract(raw)
    contract_node=r.source(CONTRACT)
    r.node(9,(contract_node,),bytes.fromhex(sha256(raw).hexdigest()))
    captured={}
    for name,pin in contract["source_files"].items():
        captured[name]=r.source(name)
        r.node(9,(captured[name],),bytes.fromhex(pin))
    named={name+".hepta":PROGRAMS+name+".hepta"for name in NATIVE_NAMES}
    sources,images=r.compile(named)
    flats={name:images[name+".hepta"]for name in NATIVE_NAMES}
    chunk_nodes=[r.source(name)for name in THRESHOLD_SOURCES]
    threshold=r.node(16,tuple(chunk_nodes))
    r.node(9,(threshold,),bytes.fromhex(THRESHOLD_SHA256))
    normalizer=r.import_product(NORMALIZER_PRODUCT)
    def concat(parts):return r.node(16,tuple(parts))
    def word(value):return r.literal(struct.pack("<Q",value))
    def digest(value):return r.node(13,(value,))
    def length(value):return r.node(17,(value,))
    composer,_,_=r.kit(KIT_POLICY,KIT_PACKER)
    kits={}
    def pack(packer,magic,parts,*,engine=False,owner=False,payload=False,records=0):
        fields=[r.literal(magic)]
        if engine:fields.append(word(21))
        fields.extend(length(x)for x in parts)
        if engine or owner:fields.append(word(1))
        elif payload:fields.append(r.literal(bytes(16)))
        elif records:fields.append(r.literal(struct.pack("<4Q",192,0,0,0)))
        fields.extend(parts)
        if records:fields.append(records)
        wire=concat(fields)
        if packer not in kits:
            sources=r.capture({"source_build_policy.hepta":PROGRAMS+POLICY,
                               "selfhost.hepta":PROGRAMS+"selfhost.hepta",
                               "source_build_packer.hepta":PROGRAMS+packer+".hepta"},b"HIAKOBJ1")
            kits[packer]=r.run(composer,sources)
        author=kits[packer]
        first,second=r.run(author,wire),r.run(author,wire)
        r.node(8,(first,second))
        return first
    roles={role:flats[name]for role,name in ROLE_SOURCES.items()}
    roles["r17"]=pack("ndu_rank_native_owner_packer",b"HIANOP02",[flats[n]for n in OWNER],owner=True)
    roles["r19"]=pack("ndu_rank_native_owner_error_packer",b"HIAERR01",[flats["ndu_rank_native_owner_error"]])
    engine=pack("ndu_rank_engine_packer",b"HIANEP02",[roles[n]for n in ROLES],engine=True)
    scalar=pack("native_scalar_proof_packer",b"HIAMVK02",[flats[n]for n in SCALAR])
    calls=pack("native_call_proof_packer",b"HIAMCK01",[flats[n]for n in CALL])
    normal_record=concat((r.literal(b"HIANRM01"),length(normalizer),word(0o500),digest(normalizer),word(0)))
    extra={"normalizer_record":normal_record,"scalar_image":scalar,"call_image":calls}
    proof=pack("ndu_rank_proof_facade_packer",b"HIANFP01",[extra[n]if n in extra else flats[n]for n in FACADE])
    payload=pack("ndu_rank_context_payload_packer",b"HIANKPL1",[flats["multiversion_background_payload"]],payload=True)
    identities=[]
    for kind,value in ((0,normalizer),(1,proof),(3,threshold)):
        identities.append(concat((r.literal(b"HIANKI01"),word(kind),length(value),digest(value),word(0))))
    records=concat(identities)
    context=pack("ndu_rank_context_records_packer",b"HIANKP02",
                 [flats["ndu_rank_context_records"],flats["ndu_rank_sha_stream_private"],payload],records=records)
    products={"engine":engine,"context":context,"normalizer":normalizer,"proof":proof,"threshold":threshold}
    for role,value in products.items():
        r.node(9,(value,),bytes.fromhex(contract["products"][role]["sha256"]))
    for role,row in zip(ROLES,contract["rank_roles"],strict=True):
        r.node(9,(roles[role],),bytes.fromhex(row["sha256"]))
    # The final raw captures remain in the actual source domain.
    r.node(8,(contract_node,r.source(CONTRACT)))
    for name,handle in captured.items():r.node(8,(handle,r.source(name)))
    for name,handle in zip(THRESHOLD_SOURCES,chunk_nodes,strict=True):r.node(8,(handle,r.source(name)))
    for alias,path in named.items():r.node(8,(sources[alias],r.source(path)))
    for role,value in products.items():r.publish(PRODUCTS[role],value,contract["products"][role]["sha256"])
    r.publish(CONTRACT_PRODUCT,contract_node,sha256(raw).hexdigest())
    return products
