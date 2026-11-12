"""Generate the two complete initializer P16/P17/P18 private bridge images.

Every import uses exact source bytes. This generator performs no runtime
business work: HIA owns program framing, actual receipts and value construction.
"""
from __future__ import annotations
import ast,copy,json,os,re,sys
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REFERENCE=Path(os.environ.get("HIA_WORKER_REFERENCE",str(ROOT.parent/"Hepta-agent-edit-native"))).resolve()
sys.path.insert(0,str(REFERENCE))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder

OWN_PINS={
  "worker_initializer_program_bridge_common.py": "31451df01b02736b069b71010b1b81132bbe3a549d6fe21df5aca493c1a723a5",
  "worker_initializer_program_bridge_input.py": "44bddb83b5888e223865d15a7befe438525048cf3cfa971667d0eba6cb81d332",
  "worker_initializer_program_bridge_output.py": "8751fcbbcdaa72b7dbe593755a6dbe381b5f4be47ba7e3562720e57f2da8f342"
}
DEPENDENCIES={
  "generate_hia_agent_worker_init_values.py": "9a786c3d3982b736bd068eb522b8b8d7649da80bd4813f9c235e2c83461a95ac",
  "generate_hia_agent_worker_init_sequence.py": "fad447d45d40494f04280ca100f1ce1abf5e5651bce4feba8cedcfcdbdae06ef",
  "worker_init_resources_front.py": "f88b58c8471e16636c2c780b25ee8a1dce278b598a4ab4ce2575c1fb9a78c9bc",
  "worker_init_resources_result.py": "0d5c0185c897ff34431caf6e2912661d01131b3cc363b138bec38a64f525e272",
  "agent_data_graph_values.py": "4b005ea341992084ce60355c7112dcd47c7544dc3f24b2eccd4b8966b2734421"
}
INTRINSICS={"byte","length","store","choose","copy_bytes","fill_range"}
SOURCE_PINS={}
def magic(value):
    assert len(value)==8
    return int.from_bytes(value.encode("ascii"),"little")
def verified(path,identity):
    raw=path.read_bytes()
    assert sha256(raw).hexdigest()==identity,(str(path),sha256(raw).hexdigest(),identity)
    SOURCE_PINS[str(path)]=dict(bytes=len(raw),sha256=identity,mode=path.stat().st_mode&4095)
    return ast.parse(raw,filename=str(path))
def assigned(tree,name):
    values=[n.value for n in tree.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    assert len(values)==1,(name,len(values))
    return ast.literal_eval(values[0])
def exact(tree,names):
    nodes=[copy.deepcopy(n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert {n.name for n in nodes}==set(names)
    return nodes
def constants(own,deps):
    result={
       "IV_BAD":0xfffffffd,"IV_MAX":(1<<64)-1,"IV_GRAPH":magic("HIAGRF01"),
       "PB_COMMAND":magic("HIAWPBC1"),"PB_EVENT":magic("HIAWPBE1"),
       "PB_STATE":magic("HIAWPBS1"),"PB_RECORD":magic("HIAWPC01"),
       "PB_PROGRAM_COMMAND":magic("HIAWPI01"),"PB_PROGRAM_RESULT":magic("HIAWPE01"),
       "PB_PROGRAM_RECEIPT":magic("HIAPRV01"),"PB_CARRIER_EVENT":magic("HIACDE01"),
       "PB_REG_MAGIC":magic("HIAWGC01"),"PB_REG_EVENT":magic("HIAWGE01"),
       "PB_WIRE_MAGIC":magic("HIAGWC01"),"PB_WIRE_EVENT":magic("HIAGWE01"),
       "PB_DATA_ARENA":magic("HIADATA1"),
       "PB_DG_COMMAND":magic("HIADGC01"),"PB_DG_STATE":magic("HIADGW01"),
       "PB_DG_EVENT":magic("HIADGE01"),
       "PB_HANDLE":1<<63,"PB_MIN":8192,"PB_DATA":8192,
       "PB_EVENT_AT":2048,"PB_EVENT_END":2304,"PB_REG_COMMAND":2304,
       "PB_WIRE_COMMAND":2432,"PB_SAVED_COMMAND":2560,
       "PB_SOURCE_HEADER":2688,"PB_PREVIOUS_EVENT":2816,
       "PB_INITIALIZER_EVENT":3072,"PB_DG_CONFIG":3328,
       "PB_DECODER_CONFIG":3456,"PB_ORIGINAL_DIGEST":3840,"PB_REPLY":4096,
       "IS_STATE":magic("HIAWIW01"),"IS_EVENT":magic("HIAWIE01"),"IS_REPLY":magic("HIAWIR01"),
       "RS_PURE_EVENT":magic("HIAWPE01"),"RS_REG_EVENT":magic("HIAWGE01"),
       "RS_HANDLE":1<<63,"RS_REG_EVENT_COPY":2816}
    fields=assigned(own["worker_initializer_program_bridge_common.py"],"FIELDS")
    assert len(fields)==len(set(fields)) and len(fields)*8<=1024
    result.update({"P_"+name:1024+8*i for i,name in enumerate(fields)})
    result["V_BAD"]=result["P_BAD"]
    for name in ("INV","CALL","PENDING","ORIGIN","INITIALIZER_BYTES","REG_SEQUENCE",
                 "REG_PREVIOUS","REG_ACTIVE","ISSUED","PACKET_AT","PACKET_BYTES",
                 "OLD_NODES","OLD_EDGES","OLD_POOL","NEW_NODES","NEW_EDGES",
                 "NEW_POOL","NEW_BYTES","OUTPUT","FOREIGN","GRAPH_LEASE","GRAPH_BYTES"):
        result["R_"+name]=result["P_"+name]
    names=assigned(deps["generate_hia_agent_worker_init_sequence.py"],"NAMES")
    result.update({"I_"+name:1024+8*i for i,name in enumerate(names)})
    assert result["I_PENDING"]==1408 and result["I_PHASE"]==1040
    assert result["P_HANDLE1"]==result["P_HANDLE0"]+8 and result["P_HANDLE2"]==result["P_HANDLE0"]+16
    ranges=[(1024,1024+len(fields)*8),(2048,2304),(2304,2432),(2432,2496),
            (2560,2688),(2688,2752),(2816,3072),(3072,3328),(3328,3456),
            (3456,3520),(3840,3872),(4096,4352)]
    assert all(a<b<=8192 for a,b in ranges)
    assert all(b<=c for (a,b),(c,d) in zip(ranges,ranges[1:]))
    return result
def source_program(which):
    assert which in ("input","output")
    own={name:verified(ROOT/"tools"/name,pin) for name,pin in OWN_PINS.items()}
    deps={name:verified(ROOT/"dependencies"/name,pin) for name,pin in DEPENDENCIES.items()}
    nodes=[]
    for name,tree in own.items():
        nodes+=ast.parse(assigned(tree,"BODY"),filename=name+" BODY").body
    nodes+=exact(ast.parse(assigned(deps["generate_hia_agent_worker_init_values.py"],"BODY")),
                 {"iv_word","iv_get","iv_put","iv_bad","iv_shape","iv_valid_node"})
    nodes+=exact(ast.parse(assigned(deps["worker_init_resources_front.py"],"BODY")),
                 {"rs_previous_pure","rs_previous_registry"})
    nodes+=exact(ast.parse(assigned(deps["worker_init_resources_result.py"],"BODY")),
                 {"rs_plan","rs_bound_header","rs_bound_node","rs_bound_bytes"})
    utf,=exact(ast.parse(assigned(deps["agent_data_graph_values.py"],"VALUES")),{"dg_utf8"})
    utf.name="pb_utf8";utf.args.args[0].annotation=ast.Name(id="mutbuf",ctx=ast.Load())
    class Utf(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id=="DG_MAX":return ast.copy_location(ast.Name(id="IV_MAX",ctx=node.ctx),node)
            return node
    nodes.append(Utf().visit(utf))
    assert all(isinstance(n,ast.FunctionDef) for n in nodes)
    available={n.name:n for n in nodes};assert len(available)==len(nodes)
    root="initializer_program_"+which
    selected=set();pending=[root]
    while pending:
        name=pending.pop()
        if name in selected:continue
        selected.add(name);node=available[name]
        for call in ast.walk(node):
            if isinstance(call,ast.Call):
                assert isinstance(call.func,ast.Name),ast.dump(call)
                if call.func.id in INTRINSICS:continue
                assert call.func.id in available,call.func.id
                pending.append(call.func.id)
    nodes=[n for n in nodes if n.name in selected]
    nodes.sort(key=lambda n:n.name!=root)
    c=constants(own,deps)
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if node.id in c:return ast.copy_location(ast.Constant(c[node.id]),node)
            return node
    tree=Expand().visit(ast.Module(body=nodes,type_ignores=[]))
    source=ast.unparse(ast.fix_missing_locations(tree))+"\n"
    # No unresolved uppercase transport or state identifier may reach the builder.
    assert not {n.id for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Name) and n.id.isupper()},source
    return source,dict(constants=c,root=root,source_dependencies=dict(SOURCE_PINS))
def measured(value):
    functions=value["functions"]
    counts=dict(functions=len(functions),blocks=sum(len(f["blocks"]) for f in functions),
                instructions=sum(len(b["ops"]) for f in functions for b in f["blocks"]),
                max_function_blocks=max(len(f["blocks"]) for f in functions),
                max_block_parameters=max(len(b["params"]) for f in functions for b in f["blocks"]))
    limits=dict(functions=128,blocks=1536,instructions=8192,max_function_blocks=256,max_block_parameters=16)
    assert all(counts[k]<=v for k,v in limits.items()),counts
    indices=[]
    for f in functions:
        for b in f["blocks"]:
            for item in b["params"]+[out for op in b["ops"] for out in op.get("out",[])]:
                match=re.fullmatch("v([0-9]+)",item["name"]);assert match,item
                indices.append(int(match.group(1)))
    counts["max_ssa_index"]=max(indices)
    assert counts["max_ssa_index"]<2048,counts
    return counts
def document(which):
    source,metadata=source_program(which)
    nodes=ast.parse(source).body
    names={n.name:"f"+str(i+1) for i,n in enumerate(nodes)}
    sig={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes)
    params=[dict(name="v0",type="readbuf"),dict(name="v1",type="mutbuf"),dict(name="v2",type="mutbuf")]
    functions=[dict(name="f0",params=params,returns=["u32"],effects=["read","write","trap"],entry="b0",
        blocks=[dict(id="b0",params=params,ops=[
            dict(op="borrow.read",args=["v1"],out=[dict(name="v3",type="readbuf")],attrs={}),
            dict(op="call",args=["v0","v3","v2"],out=[dict(name="v4",type="u32")],
                 attrs=dict(function=names[metadata["root"]])),
            dict(op="loan.end",args=["v3"],out=[],attrs={})],term=dict(op="ret",values=["v4"]))])]
    for node in nodes:
        b=CopyBuilder(node,names,sig,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(v) for v in b.params],
                              returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    value=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
                  module="worker_initializer_program_"+which,functions=functions))
    profile=measured(value);verify_program(value)
    return value,source,dict(metadata,profile=profile)
if __name__=="__main__":
    which=sys.argv[1]
    value,source,metadata=document(which)
    development=ROOT/"development";development.mkdir(exist_ok=True)
    target=ROOT/"examples/hia_bootstrap"/("worker_initializer_program_"+which+".hiaasm")
    target.parent.mkdir(parents=True,exist_ok=True)
    raw=render_assembly(value).encode("utf-8")
    for path,payload in ((target,raw),
        (development/(which+"-authoring-r1.py"),source.encode()),
        (development/(which+"-source-r1.json"),(json.dumps(metadata,sort_keys=True,indent=2)+"\n").encode())):
        with path.open("xb") as stream:stream.write(payload)
    print(json.dumps(dict(path=str(target),bytes=len(raw),sha256=sha256(raw).hexdigest(),
             **metadata["profile"],scope="NEW_NATIVE_INITIALIZER_PROGRAM_BRIDGE_NOT_EXECUTION"),sort_keys=True),flush=True)
